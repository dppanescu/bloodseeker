from __future__ import annotations

import asyncio
import json
import os
import random
import signal
import ssl
from datetime import datetime, timezone
from time import monotonic
from typing import Iterable, Optional, Set, Tuple

import websockets
from websockets.exceptions import ConnectionClosed, InvalidMessage
# idna e opțional; fără el, facem fallback simplu
try:
    import idna
    HAS_IDNA = True
except Exception:
    HAS_IDNA = False

try:
    import redis as redis_lib  # optional
except Exception:
    redis_lib = None

from app.config import settings
from ..db import SessionLocal
from ..logging_setup import configure_logger
from ..models import CTCandidate, SeedDomain

logger = configure_logger("certstream")

# === Config ===
CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
REDIS_URL = getattr(getattr(settings, "redis", None), "url", None) or os.getenv("REDIS_URL")
CERTSTREAM_SOURCE = os.getenv("CERTSTREAM_SOURCE", CERTSTREAM_URL)

# Heartbeat file fallback (if Redis not available)
HEARTBEAT_FILE = os.getenv("CERTSTREAM_HEARTBEAT_FILE", "/opt/brandmon/var/certstream.last_seen")
HEARTBEAT_TTL = int(os.getenv("CERTSTREAM_HEARTBEAT_TTL", "0"))  # 0 = fără TTL

# WebSocket tuning
WS_PING_INTERVAL = 20
WS_PING_TIMEOUT = 20
WS_CLOSE_TIMEOUT = 5
WS_OPEN_TIMEOUT = 15
WS_MAX_SIZE = 1_000_000  # ~1MB per frame
WS_MAX_QUEUE = 100       # buffer pentru frames

# Seeds cache
_SEEDS_CACHE: list[SeedDomain] = []
_SEEDS_TS: float = 0.0
_SEEDS_TTL = float(os.getenv("CERTSTREAM_SEEDS_TTL", "60"))  # secunde

_shutdown = asyncio.Event()

# === Redis client (opțional) ===
def _redis():
    if not REDIS_URL or not redis_lib:
        return None
    try:
        return redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception as e:
        logger.warning("certstream_redis_connect_warn", extra={"error": str(e)})
        return None

# === Seeds cache ===
def _load_seeds_sync() -> list[SeedDomain]:
    with SessionLocal() as db:
        return db.query(SeedDomain).filter(SeedDomain.deleted_at.is_(None)).all()

def _get_seeds_cached() -> list[SeedDomain]:
    global _SEEDS_CACHE, _SEEDS_TS
    now = monotonic()
    if not _SEEDS_CACHE or (now - _SEEDS_TS) > _SEEDS_TTL:
        _SEEDS_CACHE = _load_seeds_sync()
        _SEEDS_TS = now
        logger.info("certstream_seeds_refreshed", extra={"count": len(_SEEDS_CACHE)})
    return _SEEDS_CACHE

# === Utils ===
def _norm_domain(d: str) -> str:
    d = d.lower().lstrip("*.").strip()
    if not d:
        return d
    if HAS_IDNA:
        try:
            # convert to ASCII punycode for uniform comparison
            d = idna.encode(d).decode("ascii")
        except Exception:
            # dacă nu merge, îl lăsăm așa
            pass
    return d

def match_seed(domain: str, seeds: Iterable[SeedDomain]) -> Optional[SeedDomain]:
    """Caută primul seed a cărui denumire apare ca subșir în domeniu (heuristic simplu)."""
    d = _norm_domain(domain)
    for s in seeds:
        name = _norm_domain(s.name or "")
        if name and name in d:
            return s
    return None

# === Heartbeat ===
def _heartbeat_redis() -> bool:
    r = _redis()
    if not r:
        return False
    try:
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        if HEARTBEAT_TTL > 0:
            r.setex("certstream:last_seen", HEARTBEAT_TTL, now_epoch)
        else:
            r.set("certstream:last_seen", now_epoch)
        # setează sursa, dacă nu e deja
        r.set("certstream:source", CERTSTREAM_SOURCE)
        return True
    except Exception as e:
        logger.warning("certstream_heartbeat_redis_warn", extra={"error": str(e)})
        return False

def _heartbeat_file() -> None:
    try:
        os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
        with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
            f.write(datetime.now(timezone.utc).isoformat())
    except Exception as e:
        logger.warning("certstream_heartbeat_file_warn", extra={"error": str(e)})

def heartbeat() -> None:
    if not _heartbeat_redis():
        _heartbeat_file()

# === Procesare mesaje ===
async def process_message(msg: dict) -> None:
    """
    Așteptăm:
      {
        "message_type": "certificate_update",
        "data": { "leaf_cert": { "all_domains": [...] }, ... }
      }
    """
    if not isinstance(msg, dict):
        return
    if msg.get("message_type") != "certificate_update":
        # pentru 'heartbeat' sau altceva, doar menținem own heartbeat
        heartbeat()
        return

    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    raw_domains = leaf.get("all_domains") or []
    if not isinstance(raw_domains, list) or not raw_domains:
        heartbeat()
        return

    # normalize + deduplicate
    all_domains: Set[str] = set()
    for d in raw_domains:
        if not isinstance(d, str):
            continue
        nd = _norm_domain(d)
        if nd:
            all_domains.add(nd)

    if not all_domains:
        heartbeat()
        return

    seeds = _get_seeds_cached()
    matched_pairs: list[Tuple[int, str]] = []

    # SQL: minimizăm query-urile — folosim o singură sesiune și .commit() doar dacă e cazul
    with SessionLocal() as db:
        try:
            for d in all_domains:
                seed = match_seed(d, seeds)
                if not seed:
                    continue

                existing = (
                    db.query(CTCandidate)
                    .filter(CTCandidate.seed_id == seed.id, CTCandidate.domain == d)
                    .first()
                )
                if existing:
                    existing.seen_count = (existing.seen_count or 0) + 1
                else:
                    db.add(CTCandidate(seed_id=seed.id, domain=d, seen_count=1))

                matched_pairs.append((seed.id, d))

            if matched_pairs:
                db.commit()

            # heartbeat indiferent de match
            heartbeat()

        except Exception as e:
            db.rollback()
            logger.exception("certstream_db_error", extra={"error": str(e), "matches": len(matched_pairs)})

# === Run loop ===
async def run_certstream_forever() -> None:
    # TLS context curat (moare dacă validarea eșuează – e ce vrei în prod)
    ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    backoff = 1.0

    while not _shutdown.is_set():
        try:
            # Notă: max_size & max_queue limitează mem. dacă serverul trimite spike-uri
            async with websockets.connect(
                CERTSTREAM_URL,
                ssl=ssl_ctx,
                ping_interval=WS_PING_INTERVAL,
                ping_timeout=WS_PING_TIMEOUT,
                close_timeout=WS_CLOSE_TIMEOUT,
                open_timeout=WS_OPEN_TIMEOUT,
                max_size=WS_MAX_SIZE,
                max_queue=WS_MAX_QUEUE,
            ) as ws:
                logger.info("certstream_connected", extra={"url": CERTSTREAM_URL})
                backoff = 1.0  # reset backoff după conectare

                # heartbeat inițial (vizibil imediat în health)
                heartbeat()

                async for raw in ws:
                    if _shutdown.is_set():
                        break
                    try:
                        msg = json.loads(raw)
                    except Exception as e:
                        logger.warning("certstream_json_parse_warn", extra={"error": str(e)})
                        continue

                    try:
                        await process_message(msg)
                    except Exception as e:
                        logger.exception("certstream_process_exception", extra={"error": str(e)})

        except (ConnectionClosed, InvalidMessage) as e:
            logger.warning("certstream_ws_closed", extra={"error": str(e)})
        except Exception as e:
            logger.error("certstream_connection_error", extra={"error": str(e)})

        # backoff cu jitter; nu depăși 30s
        sleep_for = min(backoff, 30.0) + random.uniform(0.0, 0.5 * min(backoff, 30.0))
        await asyncio.sleep(sleep_for)
        backoff = min(backoff * 2.0, 30.0)

def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _graceful(*_):
        if not _shutdown.is_set():
            logger.info("certstream_shutdown_signal")
            _shutdown.set()
    try:
        loop.add_signal_handler(signal.SIGTERM, _graceful)
        loop.add_signal_handler(signal.SIGINT, _graceful)
    except NotImplementedError:
        # pe Windows sau în unele medii nu e suport
        pass

def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)
    try:
        loop.run_until_complete(run_certstream_forever())
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        finally:
            loop.close()

if __name__ == "__main__":
    main()
