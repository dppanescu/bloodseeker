# app/health.py
from __future__ import annotations
import time, math, platform, datetime as dt
from typing import Any, Dict
from sqlalchemy import text
from .db import SessionLocal
from .config import settings
from .tasks import celery_app  # dacă e în alt modul, ajustează importul
import fastapi
import redis
import psutil
import os

# Utils
def fmt_duration(seconds: float | int) -> str:
    try:
        s = int(max(0, seconds))
    except Exception:
        s = 0
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h or d: parts.append(f"{h}h")
    if m or h or d: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

def fmt_bytes(n: int) -> str:
    step = 1024.0
    units = ["B","KB","MB","GB","TB","PB"]
    i = 0
    x = float(n)
    while x >= step and i < len(units)-1:
        x /= step; i += 1
    return f"{x:.1f} {units[i]}"

def now_ts() -> int:
    return int(time.time())

def redis_client():
    # încearcă settings.redis.url, apoi REDIS_URL din env
    url = None
    try:
        url = getattr(getattr(settings, "redis", None), "url", None)
    except Exception:
        url = None
    url = url or os.getenv("REDIS_URL")
    if not url:
        return None
    try:
        import redis
        return redis.Redis.from_url(url, decode_responses=False)
    except Exception:
        return None

def _celery_queue_name() -> str:
    # preferă env, apoi setarea simplă din Settings, apoi 'celery'
    return os.getenv("CELERY_QUEUE") or getattr(settings, "CELERY_QUEUE_NAME", None) or "celery"

def _queue_depth(r, queue_name: str = "celery") -> int | str:
    if r is None:
        return "n/a"
    try:
        return int(r.llen(queue_name))
    except Exception:
        return "n/a"

def _certstream_last_seen(r: redis.Redis) -> int | None:
    # presupunem că un worker scrie un epoch în cheia asta
    try:
        raw = r.get("certstream:last_seen")
        if not raw:
            return None
        return int(raw)
    except Exception:
        return None

def _certstream_source(r: redis.Redis) -> str:
    try:
        raw = r.get("certstream:source")  # ex: "wss://certstream.calidog.io"
        return raw.decode() if raw else "unknown"
    except Exception:
        return "unknown"

# API uptime — ideal salvat în app.state la startup
_APP_STARTED_AT = time.monotonic()  # fallback local
def _api_uptime(app) -> float:
    started = getattr(app.state, "started_monotonic", None)
    if isinstance(started, (float, int)):
        return max(0.0, time.monotonic() - float(started))
    return max(0.0, time.monotonic() - _APP_STARTED_AT)

def _api_requests_total(app) -> int:
    # dacă ai un middleware care incrementează app.state.requests_total
    return int(getattr(app.state, "requests_total", 0))

# DB helpers
def _db_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "status": "fail",
        "server_version": "unknown",
        "current_database": "unknown",
        "size_bytes": 0,
        "size_human": "0 B",
        "connections": None,
        "alembic_current": None,
        "alembic_head": None,
    }
    try:
        with SessionLocal() as s:
            # Versiune server
            ver = s.execute(text("select version()")).scalar()  # e.g. 'PostgreSQL 16.3 ...'
            info["server_version"] = ver or "unknown"

            dbname = s.execute(text("select current_database()")).scalar()
            info["current_database"] = dbname or "unknown"

            # Dimensiunea bazei curente (bytes)
            size = s.execute(text("select pg_database_size(current_database())")).scalar()
            if isinstance(size, int):
                info["size_bytes"] = size
                info["size_human"] = fmt_bytes(size)

            # Conexiuni (necesită permisiuni pe pg_stat_database)
            try:
                connections = s.execute(text("""
                    select numbackends
                    from pg_stat_database
                    where datname = current_database()
                """)).scalar()
                if connections is not None:
                    info["connections"] = int(connections)
            except Exception:
                info["connections"] = None

            # Alembic
            try:
                curr = s.execute(text("select version_num from alembic_version")).scalar()
                info["alembic_current"] = curr
                # Head local din fișiere – dacă vrei să citești din env sau setări:
                info["alembic_head"] = getattr(settings, "alembic_head", curr)
            except Exception:
                pass

        info["status"] = "ok"
    except Exception:
        info["status"] = "fail"
    return info

# Celery helpers

def _celery_queue_name() -> str:
    # preferă env, apoi settings.CELERY_QUEUE_NAME, apoi "celery"
    return (
        os.getenv("CELERY_QUEUE")
        or getattr(settings, "CELERY_QUEUE_NAME", None)
        or "celery"
    )

def _celery_info() -> dict:
    r = redis_client()
    qname = _celery_queue_name()
    out = {
        "status": "fail",
        "workers": [],
        "worker_count": 0,
        "queue_depth": _queue_depth(r, qname),
        "tasks_active": 0,
        "tasks_reserved": 0,
        "beat_age_human": "unknown",
        "beat_status": "unknown",
    }
    try:
        insp = celery_app.control.inspect(timeout=2.0)

        ping = insp.ping() or {}
        out["workers"] = sorted(ping.keys())
        out["worker_count"] = len(out["workers"])

        active = insp.active() or {}
        reserved = insp.reserved() or {}
        out["tasks_active"] = sum(len(v or []) for v in active.values()) if active else 0
        out["tasks_reserved"] = sum(len(v or []) for v in reserved.values()) if reserved else 0

        if r is not None:
            try:
                last_tick = r.get("celery:beat:last_tick")
                if last_tick:
                    last_tick = int(last_tick)
                    age = now_ts() - last_tick
                    out["beat_age_human"] = fmt_duration(age)
                    out["beat_status"] = "ok" if age < 60 else "warn"
                else:
                    out["beat_age_human"] = "never"
                    out["beat_status"] = "warn"
            except Exception:
                out["beat_age_human"] = "unknown"
                out["beat_status"] = "warn"
        else:
            out["beat_age_human"] = "n/a"
            out["beat_status"] = "warn"

        out["status"] = "ok" if out["worker_count"] > 0 else "fail"
    except Exception:
        out["status"] = "fail"
    return out

# CertStream helpers
def _certstream_info() -> Dict[str, Any]:
    r = redis_client()
    last_seen = _certstream_last_seen(r)
    source = _certstream_source(r)

    if last_seen is None:
        return {
            "status": "warn",
            "last_seen_human": "never",
            "lag_human": "unknown",
            "source": source,
        }
    lag = max(0, now_ts() - last_seen)
    status = "ok" if lag < 30 else "warn" if lag < 300 else "fail"
    return {
        "status": status,
        "last_seen_human": dt.datetime.utcfromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "lag_human": fmt_duration(lag),
        "source": source,
    }

# System
def _system_info() -> Dict[str, Any]:
    try:
        boot = psutil.boot_time()
        uptime = max(0, now_ts() - int(boot))
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")
        cpu = psutil.cpu_percent(interval=None)
        os_str = f"{platform.system()} {platform.release()} ({platform.version()})"
        return {
            "status": "ok",
            "os": os_str,
            "uptime_human": fmt_duration(uptime),
            "cpu_percent": int(cpu),
            "mem_total_human": fmt_bytes(int(vm.total)),
            "mem_used_human": fmt_bytes(int(vm.used)),
            "mem_percent": int(vm.percent),
            "disk_total_human": fmt_bytes(int(du.total)),
            "disk_used_human": fmt_bytes(int(du.used)),
            "disk_percent": int(du.percent),
        }
    except Exception:
        return {"status": "fail"}

def aggregate(app) -> Dict[str, Any]:
    ts = now_ts()

    api = {
        "status": "ok",
        "fastapi_version": getattr(fastapi, "__version__", "unknown"),
        "uptime_human": fmt_duration(_api_uptime(app)),
        "requests_total": _api_requests_total(app),
    }

    db = _db_info()
    celery = _celery_info()
    certstream = _certstream_info()
    system = _system_info()

    # status global simplu: fail > warn > ok
    status_rank = {"ok": 0, "warn": 1, "fail": 2}
    overall = max([api["status"], db["status"], celery["status"], certstream["status"], system["status"]],
                  key=lambda s: status_rank.get(s, 2))

    return {
        "status": overall,
        "ts": ts,
        "ts_human": dt.datetime.fromtimestamp(ts).strftime("%d-%m-%Y %H:%M:%S"),
        "api": api,
        "database": db,
        "celery": celery,
        "certstream": certstream,
        "system": system,
    }
