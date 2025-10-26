# app/routers/metrics.py
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from app.db import SessionLocal
from app.config import settings
import contextlib

try:
    import redis
except Exception:  # dacă lipsește lib-ul, exportăm doar 0 la redis
    redis = None

router = APIRouter()

def _safe_db_ok() -> bool:
    try:
        with SessionLocal() as db:
            db.execute("SELECT 1")
        return True
    except Exception:
        return False

def _safe_variants_total() -> int:
    try:
        with SessionLocal() as db:
            res = db.execute("SELECT count(*) FROM variants")
            return int(res.scalar_one() or 0)
    except Exception:
        return 0

def _safe_redis_status():
    ok, depth = 0, 0
    if redis is None:
        return ok, depth
    try:
        r = redis.from_url(
            settings.redis.url,
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
            health_check_interval=0,
        )
        r.ping()
        ok = 1
        # depth e best-effort: dacă nu există lista, e 0
        with contextlib.suppress(Exception):
            depth = int(r.llen("celery"))
    except Exception:
        ok, depth = 0, 0
    return ok, depth

@router.get("/metrics", response_class=PlainTextResponse)
def metrics():
    lines = []
    lines.append("brandmon_up 1")
    # DB
    db_ok = 1 if _safe_db_ok() else 0
    lines.append(f"brandmon_db_up {db_ok}")
    # Redis
    redis_ok, depth = _safe_redis_status()
    lines.append(f"brandmon_redis_up {redis_ok}")
    lines.append(f"brandmon_queue_depth {depth}")
    # Variants
    lines.append(f"brandmon_variants_total {_safe_variants_total()}")
    return "\n".join(lines) + "\n"
