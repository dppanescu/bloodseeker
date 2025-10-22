# app/services/whois.py
from __future__ import annotations
from typing import Optional, Any, Mapping
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..config import settings
import json, time, urllib.request, urllib.parse

# folosim Redis (dacă există) pentru cooldown
try:
    import redis as _redis
except Exception:
    _redis = None

_R = None
def _get_redis():
    global _R
    if _R is not None:
        return _R
    if _redis:
        try:
            _R = _redis.from_url(settings.redis.url, decode_responses=True)
            return _R
        except Exception:
            return None
    return None

def cooldown_ok(domain: str) -> bool:
    """Rate limit simplu: 1 cerere / cooldown_sec per domeniu."""
    r = _get_redis()
    key = f"brandmon:whois:cd:{domain}"
    ttl = int(getattr(settings.whois, "cooldown_sec", 600)) if getattr(settings, "whois", None) else 600
    if r:
        try:
            # setează doar dacă nu există (NX); expiră automat
            ok = r.set(key, str(time.time()), ex=ttl, nx=True)
            return bool(ok)
        except Exception:
            pass
    return True  # fallback

def fetch_whois_whoisxmlapi(domain: str, timeout: int = 15) -> Optional[dict]:
    """Interoghează WhoisXML API și normalizează câteva câmpuri utile."""
    api_key = settings.WHOISXML_API_KEY
    if not api_key:
        return None
    base = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    qs = urllib.parse.urlencode({
        "apiKey": api_key,
        "domainName": domain,
        "outputFormat": "JSON",
    })
    url = f"{base}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "brandmon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None

    record = (data.get("WhoisRecord") or {})
    norm = {
        "domainName": record.get("domainName"),
        "createdDate": record.get("createdDateNormalized") or record.get("createdDate"),
        "updatedDate": record.get("updatedDateNormalized") or record.get("updatedDate"),
        "expiresDate": record.get("expiresDateNormalized") or record.get("expiresDate"),
        "registrarName": (record.get("registrarName") or (record.get("registrar") or {}).get("name")),
        "status": record.get("status"),
        "nameServers": (record.get("nameServers") or {}).get("hostNames", []),
        "contactEmail": record.get("contactEmail"),
        "raw": record,
    }
    return norm

def read_cache(db: Session, variant_id: int):
    """Returnează rândul din whois_cache (sau None)."""
    return db.execute(
        text("SELECT variant_id, domain, data, source, fetched_at FROM whois_cache WHERE variant_id = :vid"),
        {"vid": variant_id},
    ).first()

def upsert_cache(db: Session, variant, norm: Mapping[str, Any], source: str = "whoisxmlapi") -> None:
    """UPSERT în whois_cache pentru varianta dată."""
    db.execute(
        text("""
        INSERT INTO whois_cache (variant_id, domain, data, source, fetched_at)
        VALUES (:vid, :dom, :data::jsonb, :src, NOW())
        ON CONFLICT (variant_id) DO UPDATE
        SET data = EXCLUDED.data,
            source = EXCLUDED.source,
            fetched_at = NOW()
        """),
        {"vid": variant.id, "dom": variant.domain.lower(), "data": json.dumps(norm), "src": source},
    )
    db.commit()

def should_refresh(row, hard_ttl_hours: int) -> bool:
    """Păstrat pentru compatibilitate (dacă îl vei folosi)."""
    try:
        age_sec = time.time() - row.fetched_at.timestamp()
        return age_sec >= hard_ttl_hours * 3600
    except Exception:
        return True
