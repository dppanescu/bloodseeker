from __future__ import annotations
import httpx

_CLIENT = httpx.Client(timeout=3.0, follow_redirects=True, headers={"User-Agent": "BrandMon/1.0"})

def http_check(url: str, timeout: float = 3.0) -> int | None:
    try:
        # allow override per-call but reuse client
        resp = _CLIENT.get(url if url.startswith('http') else f'https://{url}', timeout=timeout)
        return resp.status_code
    except Exception:
        return None
