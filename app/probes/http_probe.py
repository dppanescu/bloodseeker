from __future__ import annotations
import httpx

def http_check(url: str, timeout: float = 3.0) -> int | None:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "BrandMon/0.1"}) as c:
            resp = c.get(url if url.startswith('http') else f'https://{url}', timeout=timeout)
            return resp.status_code
    except Exception:
        return None
