from __future__ import annotations
import dns.resolver

def dns_check(domain: str, timeout: float = 2.0) -> bool:
    try:
        r = dns.resolver.Resolver(configure=True)
        r.lifetime = timeout
        r.timeout = timeout
        r.resolve(domain, 'A')
        return True
    except Exception:
        return False
