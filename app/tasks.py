# app/tasks.py
from __future__ import annotations
from celery import Celery
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy import func as sa_func
from .config import settings
from .db import SessionLocal
from .models import SeedDomain, Variant, CheckRun, CTCandidate
from .probes.dns_probe import dns_check
from .probes.http_probe import http_check
from .services.scoring import compute_risk_score, is_alert
from .services.alerts import fanout_alert
from .logging_setup import configure_logger
import json, subprocess, shlex, tempfile, os, time, redis
import urllib.parse

# WHOIS helpers (fără requests)
from .services.whois import (
    fetch_whois_whoisxmlapi, read_cache, upsert_cache, cooldown_ok
)

# --- Bannere / DNS TXT / TLS ---
import socket, ssl, http.client
try:
    import dns.resolver  # dnspython
except Exception:
    dns = None  # tratăm defensiv
try:
    import idna  # pentru IDN/SNI corect
except Exception:
    idna = None

logger = configure_logger('tasks')

celery_app = Celery('brandmon', broker=settings.redis.url, backend=settings.redis.url)
celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    broker_transport_options={'visibility_timeout': 3600},
    beat_schedule={
        'rescan-variants-15min': {'task': 'app.tasks.scan_all_variants', 'schedule': 900.0},
    }
)

# ---------------- helpers ----------------

def _filter_by_tld(domains: list[str], tlds: list[str]) -> list[str]:
    if not tlds:
        return domains
    tset = {t.lower().lstrip('.') for t in tlds}
    out = []
    for d in domains:
        parts = d.rsplit('.', 1)
        if len(parts) == 2 and parts[1].lower() in tset:
            out.append(d)
    return out

def _levenshtein(a: str, b: str) -> int:
    n, m = len(a), len(b)
    if n > m:
        a, b, n, m = b, a, m, n
    prev = list(range(n + 1))
    for j in range(1, m + 1):
        cur = [j] + [0] * n
        for i in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[i] = min(cur[i - 1] + 1, prev[i] + 1, prev[i - 1] + cost)
        prev = cur
    return prev[n]

def _norm_list(x):
    if not x:
        return []
    if isinstance(x, str):
        return [i.strip() for i in x.split(",") if i.strip()]
    if isinstance(x, (list, tuple, set)):
        return [str(i).strip() for i in x if str(i).strip()]
    return []

def _default_fuzzers():
    return [
        "homoglyph","hyphenation","transposition","omission","insertion",
        "replacement","repetition","bitsquatting","subdomain","vowel-swap"
    ]

def _tmp_file_from_lines(lines: list[str]) -> str:
    tf = tempfile.NamedTemporaryFile("w", delete=False)
    tf.write("\n".join(lines) + "\n")
    tf.flush(); tf.close()
    return tf.name

def _build_dnstwist_cmd(seed_name: str, opts: dict) -> tuple[list[str], list[str]]:
    """
    Returnează (cmd, temp_files).
    Dnstwist doar GENEREAZĂ. Nu folosim --registered/--mxcheck/--banners etc.
    """
    temp_files: list[str] = []
    o = opts or {}

    _ = _norm_list(o.get("fuzzers")) or _default_fuzzers()  # păstrăm doar ca metadată
    dictionary_words = _norm_list(o.get("dictionary"))
    tlds_list = _norm_list(o.get("tlds"))

    cmd = [settings.dnstwist.path, "--format", "json"]

    if dictionary_words:
        dict_file = _tmp_file_from_lines(dictionary_words)
        temp_files.append(dict_file)
        cmd += ["--dictionary", dict_file]

    if tlds_list:
        tmp_tld = _tmp_file_from_lines([t.lstrip(".") for t in tlds_list])
        temp_files.append(tmp_tld)
        cmd += ["--tld", tmp_tld]

    cmd.append("--all")
    cmd += ["--useragent", "BrandMon/1.0 (+https://cybersight.ro)"]
    cmd.append(seed_name)
    return cmd, temp_files

def _has_mx(domain: str) -> bool:
    try:
        import dns.resolver  # local ca să nu depindem de globalul dns
        ans = dns.resolver.resolve(domain, 'MX')
        return len(ans) > 0
    except Exception:
        return False

def _mx_hosts(domain: str) -> list[str]:
    if not dns:
        return []
    try:
        mx_ans = dns.resolver.resolve(domain, 'MX')
        pairs = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_ans], key=lambda x: x[0])
        return [h for _, h in pairs]
    except Exception:
        return []

# --- TXT/SPF/DKIM/DMARC ---

def _dns_txt_records(name: str) -> list[str]:
    if not dns:
        return []
    try:
        ans = dns.resolver.resolve(name, 'TXT')
        out = []
        for r in ans:
            try:
                s = "".join([p.decode() if isinstance(p, bytes) else str(p) for p in r.strings])
            except Exception:
                txt = r.to_text()
                if txt.startswith('"') and txt.endswith('"'):
                    txt = txt[1:-1]
                s = txt
            out.append(s)
        return out
    except Exception:
        return []

def _resolve_cname(name: str, max_depth: int = 3) -> str | None:
    if not dns:
        return None
    cur = name
    for _ in range(max_depth):
        try:
            ans = dns.resolver.resolve(cur, 'CNAME')
            target = str(ans[0].target).rstrip('.')
            if not target:
                return None
            cur = target
        except Exception:
            return cur if cur != name else None
    return cur

def _get_spf(domain: str) -> dict:
    for txt in _dns_txt_records(domain):
        if txt.lower().startswith("v=spf1"):
            return {"found": True, "record": txt}
    return {"found": False, "record": None}

_COMMON_DKIM_SELECTORS = [
    "default","selector1","selector2","google","k1","s1","s2","mail","dkim","smtp",
    "mandrill","sendgrid","mailgun","sparkpost","zoho","amazonses"
]

def _get_dkim(domain: str, selectors: list[str] | None = None, limit: int = 2) -> dict:
    sels = selectors or _COMMON_DKIM_SELECTORS
    found: list[str] = []
    for sel in sels:
        base = f"{sel}._domainkey.{domain}"
        # TXT direct
        for txt in _dns_txt_records(base):
            if txt.lower().startswith("v=dkim1"):
                found.append(sel)
                break
        if sel in found:
            if len(found) >= limit:
                break
            continue
        # follow CNAME
        target = _resolve_cname(base)
        if target:
            for txt in _dns_txt_records(target):
                if txt.lower().startswith("v=dkim1"):
                    found.append(sel)
                    break
        if len(found) >= limit:
            break
    return {"found": bool(found), "selectors": found}

def _get_dmarc(domain: str) -> dict:
    name = f"_dmarc.{domain}"
    # TXT direct
    for txt in _dns_txt_records(name):
        low = txt.lower()
        if low.startswith("v=dmarc1"):
            policy = None
            for part in txt.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part.split("=", 1)[1].strip()
            return {"found": True, "policy": policy, "record": txt}
    # follow CNAME
    target = _resolve_cname(name)
    if target:
        for txt in _dns_txt_records(target):
            low = txt.lower()
            if low.startswith("v=dmarc1"):
                policy = None
                for part in txt.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part.split("=", 1)[1].strip()
                return {"found": True, "policy": policy, "record": txt}
    return {"found": False, "policy": None, "record": None}

# --- HTTP banner + follow redirects ---

def _fetch_http_banner(domain: str, timeout: float = 3.0, max_redirects: int = 4) -> dict | None:
    def _one_request(url: str):
        parsed = urllib.parse.urlparse(url)
        use_ssl = parsed.scheme == "https"
        host = parsed.hostname
        port = parsed.port or (443 if use_ssl else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context()) if use_ssl \
            else http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "BrandMon/1.0"})
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            data = {
                "status": resp.status,
                "reason": resp.reason,
                "server": headers.get("server"),
                "powered_by": headers.get("x-powered-by") or headers.get("powered-by") or headers.get("x_powered_by"),
                "location": headers.get("location"),
            }
            return data
        finally:
            try: conn.close()
            except Exception: pass

    # încearcă mai întâi https://, apoi http://
    for scheme in ("https", "http"):
        initial_url = f"{scheme}://{domain}/"
        url = initial_url
        chain: list[str] = []
        last = None
        try:
            for _ in range(max_redirects + 1):
                cur = _one_request(url)
                if not cur:
                    break
                last = cur
                loc = cur.get("location")
                if cur["status"] in (301, 302, 303, 307, 308) and loc:
                    url = urllib.parse.urljoin(url, loc)
                    chain.append(url)
                    continue
                break  # nu mai e redirect
        except Exception:
            last = None

        if last:
            # completează bannerul
            banner = dict(last)
            banner["initial_url"] = initial_url
            banner["final_url"] = chain[-1] if chain else initial_url
            banner["redirect_chain"] = chain
            banner["final_status"] = last.get("status")
            banner["final_reason"] = last.get("reason")
            return banner

    return None

# --- SMTP banner ---

def _fetch_smtp_banner(domain: str, timeout: float = 3.0) -> dict | None:
    """
    Citește bannerul SMTP (linia 220) de pe primul MX cu prioritate minimă.
    Returnează dict cu chei: {"mx": "<host>", "banner": "<text>"} sau None.
    """
    if not dns:
        return None
    try:
        mx_ans = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted(
            [(r.preference, str(r.exchange).rstrip('.')) for r in mx_ans],
            key=lambda x: x[0]
        )
    except Exception:
        mx_hosts = []

    for _, host in mx_hosts[:1]:
        try:
            with socket.create_connection((host, 25), timeout=timeout) as s:
                s.settimeout(timeout)
                data = s.recv(512)
                banner = data.decode("utf-8", errors="ignore").strip()
                if banner:
                    return {"mx": host, "banner": banner}
        except Exception:
            continue

    return None

# --- TLS (issuer + valid from/to) ---

_TLS_TIME_FMT = "%b %d %H:%M:%S %Y %Z"  # ex: 'Jun  1 12:00:00 2024 GMT'

def _parse_tls_time_str(val: str | None) -> str | None:
    if not val:
        return None
    try:
        dt = time.strptime(val, _TLS_TIME_FMT)
        from datetime import datetime, timezone as _tz
        dt2 = datetime(
            year=dt.tm_year, month=dt.tm_mon, day=dt.tm_mday,
            hour=dt.tm_hour, minute=dt.tm_min, second=dt.tm_sec, tzinfo=_tz.utc
        )
        return dt2.isoformat()
    except Exception:
        return None

def fetch_tls_info(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Întoarce dict cu chei standardizate:
      { "issuer": str, "not_before": ISO8601, "not_after": ISO8601 }
    Face SNI și NU validează CA (nu vrem să crape la self-signed).
    """
    try:
        server_name = idna.encode(host).decode("ascii") if idna else host
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((server_name, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                cert = ssock.getpeercert()
                issuer = None
                try:
                    for rdn in cert.get("issuer", []):
                        for k, v in rdn:
                            if k.lower() in ("commonname", "cn"):
                                issuer = v
                                break
                        if issuer:
                            break
                except Exception:
                    pass
                not_before = _parse_tls_time_str(cert.get("notBefore"))
                not_after  = _parse_tls_time_str(cert.get("notAfter"))

                out = {}
                if issuer:     out["issuer"] = issuer
                if not_before: out["not_before"] = not_before
                if not_after:  out["not_after"] = not_after
                return out
    except Exception:
        return {}

# ---------------- generators ----------------

@celery_app.task(name='app.tasks.generate_variants')
def generate_variants(seed_id: int):
    db: Session = SessionLocal()
    try:
        seed = db.query(SeedDomain).get(seed_id)
        if not seed:
            return
        base = seed.name
        variants = set()

        parts = base.split('.')
        sld = parts[0]
        tld = '.'.join(parts[1:]) if len(parts) > 1 else ''
        repl = [('o','0'), ('i','1'), ('e','3'), ('a','4'), ('s','5')]
        for (a,b) in repl:
            variants.add(base.replace(a,b))
        variants.add(sld + '-' + tld if tld else sld + '-x')
        variants.add(sld + 'secure.' + tld if tld else sld + 'secure')

        for d in variants:
            if not d or d == base:
                continue
            exists = db.query(Variant).filter(Variant.seed_id==seed.id, Variant.domain==d).first()
            if not exists:
                db.add(Variant(seed_id=seed.id, domain=d, status='new'))
        db.commit()
    finally:
        db.close()

@celery_app.task(name='app.tasks.generate_variants_dnstwist')
def generate_variants_dnstwist(seed_id: int):
    if not settings.dnstwist.enabled:
        return
    db: Session = SessionLocal()
    tmp_files: list[str] = []
    r = None
    lock_key = None
    try:
        seed = db.get(SeedDomain, seed_id)
        if not seed:
            return

        # lock per seed
        try:
            r = redis.from_url(settings.redis.url, decode_responses=True)
            lock_key = f"brandmon:lock:dnstwist:{seed.name.lower()}"
            if not r.set(lock_key, "1", ex=900, nx=True):
                logger.info("dnstwist_skip_locked", extra={"seed": seed.name})
                return
        except Exception:
            r = None

        opts = dict(seed.options or {})
        cmd, tmp_files = _build_dnstwist_cmd(seed.name, opts)
        logger.info("dnstwist_run", extra={"seed": seed.name, "cmd": " ".join(shlex.quote(c) for c in cmd)})

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=settings.dnstwist.timeout_sec, check=False
            )
        except subprocess.TimeoutExpired:
            logger.error("dnstwist_timeout", extra={"seed": seed.name, "timeout": settings.dnstwist.timeout_sec})
            return

        if proc.returncode not in (0, 1):
            logger.error("dnstwist_rc", extra={"rc": proc.returncode, "stderr": proc.stderr[:2000]})

        try:
            rows = json.loads(proc.stdout or "[]")
            if isinstance(rows, dict) and "results" in rows:
                rows = rows["results"]
            if not isinstance(rows, list):
                rows = []
        except Exception:
            logger.exception("dnstwist_json_parse_failed")
            rows = []

        base = seed.name.lower()
        maxn = int(getattr(settings.dnstwist, "max_variants", 300))
        inserted = 0

        for it in rows[:maxn]:
            dom = (str((it.get("domain") or it.get("dname") or it.get("fqdn") or "")).strip().lower())
            if not dom or dom == base:
                continue

            fuzzer = (it.get("fuzzer") or "").lower() or None

            v = db.query(Variant).filter(Variant.seed_id == seed.id, Variant.domain == dom).first()
            if not v:
                v = Variant(seed_id=seed.id, domain=dom, status='new')
                db.add(v)
                inserted += 1

            if fuzzer:
                v.fuzzer = fuzzer
                try:
                    if r:
                        r.hset("brandmon:dnstwist:fuzzer", dom, fuzzer)
                except Exception:
                    pass

        try:
            db.commit()
        except IntegrityError as e:
            db.rollback()
            logger.warning("dnstwist_dup_commit", extra={"seed": seed.name, "err": str(e)})

        logger.info("dnstwist_done", extra={"seed": seed.name, "inserted": inserted})

        if inserted:
            ids = [row[0] for row in db.query(Variant.id)
                                  .filter(Variant.seed_id==seed.id, Variant.status=='new')
                                  .order_by(Variant.id.desc())
                                  .limit(inserted).all()]
            for vid in ids:
                scan_variant.delay(vid)

    except Exception as e:
        logger.exception("dnstwist_unhandled", extra={"seed_id": seed_id, "err": str(e)})
    finally:
        for p in (tmp_files or []):
            try: os.unlink(p)
            except Exception: pass
        if r and lock_key:
            try: r.delete(lock_key)
            except Exception: pass
        db.close()

# ---------------- scanning ----------------

@celery_app.task(name='app.tasks.scan_variant')
def scan_variant(variant_id: int):
    db: Session = SessionLocal()
    try:
        v = db.get(Variant, variant_id)
        if not v:
            return
        if v.status == 'stop':
            return

        dom = v.domain.lower()

        dns_ok = dns_check(dom, timeout=2.0)

        # Păstrăm http_check pentru scoring fallback, dar nu-l mai scriem în notes.
        legacy_http_status = http_check(dom, timeout=3.0)

        seed = db.get(SeedDomain, v.seed_id)
        seed_sld = (seed.name.split('.')[0].lower() if seed and seed.name else None)
        tld = dom.rsplit('.', 1)[-1] if '.' in dom else ''
        try:
            sld_distance = _levenshtein(dom.split('.')[0], seed_sld) if seed_sld else None
        except Exception:
            sld_distance = None

        ct_seen_count = db.query(sa_func.coalesce(sa_func.sum(CTCandidate.seen_count), 0))\
                          .filter(CTCandidate.domain == dom)\
                          .scalar() or 0

        fuzzer = v.fuzzer
        if not fuzzer:
            try:
                r = redis.from_url(settings.redis.url, decode_responses=True)
                fuzzer = r.hget("brandmon:dnstwist:fuzzer", dom)
            except Exception:
                fuzzer = None

        has_mx = _has_mx(dom)
        mx_hosts = _mx_hosts(dom) if has_mx else []

        # HTTP banner (include status + redirect-uri + final_status/final_reason)
        http_banner = _fetch_http_banner(dom, timeout=2.5)

        # SMTP banner (text simplu)
        smtp_b = _fetch_smtp_banner(dom, timeout=3.0) if has_mx else None
        smtp_banner = smtp_b["banner"] if isinstance(smtp_b, dict) else None

        # Email auth
        spf  = _get_spf(dom)
        dkim = _get_dkim(dom)
        dmarc = _get_dmarc(dom)

        # TLS: pe domeniu, fallback pe www.<dom>, apoi pe host-ul din final_url (dacă redirecționează)
        tls = fetch_tls_info(dom, timeout=4.0)
        if not tls and not dom.startswith("www."):
            tls = fetch_tls_info("www." + dom, timeout=4.0)
        if not tls and http_banner and isinstance(http_banner.get("final_url"), str):
            try:
                host_from_final = urllib.parse.urlparse(http_banner["final_url"]).hostname
                if host_from_final and host_from_final != dom:
                    tls = fetch_tls_info(host_from_final, timeout=4.0)
            except Exception:
                pass

        # pentru scor: preferă final_status -> status -> legacy
        status_for_scoring = None
        if http_banner:
            status_for_scoring = http_banner.get("final_status") or http_banner.get("status")
        if status_for_scoring is None:
            status_for_scoring = legacy_http_status

        score = compute_risk_score(
            domain=dom,
            seed_sld=seed_sld,
            dns_ok=dns_ok,
            http_status=status_for_scoring,
            tld=tld,
            sld_distance=sld_distance,
            ct_seen_count=ct_seen_count,
            has_mx=has_mx,
            fuzzer=fuzzer,
        )

        try:
            updated = (
                db.query(Variant)
                  .filter(Variant.id == variant_id, Variant.status != 'stop')
                  .update(
                      {Variant.risk_score: score, Variant.last_checked_at: sa_func.now()},
                      synchronize_session=False
                  )
            )
            if updated == 0:
                db.rollback()
                logger.warning("variant_gone_on_update", extra={"variant_id": variant_id})
                return

            # NOTE: nu mai scriem 'http_status' în notes (cum ai cerut),
            # folosim doar http_banner.* și tls.
            notes = {
                "domain": dom,
                "dns_ok": dns_ok,
                "tld": tld,
                "sld_distance": sld_distance,
                "ct_seen_count": ct_seen_count,
                "has_mx": has_mx,
                "mx_hosts": mx_hosts,          # <--- nou
                "fuzzer": fuzzer,
                "http_banner": http_banner,
                "smtp_banner": smtp_banner,
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
                "tls": tls if tls else None,   # {issuer, not_before, not_after} sau None
            }

            db.add(CheckRun(
                variant_id=variant_id,
                dns_ok=dns_ok,
                http_status=None,   # clar: nu mai populăm 200/301 separat
                notes=notes
            ))
            db.commit()

        except (StaleDataError, IntegrityError) as e:
            db.rollback()
            logger.warning("variant_update_race", extra={"variant_id": variant_id, "err": str(e)})
            return

        if is_alert(score):
            fanout_alert(
                subject=f"[BrandMon] High risk variant {dom} (score {score})",
                body=f"Domain: {dom}\nDNS ok: {dns_ok}\nHTTP (final): {(http_banner or {}).get('final_status')}\nVariant ID: {variant_id}",
                event={"variant": dom, "risk_score": score, "http_banner": http_banner}
            )
    finally:
        db.close()

@celery_app.task(name='app.tasks.scan_all_variants')
def scan_all_variants(limit: int = 200):
    db: Session = SessionLocal()
    try:
        ids = [
            row[0]
            for row in (
                db.query(Variant.id)
                  .filter(Variant.status != 'stop')
                  .order_by(Variant.last_checked_at.nullsfirst())
                  .limit(limit)
                  .all()
            )
        ]
        for vid in ids:
            scan_variant.delay(vid)
    finally:
        db.close()

@celery_app.task(name='app.tasks.whois_enrich')
def whois_enrich(variant_id: int):
    if not getattr(settings, "whois", None) or not settings.whois.enabled:
        return
    db: Session = SessionLocal()
    try:
        v = db.query(Variant).get(variant_id)
        if not v:
            return
        domain = v.domain.lower()

        row = read_cache(db, v.id)
        if row:
            try:
                age = time.time() - row.fetched_at.timestamp()
                ttl_hours = int(getattr(settings.whois, "ttl_hours", 24))
                if age < ttl_hours * 3600:
                    return
            except Exception:
                pass

        if not cooldown_ok(domain):
            return

        norm = fetch_whois_whoisxmlapi(domain, timeout=int(getattr(settings.whois, "timeout_sec", 15)))
        if norm:
            upsert_cache(db, v, norm, source="whoisxmlapi")
    except Exception as e:
        logger.exception("whois_enrich_exc", extra={"variant_id": variant_id, "err": str(e)})
    finally:
        db.close()

# ---------------- beat heartbeat ----------------

@celery_app.on_after_finalize.connect
def setup_periodic(sender, **kwargs):
    sender.add_periodic_task(30.0, beat_heartbeat.s(), name="beat_heartbeat")

@celery_app.task
def beat_heartbeat():
    try:
        r = redis.from_url(settings.redis.url, decode_responses=True)
        r.set("brandmon:beat:heartbeat", str(time.time()), ex=300)
    except Exception:
        pass
