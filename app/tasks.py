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
import redis

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

celery_app = Celery(
    "brandmon",
    broker=settings.redis.url,
    backend=settings.redis.url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Optimizările promise:
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
)

# ---------------- helpers ----------------

def _guess_mta_from_banner(banner: str | None) -> str | None:
    if not banner:
        return None
    s = banner.lower()
    patterns = [
        ("postfix", "Postfix"),
        ("exim", "Exim"),
        ("sendmail", "Sendmail"),
        ("opensmtpd", "OpenSMTPD"),
        ("microsoft", "Microsoft Exchange"),
        ("exchange", "Microsoft Exchange"),
        ("mailenable", "MailEnable"),
        ("qmail", "qmail"),
        ("haraka", "Haraka"),
        ("zimbra", "Zimbra"),
        ("smtp2go", "SMTP2GO"),
        ("sendgrid", "SendGrid"),
        ("amazonses", "Amazon SES"),
        ("amazon ses", "Amazon SES"),
        ("mailgun", "Mailgun"),
        ("sparkpost", "SparkPost"),
        ("zoho", "Zoho Mail"),
        ("gsuite", "Google Workspace"),
        ("google", "Google Workspace"),
    ]
    for key, label in patterns:
        if key in s:
            return label
    return None

def _detect_smtp_server(banner: str) -> str | None:
    s = banner.lower()
    if "postfix" in s: return "Postfix"
    if "exim" in s: return "Exim"
    if "sendmail" in s: return "Sendmail"
    if "opensmtpd" in s: return "OpenSMTPD"
    if "mailenable" in s: return "MailEnable"
    if "courier" in s: return "Courier"
    if "qmail" in s: return "qmail"
    if "power mta" in s or "powermta" in s: return "PowerMTA"
    if "microsoft esmtp" in s or "exchange" in s or "iis smtp" in s: return "Microsoft Exchange/IIS"
    if "google" in s or "gmail" in s: return "Google"
    if "amazonses" in s or "amazon ses" in s: return "Amazon SES"
    if "sendgrid" in s: return "SendGrid"
    if "mailgun" in s: return "Mailgun"
    if "sparkpost" in s: return "SparkPost"
    if "mailtrap" in s: return "Mailtrap"
    return None

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

def _ns_with_ips(domain: str, timeout: float = 2.0) -> list[dict]:
    """
    Returnează o listă de { "host": <ns-host>, "ips": [ip1, ip2, ...] }.
    """
    if not dns:
        return []
    out = []
    try:
        r = dns.resolver.Resolver(configure=True)
        r.lifetime = timeout
        ns_rr = r.resolve(domain, 'NS')
        ns_hosts = []
        for rr in ns_rr:
            host = getattr(rr, "target", None)
            host = str(host).rstrip(".") if host else str(rr).rstrip(".")
            if host:
                ns_hosts.append(host)
    except Exception:
        ns_hosts = []
    for host in ns_hosts:
        ips = set()
        try:
            for rr in dns.resolver.resolve(host, 'A', lifetime=timeout):
                ips.add(getattr(rr, "address", str(rr)))
        except Exception:
            pass
        try:
            for rr in dns.resolver.resolve(host, 'AAAA', lifetime=timeout):
                ips.add(getattr(rr, "address", str(rr)))
        except Exception:
            pass
        out.append({"host": host, "ips": sorted(ips)})
    return out

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

def _fetch_smtp_banners(domain: str, timeout: float = 4.0, max_hosts: int = 3) -> list[dict]:
    """
    Încearcă pe fiecare MX (în ordinea preferinței) porturile 25/587 (plain) și 465 (TLS).
    Returnează o listă de intrări: [{"mx","port","tls","banner","server_type"}...]
    """
    if not dns:
        return []

    # MX-uri
    try:
        mx_ans = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_ans], key=lambda x: x[0])
        mx_hosts = [h for _, h in mx_hosts][:max_hosts]
    except Exception:
        mx_hosts = []

    out: list[dict] = []

    def _server_guess(b: str) -> str | None:
        s = (b or "").lower()
        pairs = [
            ("postfix","Postfix"),("exim","Exim"),("sendmail","Sendmail"),("opensmtpd","OpenSMTPD"),
            ("exchange","Microsoft Exchange"),("microsoft","Microsoft Exchange"),("iis smtp","Microsoft Exchange/IIS"),
            ("mailenable","MailEnable"),("qmail","qmail"),("haraka","Haraka"),("zimbra","Zimbra"),
            ("amazonses","Amazon SES"),("amazon ses","Amazon SES"),("sendgrid","SendGrid"),("mailgun","Mailgun"),
            ("sparkpost","SparkPost"),("zoho","Zoho Mail"),("google","Google Workspace"),("gmail","Google Workspace"),
            ("mailtrap","Mailtrap"),("axigen","Axigen"),("barracuda","Barracuda"),("proofpoint","Proofpoint"),("mimecast","Mimecast")
        ]
        for k, v in pairs: 
            if k in s: 
                return v
        return None

    def _add(mx: str, port: int, tls: bool, banner_bytes: bytes | None):
        if not banner_bytes:
            return
        banner = banner_bytes.decode("utf-8", errors="ignore").strip()
        if not banner:
            return
        out.append({
            "mx": mx, "port": port, "tls": bool(tls),
            "banner": banner, "server_type": _server_guess(banner)
        })

    for mx in mx_hosts:
        # 25 / 587 (plain)
        for port in (25, 587):
            try:
                with socket.create_connection((mx, port), timeout=timeout) as s:
                    s.settimeout(timeout)
                    b = s.recv(1024)
                    if not b:
                        try: s.sendall(b"EHLO brandmon\r\n"); time.sleep(0.1); b = s.recv(1024)
                        except Exception: pass
                    _add(mx, port, False, b)
            except Exception:
                pass
        # 465 (implicit TLS)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((mx, 465), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=mx) as ss:
                    ss.settimeout(timeout)
                    b = ss.recv(1024)
                    _add(mx, 465, True, b)
        except Exception:
            pass

    return out

# --- SMTP banner ---

def _guess_mta_from_banner(banner: str) -> str | None:
    if not banner:
        return None
    s = banner.lower()
    pairs = [
        ("postfix", "Postfix"),
        ("exim", "Exim"),
        ("sendmail", "Sendmail"),
        ("opensmtpd", "OpenSMTPD"),
        ("microsoft", "Microsoft Exchange"),
        ("exchange", "Microsoft Exchange"),
        ("mailenable", "MailEnable"),
        ("qmail", "qmail"),
        ("haraka", "Haraka"),
        ("zimbra", "Zimbra"),
        ("smtp2go", "SMTP2GO"),
        ("sendgrid", "SendGrid"),
        ("amazonses", "Amazon SES"),
        ("amazon ses", "Amazon SES"),
        ("mailgun", "Mailgun"),
        ("sparkpost", "SparkPost"),
        ("zoho", "Zoho Mail"),
        ("gsuite", "Google Workspace"),
        ("google", "Google Workspace"),
    ]
    for key, label in pairs:
        if key in s:
            return label
    return None

def _read_banner_with_poke(sock, timeout: float) -> str | None:
    sock.settimeout(timeout)
    def _recv():
        try:
            return sock.recv(1024)
        except Exception:
            return b""
    data = _recv()
    if not data:
        try: sock.sendall(b"\r\n")
        except Exception: pass
        time.sleep(0.1)
        data = _recv()
    if not data:
        try: sock.sendall(b"EHLO probe.local\r\n")
        except Exception: pass
        time.sleep(0.1)
        data = _recv()
    if not data:
        return None
    try:
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

def _fetch_smtp_banner(domain: str, timeout: float = 3.0, max_hosts: int = 2) -> dict | None:
   
    if not dns:
        return None
    try:
        mx_ans = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted(
            [(r.preference, str(r.exchange).rstrip('.')) for r in mx_ans],
            key=lambda x: x[0]
        )
        mx_hosts = [h for _, h in mx_hosts][:max_hosts]
    except Exception:
        mx_hosts = []

    for host in mx_hosts:
        # port 25 (plain)
        for port, use_tls in ((25, False), (587, False), (465, True)):
            try:
                if use_tls:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=timeout) as s:
                        with ctx.wrap_socket(s, server_hostname=host) as ss:
                            ss.settimeout(timeout)
                            data = ss.recv(512)
                else:
                    with socket.create_connection((host, port), timeout=timeout) as s:
                        s.settimeout(timeout)
                        data = s.recv(512)
                banner = (data or b"").decode("utf-8", errors="ignore").strip()
                if banner:
                    return {
                        "mx": host,
                        "port": port,
                        "tls": use_tls,
                        "banner": banner,
                        "server_type": _detect_smtp_server(banner),
                    }
            except Exception:
                continue
    return None

# --- TLS (issuer + valid from/to) ---

_TLS_TIME_FMT = "%b %d %H:%M:%S %Y %Z"  # ex: 'Jun  1 12:00:00 2024 GMT'

def _parse_tls_time_str(val: str | None) -> str | None:
    if not val:
        return None
    # încerc întâi cu tz, apoi fără tz (asum UTC)
    for fmt in (_TLS_TIME_FMT, "%b %d %H:%M:%S %Y"):
        try:
            t = time.strptime(val, fmt)
            from datetime import datetime, timezone as _tz
            dt = datetime(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, tzinfo=_tz.utc)
            return dt.isoformat()
        except Exception:
            continue
    return None

def _issuer_pretty_from_meta(issuer_obj) -> str | None:
    """
    Normalizează issuer-ul (din structuri OpenSSL) la 'Organization CN' sau doar 'Organization'.
    Acceptă: string, dict sau listă de RDN-uri ((('O','...'),), (('CN','...'),), ...)
    """
    if not issuer_obj:
        return None
    if isinstance(issuer_obj, str):
        s = issuer_obj.strip()
        return s or None
    if isinstance(issuer_obj, dict):
        org = issuer_obj.get('O') or issuer_obj.get('organizationName') or issuer_obj.get('organization') or issuer_obj.get('o')
        cn  = issuer_obj.get('CN') or issuer_obj.get('commonName') or issuer_obj.get('cn')
        if org and cn: return f"{org} {cn}"
        return org or cn
    # tupluri/listă de RDN-uri
    try:
        pairs = []
        for rdn in issuer_obj:
            for k, v in rdn:
                pairs.append((str(k).lower(), str(v)))
        d = {k: v for k, v in pairs}
        org = d.get('organizationname') or d.get('o')
        cn  = d.get('commonname') or d.get('cn')
        if org and cn: return f"{org} {cn}"
        return org or cn
    except Exception:
        return None

def fetch_tls_info(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Întoarce dict:
      { "issuer": str, "not_before": ISO8601, "not_after": ISO8601, "debug": {...} }
    Face SNI corect și are fallback de decodare din DER.
    """
    debug = {"host": host, "port": port, "tries": []}
    out: dict = {}

    try:
        server_name = idna.encode(host).decode("ascii") if idna else host
    except Exception:
        server_name = host

    # rezolv IP-uri ca să loghez ce-am încercat
    addrs: list[tuple[int, str]] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(server_name, port, type=socket.SOCK_STREAM):
            ip = sockaddr[0]
            addrs.append((family, ip))
    except Exception as e:
        debug["resolve_error"] = str(e)[:300]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    tried_any = False
    for family, ip in (addrs or [(socket.AF_UNSPEC, server_name)]):
        rec = {"addr": ip, "family": "IPv6" if family == socket.AF_INET6 else "IPv4"}
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=server_name) as ssock:
                    # 1) încerc direct forma DER
                    der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert() or {}
            tried_any = True
            rec["ok"] = True
        except Exception as e:
            rec["ok"] = False
            rec["err"] = str(e)[:300]
            debug["tries"].append(rec)
            continue

        # fallback robust: decodez DER prin helper intern
        parsed = None
        if der:
            try:
                import ssl as _sslmod, tempfile, os as _os
                pem = _sslmod.DER_cert_to_PEM_cert(der)
                with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                    tf.write(pem)
                    path = tf.name
                meta = _sslmod._ssl._test_decode_cert(path)
                _os.unlink(path)
                parsed = meta  # chei: 'issuer', 'notBefore', 'notAfter', etc.
            except Exception as e:
                rec["der_decode_err"] = str(e)[:300]

        if not parsed:
            parsed = {
                "notBefore": cert_dict.get("notBefore"),
                "notAfter":  cert_dict.get("notAfter"),
                "issuer":    cert_dict.get("issuer"),  # lăsăm structura brută; o normalizăm mai jos
            }

        nb = _parse_tls_time_str(parsed.get("notBefore"))
        na = _parse_tls_time_str(parsed.get("notAfter"))
        issuer_norm = _issuer_pretty_from_meta(parsed.get("issuer"))

        if issuer_norm: out["issuer"] = issuer_norm
        if nb: out["not_before"] = nb
        if na: out["not_after"]  = na

        debug["tries"].append(rec)
        # am finalizat cu succes pe prima conexiune reușită
        break

    if not tried_any and not out:
        return {"debug": debug}
    out["debug"] = debug
    return out

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
        ns_info = _ns_with_ips(dom)

        # HTTP banner (include status + redirect-uri + final_status/final_reason)
        http_banner = _fetch_http_banner(dom, timeout=2.5)

        # SMTP banner (text simplu)
        smtp_banners = _fetch_smtp_banners(dom, timeout=4.0) if has_mx else []        

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
                "mx_hosts": mx_hosts,
                "ns": ns_info,          
                "fuzzer": fuzzer,
                "http_banner": http_banner,
                "smtp_banners": smtp_banners,
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
                "tls": tls,
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
        logger.info("whois_disabled")
        return
    import time as _time
    db: Session = SessionLocal()
    r = None
    running_key = f"brandmon:whois:running:{variant_id}"
    force_key   = f"brandmon:whois:force:{variant_id}"
    try:
        try:
            r = redis.from_url(settings.redis.url, decode_responses=True)
            r.set(running_key, "1", ex=300)
        except Exception:
            r = None

        v = db.query(Variant).get(variant_id)
        if not v:
            return
        domain = v.domain.lower()

        force = False
        try:
            force = bool(r and r.get(force_key))
        except Exception:
            force = False

        row = read_cache(db, v.id)
        if row and not force:
            try:
                age = _time.time() - row.fetched_at.timestamp()
                ttl_hours = int(getattr(settings.whois, "ttl_hours", 24))
                if age < ttl_hours * 3600:
                    logger.info("whois_skip_ttl", extra={"variant_id": variant_id, "age_sec": int(age)})
                    return
            except Exception:
                pass

        if (not force) and (not cooldown_ok(domain)):
            logger.info("whois_skip_cooldown", extra={"variant_id": variant_id, "domain": domain})
            return

        norm = fetch_whois_whoisxmlapi(domain, timeout=int(getattr(settings.whois, "timeout_sec", 15)))
        if not norm:
            norm = {}  # IMPORTANT: marcăm că “a rulat” ca să nu mai vezi 204 la nesfârșit

        upsert_cache(db, v, norm, source="whoisxmlapi")
        logger.info("whois_upsert_ok", extra={"variant_id": variant_id, "has_data": bool(norm)})
    except Exception as e:
        logger.exception("whois_enrich_exc", extra={"variant_id": variant_id, "err": str(e)})
    finally:
        try:
            if r:
                r.delete(running_key)
                r.delete(force_key)
        except Exception:
            pass
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
