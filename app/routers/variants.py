# app/routers/variants.py
from __future__ import annotations
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..db import get_db
from ..models import Variant, CheckRun
from ..services.whois import read_cache
import redis

router = APIRouter(prefix="/variants", tags=["variants"])
TZ = ZoneInfo("Europe/Bucharest")

def _fmt(dt: datetime | None) -> str | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ).strftime("%d-%m-%Y %H:%M:%S")

def _parse_date_safe(val) -> datetime | None:
    if not val:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)

    s = str(val).strip().replace("Z", "+00:00")
    if not s:
        return None

    # ISO 8601
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    for fmt in (
        "%b %d %H:%M:%S %Y %Z",  # Jun 01 12:00:00 2024 GMT
        "%Y-%m-%d %H:%M:%S %Z",  # 2018-11-07 00:00:00 UTC
        "%Y-%m-%d %H:%M:%S",     # 2018-11-07 00:00:00
        "%Y-%m-%d",              # 2018-11-07
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None

def _domain_age(created_dt: datetime | None) -> str | None:
    if not created_dt:
        return None
    if created_dt.tzinfo is None:
        created_dt = created_dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    sec = max(0, int((now - created_dt).total_seconds()))
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts: list[str] = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

def _days_left(until: datetime | None) -> int | None:
    if not until:
        return None
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0, (until - now).days)

def _as_bool(x):
    if x is None:
        return None
    if isinstance(x, bool):
        return x
    sv = str(x).strip().lower()
    if sv in ("1", "true", "yes", "y", "on"):
        return True
    if sv in ("0", "false", "no", "n", "off"):
        return False
    return None

def _latest_whois_from_cache(db: Session, variant_id: int):

    row = read_cache(db, variant_id)
    if not row:
        return None

    m = getattr(row, "_mapping", row)
    data = m["data"]
    try:
        norm = dict(data)
    except Exception:
        import json as _json
        norm = _json.loads(str(data))

    raw = norm.get("raw") or {}
    reg = raw.get("registryData") or {}

    def pick_top_then_reg(key: str):
        if norm.get(key) not in (None, "", [], {}):
            return norm.get(key)
        if reg.get(key) not in (None, "", [], {}):
            return reg.get(key)
        return None

    def norm_status(v):
        if not v:
            return []
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if str(x).strip()]
        s = str(v).strip()
        if not s:
            return []
        import re as _re
        return [x.strip() for x in _re.split(r"[;,]\s*|\s{2,}", s) if x.strip()]

    def norm_nameservers(obj):
        if not obj:
            return []
        if isinstance(obj, list):
            out = []
            for it in obj:
                if isinstance(it, str) and it.strip():
                    out.append(it.strip())
                elif isinstance(it, dict):
                    for k in ("ldhName", "host", "hostname", "name", "ns"):
                        v = it.get(k)
                        if isinstance(v, str) and v.strip():
                            out.append(v.strip()); break
            return out
        if isinstance(obj, dict):
            if obj.get("hostNames"):
                return [str(h).strip() for h in obj["hostNames"] if str(h).strip()]
            if obj.get("rawText"):
                return [ln.strip() for ln in str(obj["rawText"]).splitlines() if ln.strip()]
            return []
        if isinstance(obj, str):
            return [ln.strip() for ln in obj.splitlines() if ln.strip()]
        return []

    # --- câmpurile cerute (top-level, apoi fallback în registryData) ---
    status_raw = pick_top_then_reg("status")
    created_raw = pick_top_then_reg("createdDate")
    updated_raw = pick_top_then_reg("updatedDate")
    expires_raw = pick_top_then_reg("expiresDate")
    age_days    = pick_top_then_reg("estimatedDomainAge")
    email       = pick_top_then_reg("contactEmail")
    registrar   = pick_top_then_reg("registrarName")
    ns_obj      = pick_top_then_reg("nameServers")

    created_dt = _parse_date_safe(created_raw)
    updated_dt = _parse_date_safe(updated_raw)
    expires_dt = _parse_date_safe(expires_raw)

    statuses = norm_status(status_raw)
    nameservers = norm_nameservers(ns_obj)

    # Age: dacă avem estimatedDomainAge în zile → preferat; altfel fallback pe calc din created_dt
    if isinstance(age_days, (int, float)) and age_days is not None:
        domain_age_str = f"{int(age_days)} days"
    else:
        domain_age_str = _domain_age(created_dt)  # fallback (d h m s)

    return {
        "source": m["source"],
        "last_check_fmt": _fmt(m["fetched_at"]),
        "domain_age": domain_age_str,
        "data": {
            "registrar": registrar,
            "created": created_raw,
            "created_fmt": _fmt(created_dt),
            "updated": updated_raw,
            "updated_fmt": _fmt(updated_dt),
            "expires": expires_raw,
            "expires_fmt": _fmt(expires_dt),
            "registrant_org": None,
            "registrant_country": None,
            "email": email,
            "statuses": statuses,
            "nameservers": nameservers,
        },
    }

def _latest_domain_details_from_runs(runs):
    details = {
        "dns_ok": None,
        "ns": [],
        "has_mx": None,
        "mx_records": [],
        "smtp_banners": [],
        "http_status": None,
        "http_reason": None,
        "http_server": None,
        "http_powered_by": None,
        "http_redirect_url": None,
        "http_final_url": None,
        "http_ip": None,
        "tls_issuer": None,
        "tls_valid_from_fmt": None,
        "tls_valid_to_fmt": None,
        "tls_days_left": None,
        "spf_found": None,   "spf_record": None,
        "dkim_found": None,  "dkim_selectors": [],
        "dmarc_found": None, "dmarc_policy": None, "dmarc_record": None,
    }

    def set_once(key, value):
        if value in (None, "", [], {}):
            return
        if details.get(key) in (None, "", [], {}):
            details[key] = value

    for r in runs:
        n = r.notes or {}

        # asigură-te că avem mereu un dict pentru http_banner
        hb = n.get("http_banner") or {}
        if not isinstance(hb, dict):
            hb = {}

        # DNS
        if details["dns_ok"] is None and ("dns_ok" in n or r.dns_ok is not None):
            set_once("dns_ok", bool(n.get("dns_ok") if "dns_ok" in n else r.dns_ok))

        # NS (+ IPs)
        if not details["ns"]:
            ns_val = n.get("ns")
            ns_list = []
            if isinstance(ns_val, dict):
                for host, ips in ns_val.items():
                    if host:
                        ips_norm = [str(i).strip() for i in (ips or []) if str(i).strip()]
                        ns_list.append({"host": str(host).strip(), "ips": ips_norm})
            elif isinstance(ns_val, list):
                for item in ns_val:
                    if isinstance(item, dict):
                        host = (item.get("host") or item.get("ns") or "").strip()
                        ips  = item.get("ips") or item.get("addresses") or []
                        if host:
                            ips_norm = [str(i).strip() for i in (ips or []) if str(i).strip()]
                            ns_list.append({"host": host, "ips": ips_norm})
                    elif isinstance(item, str) and item.strip():
                        ns_list.append({"host": item.strip(), "ips": []})
            elif isinstance(ns_val, str) and ns_val.strip():
                ns_list.append({"host": ns_val.strip(), "ips": []})
            if ns_list:
                details["ns"] = ns_list

        # MX
        if details["has_mx"] is None and "has_mx" in n:
            set_once("has_mx", _as_bool(n.get("has_mx")))
        if not details["mx_records"]:
            mx_list = []
            if isinstance(n.get("mx"), list):
                for item in n.get("mx"):
                    if isinstance(item, dict):
                        host = item.get("exchange") or item.get("host") or item.get("hostname")
                        prio = item.get("priority") or item.get("pref") or item.get("preference")
                        if host:
                            mx_list.append(f"{host} (prio {prio})" if prio is not None else str(host))
                    elif isinstance(item, str) and item.strip():
                        mx_list.append(item.strip())
            if not mx_list and isinstance(n.get("mx_hosts"), list):
                for host in n.get("mx_hosts"):
                    if isinstance(host, str) and host.strip():
                        mx_list.append(host.strip())
            if mx_list:
                details["mx_records"] = mx_list

        # --- SMTP banners (listă nouă + compat vechi) ---
        if not details["smtp_banners"]:
            sb = n.get("smtp_banners")
            if isinstance(sb, list) and sb:
                norm = []
                for it in sb:
                    if isinstance(it, dict):
                        norm.append({
                            "mx": it.get("mx"),
                            "port": it.get("port"),
                            "tls": (bool(it.get("tls")) if it.get("tls") is not None else None),
                            "banner": it.get("banner"),
                            # preferă server_type, dar acceptă și guess
                            "server_type": it.get("server_type") or it.get("guess"),
                        })
                    elif isinstance(it, str) and it.strip():
                        norm.append({
                            "mx": None, "port": None, "tls": None,
                            "banner": it.strip(), "server_type": None,
                        })
                if norm:
                    details["smtp_banners"] = norm
            else:
                # compat: un singur obiect/șir sub cheia veche "smtp_banner"
                sb_old = n.get("smtp_banner")
                if isinstance(sb_old, dict):
                    details["smtp_banners"] = [{
                        "mx": sb_old.get("mx"),
                        "port": sb_old.get("port"),
                        "tls": sb_old.get("tls"),
                        "banner": sb_old.get("banner") or str(sb_old),
                        "server_type": sb_old.get("server_type") or sb_old.get("guess"),
                    }]
                elif isinstance(sb_old, str) and sb_old.strip():
                    details["smtp_banners"] = [{
                        "mx": None, "port": None, "tls": None,
                        "banner": sb_old.strip(), "server_type": None,
                    }]

        # --- HTTP banner ---
        if details["http_status"] is None:
            hs = None
            if isinstance(hb.get("status"), int):
                hs = hb.get("status")
            elif isinstance(getattr(r, "http_status", None), int):
                hs = r.http_status
            if isinstance(hs, int):
                set_once("http_status", hs)

        if details.get("http_reason") is None and hb.get("reason"):
            set_once("http_reason", hb.get("reason"))
        if details["http_server"] is None and hb.get("server"):
            set_once("http_server", hb.get("server"))
        if details["http_powered_by"] is None:
            pby = hb.get("powered_by") or hb.get("x_powered_by") or hb.get("x-powered-by")
            if pby:
                set_once("http_powered_by", pby)
        if details.get("http_redirect_url") is None:
            loc = hb.get("final_url") or hb.get("location")
            if loc:
                set_once("http_redirect_url", loc)
        if details.get("http_final_url") is None:
            furl = hb.get("final_url") or hb.get("location") or hb.get("initial_url")
            if furl:
                set_once("http_final_url", furl)
        if details.get("http_ip") is None and hb.get("peer_ip"):
            set_once("http_ip", hb.get("peer_ip"))

        # --- TLS ---
        tls = n.get("tls") or {}
        if isinstance(tls, dict):
            issuer = tls.get("issuer") or tls.get("issuer_cn") or tls.get("issuer_common_name")
            not_before = _parse_date_safe(tls.get("not_before") or tls.get("notBefore") or tls.get("valid_from"))
            not_after  = _parse_date_safe(tls.get("not_after")  or tls.get("notAfter")  or tls.get("valid_to") or tls.get("expires"))
            if issuer:
                set_once("tls_issuer", issuer)
            if not_before:
                set_once("tls_valid_from_fmt", _fmt(not_before))
            if not_after:
                set_once("tls_valid_to_fmt", _fmt(not_after))
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                set_once("tls_days_left", max(0, (not_after - now).days))

        # --- SPF / DKIM / DMARC ---
        if details["spf_found"] is None:
            spf = n.get("spf")
            if isinstance(spf, dict):
                set_once("spf_found", _as_bool(spf.get("found")))
                set_once("spf_record", spf.get("record"))
            elif isinstance(spf, bool):
                set_once("spf_found", spf)
            elif isinstance(spf, str) and spf.strip():
                set_once("spf_found", True)
                set_once("spf_record", spf.strip())

        if details["dkim_found"] is None:
            dkim = n.get("dkim")
            if isinstance(dkim, dict):
                set_once("dkim_found", _as_bool(dkim.get("found")))
                sels = dkim.get("selectors")
                if isinstance(sels, str):
                    sels = [s.strip() for s in sels.split(",") if s.strip()]
                if sels:
                    set_once("dkim_selectors", sels)
            elif isinstance(dkim, bool):
                set_once("dkim_found", dkim)
            elif isinstance(dkim, str) and dkim.strip():
                set_once("dkim_found", True)
                set_once("dkim_selectors", [dkim.strip()])

        if details["dmarc_found"] is None:
            dmarc = n.get("dmarc")
            if isinstance(dmarc, dict):
                set_once("dmarc_found",  _as_bool(dmarc.get("found")))
                set_once("dmarc_policy", dmarc.get("policy"))
                set_once("dmarc_record", dmarc.get("record"))
            elif isinstance(dmarc, bool):
                set_once("dmarc_found", dmarc)
            elif isinstance(dmarc, str) and dmarc.strip():
                set_once("dmarc_found",  True)
                set_once("dmarc_record", dmarc.strip())

        # early-exit
        if (
            details["dns_ok"] is not None
            and (details["has_mx"] is not None or details["mx_records"])
            and (details["http_status"] is not None or details["http_server"] is not None or details["http_powered_by"] is not None)
            and (details["tls_issuer"] is not None or details["tls_valid_to_fmt"] is not None)
            and details["spf_found"] is not None
            and details["dkim_found"] is not None
            and details["dmarc_found"] is not None
        ):
            break

    # flag comod pentru UI
    details["smtp_found"] = bool(details["smtp_banners"])
    return details

@router.get("/{variant_id}", response_class=HTMLResponse)
def variant_detail(variant_id: int, request: Request, db: Session = Depends(get_db)):
    templates = request.app.state.templates

    v = db.get(Variant, variant_id)
    if not v:
        raise HTTPException(status_code=404)

    history = (
        db.query(CheckRun)
        .filter(CheckRun.variant_id == v.id)
        .order_by(desc(CheckRun.ts))
        .limit(200)
        .all()
    )

    for r in history:
        n = r.notes or {}
        rv = type("RowView", (), {})()
        rv.ts_fmt = _fmt(r.ts)
        rv.fuzzer = n.get("fuzzer")
        rv.dns_ok = bool(n.get("dns_ok") if "dns_ok" in n else r.dns_ok)
        rv.has_mx = _as_bool(n.get("has_mx"))
        hb = n.get("http_banner") or {}
        rv.http_status = hb.get("status") if isinstance(hb.get("status"), int) else (r.http_status if isinstance(r.http_status, int) else None)
        rv.ct_seen = n.get("ct_seen_count")
        rv.sld_distance = n.get("sld_distance")

        def _bool_from(x):
            if isinstance(x, dict):
                return _as_bool(x.get("found"))
            if isinstance(x, bool):
                return x
            if isinstance(x, str) and x.strip():
                return True
            return None

        rv.spf_found   = _bool_from(n.get("spf"))
        rv.dkim_found  = _bool_from(n.get("dkim"))
        rv.dmarc_found = _bool_from(n.get("dmarc"))
        r.view = rv

    details = _latest_domain_details_from_runs(history)

    # WHOIS: afișăm persistent dacă există cache (altfel ascuns până la primul scan)
    whois = _latest_whois_from_cache(db, v.id)

    v.first_seen_fmt = _fmt(v.first_seen_at)
    v.last_checked_fmt = _fmt(v.last_checked_at)

    return templates.TemplateResponse(
        "variant_detail.html",
        {
            "request": request,
            "variant": v,
            "history": history,
            "details": details,
            "whois": whois,
        },
    )

@router.post("/{variant_id}/whois", response_class=HTMLResponse)
def run_whois_scan(variant_id: int, request: Request, db: Session = Depends(get_db)):
    v = db.get(Variant, variant_id)
    if not v:
        raise HTTPException(status_code=404)
    # forțează un run real (nu lăsa TTL/cooldown să-l sară)
    try:
        r = redis.from_url(settings.redis.url, decode_responses=True)
        r.set(f"brandmon:whois:force:{variant_id}", "1", ex=120)
    except Exception:
        pass
    try:
        from ..tasks import whois_enrich
        whois_enrich.delay(v.id)
    except Exception:
        pass
    return RedirectResponse(url=f"/variants/{v.id}", status_code=303)

# HTMX: butonul care pornește scanul și se învârte
@router.post("/{variant_id}/whois/trigger", response_class=HTMLResponse)
def whois_trigger(variant_id: int, request: Request, db: Session = Depends(get_db)):
    v = db.get(Variant, variant_id)
    if not v:
        raise HTTPException(status_code=404)
    # forțează run (bypass TTL/cooldown)
    try:
        r = redis.from_url(settings.redis.url, decode_responses=True)
        r.set(f"brandmon:whois:force:{variant_id}", "1", ex=120)
    except Exception:
        pass
    try:
        from ..tasks import whois_enrich
        whois_enrich.delay(v.id)
    except Exception:
        pass
    templates = request.app.state.templates
    return templates.TemplateResponse("_partials/whois_button.html", {"request": request, "variant": v, "loading": True})

@router.get("/{variant_id}/whois/table", response_class=HTMLResponse)
def whois_table(variant_id: int, request: Request, db: Session = Depends(get_db)):
    templates = request.app.state.templates
    v = db.get(Variant, variant_id)
    if not v:
        raise HTTPException(status_code=404)
    whois = _latest_whois_from_cache(db, v.id)
    if whois:
        return templates.TemplateResponse("_partials/whois_table.html", {"request": request, "variant": v, "whois": whois})
    # încă nu avem cache → 204 pentru poll HTMX
    return HTMLResponse(status_code=204)

@router.get("/{variant_id}/whois/button", response_class=HTMLResponse)
def whois_button(variant_id: int, request: Request, db: Session = Depends(get_db)):
    templates = request.app.state.templates
    v = db.get(Variant, variant_id)
    if not v:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse("_partials/whois_button.html", {"request": request, "variant": v, "loading": False})

@router.post("/{variant_id}/monitor", response_class=HTMLResponse)
def toggle_monitor(
    variant_id: int,
    request: Request,
    monitor: str | None = Form(None),
    db: Session = Depends(get_db),
):
    templates = request.app.state.templates
    v = db.get(Variant, variant_id)
    if not v:
        raise HTTPException(status_code=404)

    val = (monitor or "").strip().lower()
    is_on = val in ("1", "true", "on", "yes")

    v.status = "monitoring" if is_on else "stop"
    db.add(v); db.commit(); db.refresh(v)

    if is_on:
        try:
            from ..tasks import scan_variant
            scan_variant.delay(v.id)
        except Exception:
            pass

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("_partials/variant_row.html", {"request": request, "v": v})

    return RedirectResponse(url=f"/variants/{v.id}", status_code=303)
