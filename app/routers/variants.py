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

router = APIRouter(prefix="/variants", tags=["variants"])
TZ = ZoneInfo("Europe/Bucharest")

def _fmt(dt: datetime | None) -> str | None:
    """dd-mm-YYYY HH:mm:ss (Europe/Bucharest)."""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ).strftime("%d-%m-%Y %H:%M:%S")

def _parse_date_safe(val) -> datetime | None:
    """Acceptă datetime sau string în câteva formate comune; întoarce datetime(UTC) sau None."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    s = str(val).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
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

def _latest_whois_from_runs(runs):
    for r in runs:
        n = r.notes or {}
        data = n.get("whois") or n.get("whois_parsed") or n.get("whois_summary")
        if data and isinstance(data, dict):
            created = _parse_date_safe(data.get("created"))
            updated = _parse_date_safe(data.get("updated"))
            expires = _parse_date_safe(data.get("expires"))
            return {
                "source": data.get("source") or n.get("whois_source") or "whois",
                "last_check_fmt": _fmt(r.ts),
                "domain_age": _domain_age(created),
                "data": {
                    "registrar": data.get("registrar"),
                    "created": data.get("created"),
                    "created_fmt": _fmt(created),
                    "updated": data.get("updated"),
                    "updated_fmt": _fmt(updated),
                    "expires": data.get("expires"),
                    "expires_fmt": _fmt(expires),
                    "registrant_org": data.get("registrant_org"),
                    "registrant_country": data.get("registrant_country"),
                    "email": data.get("email"),
                    "statuses": data.get("statuses") or data.get("status") or [],
                    "nameservers": data.get("nameservers") or data.get("ns") or [],
                },
            }
    return None  # WHOIS doar la cerere

def _latest_domain_details_from_runs(runs):
    """
    Agregă cele mai recente info DNS/MX/SPF/DKIM/DMARC + HTTP + TLS din istoricul CheckRun.
    """
    details = {
        "dns_ok": None,

        "has_mx": None,
        "mx_records": [],
        "smtp_banner": None,

        "http_status": None,
        "http_reason": None,         
        "http_server": None,
        "http_powered_by": None,
        "http_redirect_url": None,

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

    for r in runs:  # desc după ts
        n = r.notes or {}

        # DNS
        if details["dns_ok"] is None and ("dns_ok" in n or r.dns_ok is not None):
            set_once("dns_ok", bool(n.get("dns_ok") if "dns_ok" in n else r.dns_ok))

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

        if details["smtp_banner"] is None and n.get("smtp_banner"):
            details["smtp_banner"] = n.get("smtp_banner")

        # HTTP
        hb = n.get("http_banner") or {}
        if details["http_status"] is None:
            hs = r.http_status if r.http_status is not None else hb.get("status")
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

        # TLS / Cert
        tls = n.get("tls") or {}
        if isinstance(tls, dict):
            issuer = tls.get("issuer") or tls.get("issuer_cn") or tls.get("issuer_common_name")
            if not issuer and isinstance(tls.get("issuer"), dict):
                issuer = tls["issuer"].get("CN") or tls["issuer"].get("commonName")
            not_before = _parse_date_safe(tls.get("not_before") or tls.get("notBefore") or tls.get("valid_from"))
            not_after  = _parse_date_safe(tls.get("not_after")  or tls.get("notAfter")  or tls.get("valid_to") or tls.get("expires"))
            if issuer:
                set_once("tls_issuer", issuer)
            if not_before:
                set_once("tls_valid_from_fmt", _fmt(not_before))
            if not_after:
                set_once("tls_valid_to_fmt", _fmt(not_after))
                # days left
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                set_once("tls_days_left", max(0, (not_after - now).days))

        # SPF
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

        # DKIM
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

        # DMARC
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

        # stop dacă avem suficient
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

    # view pentru tabel
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

    whois = None
    if (request.query_params.get("whois") or "").strip().lower() in ("1", "true", "yes"):
        whois = _latest_whois_from_runs(history)

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
    try:
        from ..tasks import scan_variant
        scan_variant.delay(v.id)
    except Exception:
        pass
    return RedirectResponse(url=f"/variants/{v.id}?whois=1", status_code=303)

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
