# app/routers/seeds.py
from __future__ import annotations

import json
import html
import math
import traceback
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import List

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, nullslast

from ..db import SessionLocal
from ..models import SeedDomain, Variant, CheckRun
from ..logging_setup import configure_logger
from ..tasks import generate_variants, generate_variants_dnstwist

logger = configure_logger("seeds-router")
router = APIRouter(prefix="/seeds", tags=["seeds"])

# ---------- helpers ----------
TZ = ZoneInfo("Europe/Bucharest")

def humanize_dt(dt: datetime) -> str:
    """Relative time în engleză, fallback la dată locală."""
    if not isinstance(dt, datetime):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = (now - dt.astimezone(timezone.utc)).total_seconds()
    if delta < 0:
        delta = 0
    if delta < 5:
        return "just now"
    if delta < 60:
        return f"{int(delta)} seconds ago"
    mins = int(delta // 60)
    if mins < 60:
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    hours = int(delta // 3600)
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = int(delta // 86400)
    if days == 1:
        return "yesterday " + dt.astimezone(TZ).strftime("%H:%M")
    if days < 7:
        return f"{days} days ago"
    return dt.astimezone(TZ).strftime("%Y-%m-%d %H:%M")

def _split_csv(val: str | None) -> List[str]:
    if not val:
        return []
    out = [x.strip() for x in val.split(",") if x.strip()]
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            uniq.append(x); seen.add(x)
    return uniq

def _collect_fuzzers(form: dict) -> List[str]:
    mapping = {
        "f_homoglyph":"homoglyph",
        "f_omission":"omission",
        "f_transposition":"transposition",
        "f_insertion":"insertion",
        "f_replacement":"replacement",
        "f_repetition":"repetition",
        "f_bitsquatting":"bitsquatting",
        "f_vowelswap":"vowel-swap",
        "f_hyphenation":"hyphenation",
        "f_subdomain":"subdomain",
    }
    return [algo for field, algo in mapping.items() if form.get(field) is not None]

def _normalize_domain(name: str) -> str:
    """Taie schemele (http/https), path/query și normalizează la lower."""
    n = (name or "").strip().lower()
    # elimină schemele
    for prefix in ("http://", "https://"):
        if n.startswith(prefix):
            n = n[len(prefix):]
            break
    # taie la primul slash/spațiu
    for cut in ("/", " ", "\t", "\n", "\r"):
        if cut in n:
            n = n.split(cut, 1)[0]
    # elimină trailing dot
    n = n.rstrip(".")
    return n

def _render_first_template(request: Request, names: List[str], context: dict) -> HTMLResponse:
    """Încearcă o listă de template-uri; altfel HTML fallback (fără 500)."""
    env = request.app.state.templates.env
    for name in names:
        try:
            tpl = env.get_template(name)
            html_txt = tpl.render(**context)
            return HTMLResponse(html_txt)
        except Exception as e:
            logger.warning("template_render_failed",
                           extra={"template_name": name, "err": str(e)})
            continue

    # fallback sigur (minimal)
    seed = context.get("seed")
    variants = context.get("variants") or []
    token = context.get("token", "ok")

    def _ga(obj, attr, default=""):
        try:
            return getattr(obj, attr)
        except Exception:
            return default

    rows = []
    for v in variants:
        rows.append(
            "<tr>"
            f"<td>{_ga(v,'id','')}</td>"
            f"<td>{html.escape(str(_ga(v,'domain','')))}</td>"
            f"<td>{_ga(v,'risk_score','')}</td>"
            f"<td>{'✔' if _ga(v,'is_registered',False) else ''}</td>"
            f"<td>{html.escape(str(_ga(v,'fuzzer','')))}</td>"
            "</tr>"
        )
    html_txt = f"""
    <h1>Seed #{getattr(seed,'id','?')}: {html.escape(str(getattr(seed,'name','')))}</h1>
    <div>Options:</div>
    <pre style="white-space:pre-wrap;margin:6px 0 12px 0">{html.escape(json.dumps(getattr(seed,'options',{}) or {}, ensure_ascii=False, indent=2))}</pre>
    <form method="post" action="/seeds/{getattr(seed,'id','')}/delete" onsubmit="return confirm('Delete seed and full history?');" style="margin-bottom:14px;">
      <input type="hidden" name="token" value="{html.escape(token)}">
      <button type="submit">Delete</button>
    </form>
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr><th>ID</th><th>Domain</th><th>Score</th><th>Reg?</th><th>Fuzzer</th></tr></thead>
      <tbody>{''.join(rows) or '<tr><td colspan="5">(none)</td></tr>'}</tbody>
    </table>
    """
    return HTMLResponse(html_txt)

# ---------- pages ----------

@router.get("", response_class=HTMLResponse, include_in_schema=False)
@router.get("/", response_class=HTMLResponse)
def list_seeds(request: Request):
    db: Session = SessionLocal()
    try:
        seeds = db.query(SeedDomain).order_by(SeedDomain.id.desc()).all()
        for s in seeds:
            try:
                s.created_human = humanize_dt(s.created_at)
            except Exception:
                s.created_human = ""
        token = "ok"  # TODO: CSRF real
        return request.app.state.templates.TemplateResponse(
            "seeds_list.html",
            {"request": request, "seeds": seeds, "token": token},
        )
    finally:
        db.close()

@router.get("/{seed_id}", response_class=HTMLResponse)
@router.get("/{seed_id}/", response_class=HTMLResponse, include_in_schema=False)
def seed_detail(seed_id: int, request: Request):
    """
    Detaliu seed + listă variante cu KPI-uri, filtrare/sortare și paginație.
    """
    db: Session = SessionLocal()
    try:
        seed = db.query(SeedDomain).filter(SeedDomain.id == seed_id).first()
        if not seed:
            logger.warning("seed_not_found", extra={"seed_id": seed_id})
            raise HTTPException(status_code=404, detail="Seed not found")

        # KPI
        total_variants = db.query(func.count(Variant.id)).filter(Variant.seed_id == seed_id).scalar() or 0
        high_risk = db.query(func.count(Variant.id)).filter(
            Variant.seed_id == seed_id,
            Variant.risk_score >= 70
        ).scalar() or 0

        # filtre & sort
        qp = request.query_params
        q = (qp.get("q") or "").strip()
        try:
            min_score = int(qp.get("min_score") or "0")
        except Exception:
            min_score = 0
        sort = (qp.get("sort") or "-risk").strip()

        try:
            per_page = int(qp.get("per_page") or "50")
        except Exception:
            per_page = 50
        if per_page not in (10, 25, 50, 100, 200):
            per_page = 50

        try:
            page = int(qp.get("page") or "1")
        except Exception:
            page = 1
        if page < 1:
            page = 1

        base_q = db.query(Variant).filter(Variant.seed_id == seed_id)
        if q:
            base_q = base_q.filter(Variant.domain.ilike(f"%{q}%"))
        if min_score > 0:
            base_q = base_q.filter(Variant.risk_score >= min_score)

        total_filtered = base_q.with_entities(func.count(Variant.id)).scalar() or 0

        if sort == "-risk":
            order_cols = [nullslast(Variant.risk_score.desc()), Variant.id.desc()]
        elif sort == "risk":
            order_cols = [nullslast(Variant.risk_score.asc()), Variant.id.desc()]
        elif sort == "-last":
            order_cols = [nullslast(Variant.last_checked_at.desc()), Variant.id.desc()]
        elif sort == "last":
            order_cols = [nullslast(Variant.last_checked_at.asc()), Variant.id.desc()]
        elif sort == "domain":
            order_cols = [Variant.domain.asc()]
        elif sort == "-domain":
            order_cols = [Variant.domain.desc()]
        else:
            order_cols = [nullslast(Variant.risk_score.desc()), Variant.id.desc()]

        pages = max(1, math.ceil(total_filtered / per_page)) if per_page else 1
        if page > pages:
            page = pages
        offset = (page - 1) * per_page if per_page else 0

        variants = base_q.order_by(*order_cols).offset(offset).limit(per_page).all()

        window = 5
        start = max(1, page - (window // 2))
        end = min(pages, start + window - 1)
        start = max(1, end - window + 1)

        has_prev = page > 1
        has_next = page < pages

        token = "ok"
        ctx = {
            "request": request,
            "seed": seed,
            "variants": variants,
            "token": token,
            "kpi": {"total_variants": total_variants, "high_risk": high_risk},
            "q": q, "min_score": min_score, "sort": sort,
            "page": page, "per_page": per_page, "total": total_filtered, "pages": pages,
            "page_start": start, "page_end": end,
            "has_prev": has_prev, "has_next": has_next,
            "prev_page": page - 1 if has_prev else 1,
            "next_page": page + 1 if has_next else pages,
        }
        return _render_first_template(request, ["seeds_detail.html", "seed_detail.html"], ctx)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("seed_detail_error", extra={"seed_id": seed_id, "err": str(e), "trace": traceback.format_exc()})
        msg = html.escape(str(e))
        return HTMLResponse(f"<h1>Seed {seed_id}</h1><p>Error: <code>{msg}</code></p>", status_code=500)
    finally:
        db.close()

@router.post("/add")
async def add_seed(request: Request):
    form = {k: v for k, v in (await request.form()).items()}
    raw_name = (form.get("name") or "")
    name = _normalize_domain(raw_name)
    if not name or "." not in name:
        raise HTTPException(status_code=400, detail="Invalid domain")

    generator = (form.get("generator") or "simple").strip().lower()

    # Construim STRICT opțiunile din UI (nimic implicit extra)
    opts: dict = {}

    # TLDs (→ --tld)
    tlds = _split_csv(form.get("tlds"))
    if tlds:
        opts["tlds"] = tlds

    # Dictionary/prefix — ELIMINAT COMPLET

    # Fuzzers bifate (→ --fuzzers)
    fuzzers = _collect_fuzzers(form)
    if fuzzers:
        opts["fuzzers"] = fuzzers

    # Limits/filters (doar dacă sunt setate)
    mv = form.get("max_variants")
    if mv:
        try:
            mv_i = int(mv)
            if mv_i > 0:
                opts["max_variants"] = mv_i
        except Exception:
            pass

    med = form.get("max_edit_distance")
    if med:
        try:
            med_i = int(med)
            if med_i >= 0:
                opts["max_edit_distance"] = med_i
        except Exception:
            pass

    db: Session = SessionLocal()
    try:
        s = SeedDomain(name=name, options=opts)
        db.add(s)
        db.commit()
        db.refresh(s)

        # Rulează generatorul selectat
        if generator == "simple":
            generate_variants.delay(s.id)
        elif generator == "dnstwist":
            generate_variants_dnstwist.delay(s.id)
        elif generator == "both":
            generate_variants.delay(s.id)
            generate_variants_dnstwist.delay(s.id)

        return RedirectResponse(url="/seeds", status_code=303)
    finally:
        db.close()

@router.post("/{seed_id}/delete")
def delete_seed(seed_id: int):
    """Șterge seed-ul + toată istoria (variants + checkruns)."""
    db: Session = SessionLocal()
    try:
        seed = db.get(SeedDomain, seed_id)
        if not seed:
            raise HTTPException(status_code=404, detail="Seed not found")

        vid_rows = db.query(Variant.id).filter(Variant.seed_id == seed_id).all()
        variant_ids = [vid for (vid,) in vid_rows]

        if variant_ids:
            db.query(CheckRun).filter(CheckRun.variant_id.in_(variant_ids)).delete(synchronize_session=False)
            db.query(Variant).filter(Variant.id.in_(variant_ids)).delete(synchronize_session=False)
        else:
            db.query(Variant).filter(Variant.seed_id == seed_id).delete(synchronize_session=False)

        db.delete(seed)
        db.commit()
        return RedirectResponse(url="/seeds", status_code=303)
    finally:
        db.close()

@router.post("/{seed_id}/generate")
def regenerate_seed(seed_id: int):
    db: Session = SessionLocal()
    try:
        seed = db.get(SeedDomain, seed_id)
        if not seed:
            raise HTTPException(status_code=404, detail="Seed not found")
        generate_variants_dnstwist.delay(seed.id)
        return RedirectResponse(url=f"/seeds/{seed_id}", status_code=303)
    finally:
        db.close()
