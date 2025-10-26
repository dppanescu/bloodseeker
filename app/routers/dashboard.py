from __future__ import annotations
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..db import get_db
from ..models import SeedDomain, Variant, CheckRun
from fastapi.responses import HTMLResponse
from fastapi import Request

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    templates = request.app.state.templates
    seeds = db.query(func.count(SeedDomain.id)).scalar()
    variants = db.query(func.count(Variant.id)).scalar()
    suspicious = db.query(Variant).filter(Variant.risk_score >= 70).count()
    latest = db.query(CheckRun).order_by(CheckRun.ts.desc()).limit(10).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "seeds": seeds, "variants": variants, "suspicious": suspicious, "latest": latest})
