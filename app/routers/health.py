# app/routers/health.py
from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from ..health import aggregate
import html
from collections import deque
from pathlib import Path

router = APIRouter(prefix="/health", tags=["health"])

@router.get("/", response_class=HTMLResponse)
def health_page(request: Request):
    return request.app.state.templates.TemplateResponse(
        "health.html",
        {"request": request}
    )

@router.get("/cards", response_class=HTMLResponse)
def health_cards(request: Request):
    data = aggregate(request.app)
    return request.app.state.templates.TemplateResponse(
        "health.html",
        {"request": request, "data": data, "fragment": "cards"},
        headers={"Cache-Control": "no-store"},
    )

@router.get("/logs", response_class=HTMLResponse)
def tail_logs(lines: int = 200):
    path = Path("/var/log/brandmon/brandmon.log")
    try:
        if path.exists():
            dq = deque(maxlen=max(1, min(lines, 10000)))
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    dq.append(line)
            content = "".join(dq)
        else:
            content = f"<missing: {path}>"
    except Exception as e:
        content = f"<unable to read {path}: {e}>"

    return HTMLResponse(
        f"<pre style='white-space:pre-wrap;margin:0'>{html.escape(content)}</pre>",
        headers={"Cache-Control": "no-store"},
    )

@router.get("/api", response_class=JSONResponse)
def health_api(request: Request):
    return JSONResponse(aggregate(request.app), headers={"Cache-Control": "no-store"})

@router.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return PlainTextResponse("ok")

@router.get("/readyz", response_class=PlainTextResponse)
def readyz(request: Request):
    data = aggregate(request.app)
    # opțional: 503 pe fail
    return PlainTextResponse(str(data.get("status", "fail")))
