# app/main.py
from __future__ import annotations

import os
import json
import logging
from typing import Any
from uuid import uuid4

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from markupsafe import Markup, escape

# importă direct routerele, inclusiv health, fără aliasuri
from .routers import dashboard, seeds, variants, health, metrics as metrics_router


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        req_id = request.headers.get("x-request-id") or str(uuid4())
        request.state.request_id = req_id
        try:
            response = await call_next(request)
        except Exception:
            logging.getLogger("brandmon").exception(
                "unhandled error",
                extra={"request_id": req_id, "path": str(request.url.path)},
            )
            raise
        response.headers["x-request-id"] = req_id
        return response


def register_jinja_filters(templates: Jinja2Templates) -> None:
    def join_ellipsis(items, limit: int = 8, sep: str = ", "):
        if not items:
            return ""
        try:
            seq = list(items)
        except Exception:
            return ""
        head = sep.join(str(x) for x in seq[:limit])
        return head if len(seq) <= limit else f"{head}{sep}…"

    def to_mapping(value: Any):
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, (dict, list)) else {}
            except Exception:
                return {}
        return {}

    def json_pretty(value: Any) -> Markup:
        try:
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except Exception:
                    pass
            s = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
        except Exception:
            s = str(value)
        return Markup(f"<pre>{escape(s)}</pre>")

    env = templates.env
    env.filters["join_ellipsis"] = join_ellipsis
    env.filters["to_mapping"] = to_mapping
    env.filters["json_pretty"] = json_pretty


def create_app() -> FastAPI:
    app = FastAPI(title="BrandMon")
    app.add_middleware(RequestIDMiddleware)

    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    app.state.templates = Jinja2Templates(directory=templates_dir)
    register_jinja_filters(app.state.templates)

    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # include routerele
    app.include_router(dashboard.router)
    app.include_router(seeds.router)
    app.include_router(variants.router)
    app.include_router(health.router)
    app.include_router(metrics_router.router)

    # opțional: /health (fără slash) redirecționează la /health/
    @app.get("/health")
    def _health_redirect():
        return RedirectResponse(url="/health/", status_code=307)

    # root minimal
    @app.get("/")
    def _root():
        return {"app": "BrandMon", "status": "ok"}

    return app


app = create_app()
