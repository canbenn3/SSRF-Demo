from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Mock Website")
templates = Jinja2Templates(directory="templates")

FLAG_TOKEN = os.getenv("MOCK_FLAG_TOKEN", "").strip()
FLAG = os.getenv("MOCK_FLAG", "").strip()


async def _token_from_request(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    scheme, _, cred = auth.partition(" ")
    if scheme.lower() == "bearer" and cred.strip():
        return cred.strip()
    header = (request.headers.get("x-flag-token") or "").strip()
    if header:
        return header
    query = (request.query_params.get("token") or "").strip()
    if query:
        return query
    if request.method in ("POST", "PUT", "PATCH"):
        ctype = (request.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            try:
                data = await request.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and data.get("token"):
                return str(data["token"]).strip()
    return ""


def _token_matches(submitted: str) -> bool:
    if not FLAG_TOKEN or not submitted:
        return False
    left = hashlib.sha256(submitted.encode("utf-8")).digest()
    right = hashlib.sha256(FLAG_TOKEN.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.api_route("/flag", methods=["GET", "POST"])
async def flag(request: Request):
    if not FLAG_TOKEN or not FLAG:
        return JSONResponse(
            {"error": "flag endpoint is not configured"},
            status_code=503,
        )
    if not _token_matches(await _token_from_request(request)):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"message": "You successfully launched your attack!", "flag": FLAG}


@app.get("/health")
async def health():
    return {"status": "ok"}
