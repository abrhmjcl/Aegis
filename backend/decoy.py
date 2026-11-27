"""Duress-session responses. A decoy session never reaches the real routes, DB writes, object store or ledger.

It mimics the real API closely enough that comparing responses does not reveal it: same role rules (403), same response shapes, same 404 for
unknown ids, same 422 for bad pagination/JSON, and a small per-user in-memory state so that "upload, then list" looks consistent.
State is process-local, capped, and gone on restart. It cannot be perfect: see the guide's limits (§5.6)."""
import hashlib
import json
import re
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from .models import now_str
from starlette.concurrency import run_in_threadpool

from .scrub import Unsupported, scrub, sniff

CAP = 100  # items per kind per user (memory bound)
STATE = defaultdict(lambda: {"evidence": [], "relief": [], "land": []})
ALL = ("whistleblower", "relief_worker", "hr_auditor", "admin")
EV, RL, LD = ("whistleblower", "hr_auditor", "admin"), ("relief_worker", "hr_auditor", "admin"), ("whistleblower", "relief_worker", "hr_auditor", "admin")
# (method, path regex, allowed roles, handler name)
ROUTES = [
    ("GET", r"/auth/me", ALL, "me"),
    ("PUT", r"/auth/duress", ALL, "ok"),
    ("POST", r"/evidence/upload", ("whistleblower",), "ev_upload"),
    ("GET", r"/evidence/list", EV, "list:evidence"),
    ("GET", r"/evidence/(-?\d+)", EV, "get:evidence"),
    ("GET", r"/evidence/(-?\d+)/download", EV, "not_found"),
    ("POST", r"/relief/allocate", ("relief_worker",), "rl_allocate"),
    ("GET", r"/relief/ledger", RL, "list:relief"),
    ("PUT", r"/relief/(-?\d+)/status", ("relief_worker",), "rl_status"),
    ("POST", r"/land/register", ("whistleblower", "relief_worker"), "ld_register"),
    ("GET", r"/land/list", LD, "list:land"),
    ("PUT", r"/land/verify/(-?\d+)", ("hr_auditor",), "not_found"),
    ("GET", r"/land/(-?\d+)", LD, "get:land"),
    ("GET", r"/system/verify-chain", ("hr_auditor", "admin"), "verify"),
    ("GET", r"/system/users", ("admin",), "users"),
    ("GET", r"/system/signups", ("admin",), "list:empty"),
    ("GET", r"/system/audit-logs", ("admin",), "audit"),
    ("GET", r"/system/audit-logs/csv", ("admin",), "csv"),
    ("PUT", r"/system/users/(-?\d+)/(role|status)", ("admin",), "adm_user"),
    ("POST", r"/system/users/(-?\d+)/reset-2fa", ("admin",), "adm_user"),
    ("POST", r"/system/signups/(-?\d+)/(approve|reject)", ("admin",), "not_found"),
]
ROUTES = [(m, re.compile(p), r, h) for m, p, r, h in ROUTES]
NOT_FOUND = lambda: JSONResponse({"detail": "not found"}, 404)


def _422(loc, msg):
    return JSONResponse({"detail": [{"type": "value_error", "loc": loc, "msg": msg}]}, 422)


def _page(request):
    out = []
    for name, default, lo, hi in (("limit", 50, 1, 100), ("offset", 0, 0, 10**9)):
        raw = request.query_params.get(name, str(default))
        if not raw.lstrip("-").isdigit() or not lo <= int(raw) <= hi:
            return None, _422(["query", name], f"{name} out of range")
        out.append(int(raw))
    return out, None


def _hex(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


async def _body(request, model):
    try:
        return model.model_validate(await request.json()), None
    except (ValueError, ValidationError) as e:
        if isinstance(e, ValidationError):
            errs = json.loads(e.json(include_url=False))
            return None, JSONResponse({"detail": [{**x, "loc": ["body", *x["loc"]]} for x in errs]}, 422)
        return None, _422(["body"], "JSON decode error")


def _push(items, item):
    if len(items) < CAP:
        items.append(item)


async def respond(request: Request, user, path: str):
    """`user` = the real, active user row of the token (read only). Returns a Response."""
    from . import api  # lazy: api imports this module

    sub = path.removeprefix("/api/v1")
    allowed = sorted({mt for mt, rx, _, _ in ROUTES if rx.fullmatch(sub)})
    for method, rx, roles, handler in ROUTES:
        m = rx.fullmatch(sub)
        if m and method == request.method:
            break
    else:  # same routing-level answers as the real app, before any role check
        if allowed:
            return JSONResponse({"detail": "Method Not Allowed"}, 405, headers={"allow": ", ".join(allowed)})
        return JSONResponse({"detail": "Not Found"}, 404)
    if user.role not in roles:
        return JSONResponse({"detail": "role not allowed"}, 403)
    if m.groups() and re.fullmatch(r"-?\d+", m.group(1)) and not 1 <= int(m.group(1)) <= 2**63 - 1:
        return _422(["path", "id"], "id out of range")  # the real routes bound ids the same way
    st = STATE[user.id]
    now = now_str()

    if handler == "me":
        return JSONResponse({"id": user.id, "role": user.role})
    if handler == "ok":
        return JSONResponse({"status": "ok"})
    if handler == "not_found":
        return NOT_FOUND()
    if handler.startswith("list:"):
        kind = handler[5:]
        page, err = _page(request)
        if err:
            return err
        items = [] if kind == "empty" else st[kind][::-1][page[1]: page[1] + page[0]]
        return JSONResponse({"items": items, "limit": page[0], "offset": page[1]})
    if handler.startswith("get:"):
        item = next((i for i in st[handler[4:]] if i["id"] == int(m.group(1))), None)
        return JSONResponse(item) if item else NOT_FOUND()
    if handler == "verify":
        return JSONResponse({"is_valid": True, "blocks": 1, "tip_block": 1, "tip_hash": _hex("genesis"), "anchors_checked": 1})
    if handler == "users":
        return JSONResponse({"items": [{"id": user.id, "role": user.role, "is_active": True, "is_2fa_enabled": True}], "limit": 50, "offset": 0})
    if handler == "audit":
        return JSONResponse({"items": []})
    if handler == "csv":
        return Response("id,user_id,role,action,endpoint,status_code,details,timestamp\n", media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="audit.csv"'})
    if handler == "adm_user":
        return JSONResponse({"detail": "an admin cannot modify their own account"}, 409) if int(m.group(1)) == user.id else JSONResponse({"detail": "no such user"}, 404)

    if handler == "ev_upload":
        try:
            form = await request.form()
        except Exception:  # malformed multipart: the real app answers 400, never 500
            return JSONResponse({"detail": "There was an error parsing the body"}, 400)
        f, desc, loc = form.get("file"), form.get("description"), form.get("location")
        if not hasattr(f, "read") or not desc or len(str(desc)) > 2000 or (loc is not None and len(str(loc)) > 200):
            return _422(["body"], "file and description (1-2000 chars) are required")
        data = await f.read()
        if not data:
            return JSONResponse({"detail": "empty file"}, 400)
        try:
            mime = sniff(data)
            await run_in_threadpool(scrub, data, mime)  # the real validators, result discarded: same 415/422 as the real upload
        except Unsupported as e:
            return JSONResponse({"detail": str(e)}, 415)
        except ValueError:
            return JSONResponse({"detail": "file is damaged or malformed"}, 422)
        item = {"id": len(st["evidence"]) + 1, "uploader_id": user.id, "file_type": mime, "file_hmac": _hex(user.id, len(st["evidence"]), now),
                "created_at": now, "description": str(desc), "location": loc}
        _push(st["evidence"], item)
        return JSONResponse({"id": item["id"], "file_type": mime, "file_hmac": item["file_hmac"], "ledger_block": 1000 + item["id"],
                             "ledger_hash": _hex("block", item["file_hmac"]), "metadata_scrubbed": True}, 201)
    if handler == "rl_allocate":
        b, err = await _body(request, api.Allocate)
        if err:
            return err
        item = {"id": len(st["relief"]) + 1, "worker_id": user.id, "amount_cents": b.amount_cents, "currency": b.currency, "category": b.category,
                "recipient_name": b.recipient_name, "recipient_details": b.recipient_details, "destination": b.destination,
                "status": "pending", "delivered_by": None, "created_at": now, "updated_at": now}
        _push(st["relief"], item)
        return JSONResponse({"id": item["id"], "status": "pending", "ledger_block": 1000 + item["id"]}, 201)
    if handler == "rl_status":
        b, err = await _body(request, api.Status)
        if err:
            return err
        item = next((i for i in st["relief"] if i["id"] == int(m.group(1))), None)
        if item is None:
            return NOT_FOUND()
        if (item["status"], b.status) == ("pending", "in_transit"):
            item["status"], item["updated_at"] = b.status, now
            return JSONResponse({"id": item["id"], "status": b.status, "ledger_block": 2000 + item["id"]})
        if (item["status"], b.status) == ("in_transit", "delivered"):
            return JSONResponse({"detail": "delivery must be confirmed by a different worker"}, 403)
        return JSONResponse({"detail": f"cannot move from {item['status']} to {b.status}"}, 409)
    if handler == "ld_register":
        b, err = await _body(request, api.Land)
        if err:
            return err
        item = {"id": len(st["land"]) + 1, "owner_id": user.id, "owner_name": b.owner_name, "location": b.location, "area_size": b.area_size,
                "status": "pending", "verified_by": None, "verified_at": None, "created_at": now}
        _push(st["land"], item)
        return JSONResponse({"id": item["id"], "status": "pending", "ledger_block": 1000 + item["id"]}, 201)
    return NOT_FOUND()
