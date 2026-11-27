"""HTTP layer. Every route is under /api/v1. Auth = HttpOnly SameSite=Strict cookie holding a JWT.

Order of defence for a request (outermost first):
  UploadGuard (size + concurrency) -> security headers / Origin check / decoy gate / audit -> RBAC dependency -> handler
"""
import asyncio
import csv
import io
import secrets
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import jwt
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Path, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from starlette.concurrency import run_in_threadpool
from starlette.formparsers import MultiPartParser

from . import auth, database, decoy, ledger
from .config import settings
from .crypto import BUCKET, decrypt_blob, decrypt_field, encrypt_blob, encrypt_field, file_hmac
from .ledger import append_block, publish_anchor
from .models import AuditLog, Evidence, LandDeed, PendingSignup, ReliefFund, ROLES, User, now_str
from .scrub import Unsupported, scrub, sniff

MultiPartParser.spool_max_size = settings.MAX_UPLOAD_BYTES + 1024 * 1024  # uploads stay in RAM; nothing is spooled to /tmp
COOKIE = "aegis"
EXT = {"image/jpeg": "jpg", "image/png": "png", "application/pdf": "pdf", "video/mp4": "mp4"}
CATEGORIES = ("food", "medical", "shelter", "cash", "other")
Page = dict(limit=Query(50, ge=1, le=100), offset=Query(0, ge=0, le=10**9))
Id = Annotated[int, Path(ge=1, le=2**63 - 1)]  # SQLite integers are 64-bit: larger values used to crash with a 500


# ------------------------------------------------------------------ auth helpers
def _user(request: Request, scope: str) -> User:
    tok = request.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(401, "not authenticated")
    try:
        c = auth.decode_token(tok)
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid or expired session")
    if c["scope"] != scope:
        raise HTTPException(401, "wrong session scope")
    with database.ReadSession() as db:
        u = db.get(User, int(c["sub"]))
    if u is None or not u.is_active:  # role and is_active come from the DB on every request, not from the token
        raise HTTPException(401, "account inactive")
    if c["tv"] != u.token_version:
        raise HTTPException(401, "session revoked")
    request.state.uid, request.state.role = u.id, u.role
    return u


def pre2fa(request: Request) -> User:
    return _user(request, "pre_2fa")


def require(*roles: str):
    def dep(request: Request) -> User:
        u = _user(request, "full_access")
        if u.role not in roles:
            raise HTTPException(403, "role not allowed")
        return u
    return dep


def _set_cookie(resp: Response, token: str, minutes: int) -> None:
    resp.set_cookie(COOKIE, token, max_age=minutes * 60, httponly=True, samesite="strict", secure=settings.COOKIE_SECURE, path="/")


def _page(q, limit, offset):
    return q.order_by(q.column_descriptions[0]["entity"].id.desc()).limit(limit).offset(offset)


def _pii(token, col):
    return decrypt_field(token, "PII", col) if token else None


# ------------------------------------------------------------------ schemas
class Code(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class Allocate(BaseModel):
    amount_cents: int = Field(gt=0, le=10_000_000_00)
    currency: str = Field("USD", pattern="^(USD|EUR|GBP)$")
    category: str = Field(pattern="^(" + "|".join(CATEGORIES) + ")$")
    recipient_name: str = Field(min_length=1, max_length=200)
    recipient_details: str | None = Field(None, max_length=1000)
    destination: str = Field(min_length=1, max_length=300)


class Status(BaseModel):
    status: str = Field(pattern="^(in_transit|delivered)$")


class Land(BaseModel):
    owner_name: str = Field(min_length=1, max_length=200)
    location: str = Field(min_length=1, max_length=300)
    area_size: str = Field(min_length=1, max_length=100)


class Verdict(BaseModel):
    status: str = Field(pattern="^(verified|disputed|rejected)$")


class RoleIn(BaseModel):
    role: str = Field(pattern="^(" + "|".join(ROLES) + ")$")


class ActiveIn(BaseModel):
    is_active: bool


# ------------------------------------------------------------------ routes: auth
r_auth = APIRouter(prefix="/auth")


@r_auth.post("/2fa/setup")
def setup_2fa(u: User = Depends(pre2fa)):
    try:
        secret, uri = auth.begin_2fa_setup(u.id)
    except ValueError:
        raise HTTPException(409, "2FA already enabled; ask an admin to reset it")
    return {"secret": secret, "otpauth_uri": uri}


@r_auth.post("/2fa/verify")
def verify_2fa(body: Code, u: User = Depends(pre2fa)):
    res = auth.verify_code(u.id, body.code)
    if res in ("ok", "decoy"):
        resp = JSONResponse({"status": "ok"})  # identical for real and duress logins
        _set_cookie(resp, auth.issue_token(u.id, "full_access", decoy=res == "decoy"), settings.SESSION_MINUTES)
        return resp
    code, msg = {"locked": (423, "too many attempts; try again later"), "not_setup": (409, "set up 2FA first"), "inactive": (401, "account inactive")}.get(res, (401, "invalid code"))
    raise HTTPException(code, msg)


@r_auth.put("/duress")
def set_duress(body: Code, u: User = Depends(require(*ROLES))):
    try:
        auth.set_duress_code(u.id, body.code)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"status": "ok"}


@r_auth.post("/logout")
def logout(request: Request):
    tok = request.cookies.get(COOKIE)
    try:
        c = auth.decode_token(tok) if tok else None
    except jwt.PyJWTError:
        c = None
    if c and not c.get("decoy"):  # a decoy logout only clears the cookie: no write, nothing observable
        auth.revoke_sessions(int(c["sub"]), c["tv"])
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@r_auth.get("/me")
def me(u: User = Depends(require(*ROLES))):
    return {"id": u.id, "role": u.role}


# ------------------------------------------------------------------ routes: evidence
r_ev = APIRouter(prefix="/evidence")


def _ev_out(e: Evidence, detail: bool = True) -> dict:
    out = {"id": e.id, "uploader_id": e.uploader_id, "file_type": e.file_type, "file_hmac": e.file_hmac, "created_at": e.created_at}
    if detail:
        out |= {"description": _pii(e.encrypted_description, "evidence.encrypted_description"), "location": _pii(e.encrypted_location, "evidence.encrypted_location")}
    return out


@r_ev.post("/upload", status_code=201)
def upload(file: UploadFile = File(...), description: str = Form(..., min_length=1, max_length=2000), location: str | None = Form(None, max_length=200),
           u: User = Depends(require("whistleblower"))):
    data = file.file.read(settings.MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(400, "empty file")
    if len(data) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large")
    try:
        mime = sniff(data)  # the client's Content-Type and filename are ignored
        clean = scrub(data, mime)
    except Unsupported as e:
        raise HTTPException(415, str(e))
    except ValueError:
        raise HTTPException(422, "file is damaged or malformed")
    key = secrets.token_hex(16)
    blob = encrypt_blob(clean, f"evidence:{key}")
    ledger.store.put(f"blobs/{key}", blob, once=True)  # orphan blobs (DB failure below) are cleaned by a bucket lifecycle rule
    ev = Evidence(
        uploader_id=u.id, encrypted_description=encrypt_field(description, "PII", "evidence.encrypted_description"),
        encrypted_location=encrypt_field(location, "PII", "evidence.encrypted_location"),
        encrypted_blob_key=encrypt_field(key, "EVIDENCE", "evidence.encrypted_blob_key"),
        encrypted_filename=encrypt_field(file.filename or "", "PII", "evidence.encrypted_filename"),
        raw_hmac=file_hmac(data), file_hmac=file_hmac(clean), file_type=mime, padded_mb=len(blob) // BUCKET,
    )
    with database.WriteSession.begin() as db:
        blk = append_block(db, "EVIDENCE", "UPLOAD", ev, u.id, f"Evidence #{{id}} uploaded by #{u.id} type={mime}")
    publish_anchor(blk)
    return {"id": ev.id, "file_type": mime, "file_hmac": ev.file_hmac, "ledger_block": blk.id, "ledger_hash": blk.current_hash, "metadata_scrubbed": True}


def _visible(q, u: User):
    return q.where(Evidence.uploader_id == u.id) if u.role == "whistleblower" else q


@r_ev.get("/list")  # declared before /{eid}
def ev_list(u: User = Depends(require("whistleblower", "hr_auditor", "admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    with database.ReadSession() as db:
        rows = db.execute(_page(_visible(select(Evidence), u), limit, offset)).scalars().all()
    return {"items": [_ev_out(e) for e in rows], "limit": limit, "offset": offset}


def _get_ev(eid: Id, u: User) -> Evidence:
    with database.ReadSession() as db:
        e = db.execute(_visible(select(Evidence).where(Evidence.id == eid), u)).scalar_one_or_none()
    if e is None:
        raise HTTPException(404, "not found")  # 404 (not 403) so IDs cannot be probed
    return e


@r_ev.get("/{eid}")
def ev_get(eid: Id, u: User = Depends(require("whistleblower", "hr_auditor", "admin"))):
    return _ev_out(_get_ev(eid, u))


@r_ev.get("/{eid}/download")
def ev_download(eid: Id, u: User = Depends(require("whistleblower", "hr_auditor", "admin"))):
    e = _get_ev(eid, u)
    key = decrypt_field(e.encrypted_blob_key, "EVIDENCE", "evidence.encrypted_blob_key")
    try:
        data = decrypt_blob(ledger.store.get(f"blobs/{key}"), f"evidence:{key}")
    except Exception:
        raise HTTPException(500, "stored evidence failed its integrity check")
    return Response(data, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="evidence-{e.id}.{EXT[e.file_type]}"', "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "sandbox", "X-File-HMAC": e.file_hmac})


# ------------------------------------------------------------------ routes: relief
r_rl = APIRouter(prefix="/relief")


def _rl_out(r: ReliefFund) -> dict:
    return {"id": r.id, "worker_id": r.worker_id, "amount_cents": r.amount_cents, "currency": r.currency, "category": r.category,
            "recipient_name": _pii(r.encrypted_recipient_name, "relief_funds.encrypted_recipient_name"),
            "recipient_details": _pii(r.encrypted_recipient_details, "relief_funds.encrypted_recipient_details"),
            "destination": _pii(r.encrypted_destination, "relief_funds.encrypted_destination"),
            "status": r.status, "delivered_by": r.delivered_by, "created_at": r.created_at, "updated_at": r.updated_at}


@r_rl.post("/allocate", status_code=201)
def allocate(b: Allocate, u: User = Depends(require("relief_worker"))):
    r = ReliefFund(
        worker_id=u.id, amount_cents=b.amount_cents, currency=b.currency, category=b.category,
        encrypted_recipient_name=encrypt_field(b.recipient_name, "PII", "relief_funds.encrypted_recipient_name"),
        encrypted_recipient_details=encrypt_field(b.recipient_details, "PII", "relief_funds.encrypted_recipient_details"),
        encrypted_destination=encrypt_field(b.destination, "PII", "relief_funds.encrypted_destination"))
    with database.WriteSession.begin() as db:
        blk = append_block(db, "RELIEF", "ALLOCATE", r, u.id, f"Relief #{{id}} allocated by #{u.id} {b.amount_cents} {b.currency} {b.category}")
    publish_anchor(blk)
    return {"id": r.id, "status": "pending", "ledger_block": blk.id}


@r_rl.get("/ledger")
def rl_ledger(u: User = Depends(require("relief_worker", "hr_auditor", "admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    q = select(ReliefFund)
    if u.role == "relief_worker":  # own funds, plus funds in transit: those are the ones a second worker has to confirm
        q = q.where(or_(ReliefFund.worker_id == u.id, ReliefFund.status == "in_transit"))
    with database.ReadSession() as db:
        rows = db.execute(_page(q, limit, offset)).scalars().all()
    return {"items": [_rl_out(r) for r in rows], "limit": limit, "offset": offset}


@r_rl.put("/{rid}/status")
def rl_status(rid: Id, b: Status, u: User = Depends(require("relief_worker"))):
    """pending -> in_transit (the allocating worker) -> delivered (a DIFFERENT worker who can see it in transit: two-person rule). No other moves."""
    with database.WriteSession.begin() as db:  # BEGIN IMMEDIATE: the status check and the write cannot interleave with another request
        r = db.get(ReliefFund, rid)
        if r is None or (r.worker_id != u.id and r.status != "in_transit"):
            raise HTTPException(404, "not found")  # same answer as a non-existent id: other workers' pending funds cannot be probed
        if (r.status, b.status) == ("pending", "in_transit"):
            if r.worker_id != u.id:
                raise HTTPException(403, "only the allocating worker can dispatch")
        elif (r.status, b.status) == ("in_transit", "delivered"):
            if r.worker_id == u.id:
                raise HTTPException(403, "delivery must be confirmed by a different worker")
            r.delivered_by = u.id
        else:
            raise HTTPException(409, f"cannot move from {r.status} to {b.status}")
        r.status, r.updated_at = b.status, now_str()
        blk = append_block(db, "RELIEF", "STATUS", r, u.id, f"Relief #{{id}} -> {b.status} by #{u.id}")
    publish_anchor(blk)
    return {"id": rid, "status": b.status, "ledger_block": blk.id}


# ------------------------------------------------------------------ routes: land
r_ld = APIRouter(prefix="/land")


def _ld_out(d: LandDeed) -> dict:
    return {"id": d.id, "owner_id": d.owner_id, "owner_name": _pii(d.encrypted_owner_name, "land_deeds.encrypted_owner_name"),
            "location": _pii(d.encrypted_location, "land_deeds.encrypted_location"), "area_size": d.area_size, "status": d.status,
            "verified_by": d.verified_by, "verified_at": d.verified_at, "created_at": d.created_at}


@r_ld.post("/register", status_code=201)
def land_register(b: Land, u: User = Depends(require("whistleblower", "relief_worker"))):
    d = LandDeed(owner_id=u.id, encrypted_owner_name=encrypt_field(b.owner_name, "PII", "land_deeds.encrypted_owner_name"),
                 encrypted_location=encrypt_field(b.location, "PII", "land_deeds.encrypted_location"), area_size=b.area_size)
    with database.WriteSession.begin() as db:
        blk = append_block(db, "LAND", "REGISTER", d, u.id, f"Land #{{id}} registered by #{u.id}")
    publish_anchor(blk)
    return {"id": d.id, "status": "pending", "ledger_block": blk.id}


def _ld_visible(q, u: User):
    return q if u.role in ("hr_auditor", "admin") else q.where(LandDeed.owner_id == u.id)


@r_ld.get("/list")
def land_list(u: User = Depends(require("whistleblower", "relief_worker", "hr_auditor", "admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    with database.ReadSession() as db:
        rows = db.execute(_page(_ld_visible(select(LandDeed), u), limit, offset)).scalars().all()
    return {"items": [_ld_out(d) for d in rows], "limit": limit, "offset": offset}


@r_ld.put("/verify/{did}")
def land_verify(did: Id, b: Verdict, u: User = Depends(require("hr_auditor"))):
    """Final: only 'pending' deeds can be decided, and a decision is never changed afterwards."""
    with database.WriteSession.begin() as db:
        d = db.get(LandDeed, did)
        if d is None:
            raise HTTPException(404, "not found")
        if d.status != "pending":
            raise HTTPException(409, f"already {d.status}; decisions are final")
        d.status, d.verified_by, d.verified_at = b.status, u.id, now_str()
        blk = append_block(db, "LAND", "VERIFY", d, u.id, f"Land #{{id}} {b.status} by #{u.id}")
    publish_anchor(blk)
    return {"id": did, "status": b.status, "ledger_block": blk.id}


@r_ld.get("/{did}")
def land_get(did: Id, u: User = Depends(require("whistleblower", "relief_worker", "hr_auditor", "admin"))):
    with database.ReadSession() as db:
        d = db.execute(_ld_visible(select(LandDeed).where(LandDeed.id == did), u)).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "not found")
    return _ld_out(d)


# ------------------------------------------------------------------ routes: system
r_sys = APIRouter(prefix="/system")


@r_sys.get("/verify-chain")
def verify(u: User = Depends(require("hr_auditor", "admin"))):
    return ledger.verify_chain()


@r_sys.get("/users")
def users(u: User = Depends(require("admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    with database.ReadSession() as db:
        rows = db.execute(_page(select(User), limit, offset)).scalars().all()
    return {"items": [{"id": x.id, "email": _pii(x.encrypted_email, "users.email"), "name": _pii(x.encrypted_name, "users.name"), "role": x.role,
                       "is_active": x.is_active, "is_2fa_enabled": x.is_2fa_enabled, "created_at": x.created_at} for x in rows], "limit": limit, "offset": offset}


@r_sys.get("/signups")
def signups(u: User = Depends(require("admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    with database.ReadSession() as db:
        rows = db.execute(_page(select(PendingSignup), limit, offset)).scalars().all()
    return {"items": [{"id": p.id, "email": _pii(p.encrypted_email, "pending_signups.email"), "name": _pii(p.encrypted_name, "pending_signups.name"),
                       "created_at": p.created_at} for p in rows], "limit": limit, "offset": offset}


class Approve(BaseModel):
    role: str = Field("whistleblower", pattern="^(" + "|".join(ROLES) + ")$")


@r_sys.post("/signups/{pid}/approve", status_code=201)
def approve(pid: Id, b: Approve, u: User = Depends(require("admin"))):
    try:
        new = auth.approve_signup(u.id, pid, b.role)
    except LookupError:
        raise HTTPException(404, "no such sign-up")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"id": new.id, "role": new.role}


@r_sys.post("/signups/{pid}/reject")
def reject(pid: Id, u: User = Depends(require("admin"))):
    try:
        auth.reject_signup(pid)
    except LookupError:
        raise HTTPException(404, "no such sign-up")
    return {"status": "ok"}


def _admin(fn, actor: User, uid: Id, **kw):
    try:
        fn(actor.id, uid, **kw)
    except LookupError:
        raise HTTPException(404, "no such user")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"status": "ok"}


@r_sys.put("/users/{uid}/role")
def set_role(uid: Id, b: RoleIn, u: User = Depends(require("admin"))):
    return _admin(auth.admin_update, u, uid, role=b.role)


@r_sys.put("/users/{uid}/status")
def set_status(uid: Id, b: ActiveIn, u: User = Depends(require("admin"))):
    return _admin(auth.admin_update, u, uid, active=b.is_active)


@r_sys.post("/users/{uid}/reset-2fa")
def reset_2fa(uid: Id, u: User = Depends(require("admin"))):
    return _admin(auth.admin_update, u, uid, reset_2fa=True)


def _logs(limit, offset):
    with database.ReadSession() as db:
        return db.execute(_page(select(AuditLog), limit, offset)).scalars().all()


@r_sys.get("/audit-logs")
def audit_logs(u: User = Depends(require("admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    return {"items": [{c: getattr(a, c) for c in ("id", "user_id", "role", "action", "endpoint", "status_code", "details", "timestamp")} for a in _logs(limit, offset)]}


def _csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # stops spreadsheet formula injection


@r_sys.get("/audit-logs/csv")
def audit_csv(u: User = Depends(require("admin")), limit: int = Page["limit"], offset: int = Page["offset"]):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "user_id", "role", "action", "endpoint", "status_code", "details", "timestamp"])
    for a in _logs(limit, offset):
        w.writerow([_csv_safe(x) for x in (a.id, a.user_id, a.role, a.action, a.endpoint, a.status_code, a.details, a.timestamp)])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="audit.csv"'})


# ------------------------------------------------------------------ app + middleware
class _Abort(Exception):
    pass


def _session_cookie(scope) -> str | None:
    for k, v in scope["headers"]:
        if k == b"cookie":
            c = SimpleCookie(v.decode("latin-1"))
            return c[COOKIE].value if COOKIE in c else None
    return None


class UploadGuard:
    """Pure ASGI, in front of the upload route only:
    1. no valid session token -> 401 before a slot is taken or a byte is read (strangers cannot occupy slots),
    2. Content-Length over the cap -> 413; chunked bodies are counted -> 413,
    3. a client that stalls (no data for UPLOAD_IDLE_SECONDS) -> 408, freeing its slot,
    4. at most MAX_CONCURRENT_UPLOADS at once, otherwise 503."""

    def __init__(self, app):
        self.app, self.sem, self.limit = app, asyncio.Semaphore(settings.MAX_CONCURRENT_UPLOADS), settings.MAX_UPLOAD_BYTES + 64 * 1024

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or not scope["path"].endswith("/evidence/upload"):
            return await self.app(scope, receive, send)
        tok = _session_cookie(scope)
        try:
            ok = bool(tok) and auth.decode_token(tok)["scope"] == "full_access"
        except jwt.PyJWTError:
            ok = False
        if not ok:
            return await JSONResponse({"detail": "not authenticated"}, 401)(scope, receive, send)
        cl = dict(scope["headers"]).get(b"content-length")
        if cl and cl.isdigit() and int(cl) > self.limit:
            return await JSONResponse({"detail": "file too large"}, 413)(scope, receive, send)
        if self.sem.locked():
            return await JSONResponse({"detail": "server busy, retry shortly"}, 503)(scope, receive, send)
        got, abort = 0, None

        async def counted():
            nonlocal got, abort
            try:
                m = await asyncio.wait_for(receive(), settings.UPLOAD_IDLE_SECONDS)
            except asyncio.TimeoutError:
                abort = (408, "upload stalled")
                raise _Abort
            got += len(m.get("body", b"")) if m["type"] == "http.request" else 0
            if got > self.limit:
                abort = (413, "file too large")
                raise _Abort
            return m

        async def guarded_send(m):  # the framework turns the aborted read into a 400/500; replace whatever it sends
            if abort is None:
                await send(m)

        async with self.sem:
            try:
                await self.app(scope, counted, guarded_send)
            except _Abort:
                pass
            if abort:
                await JSONResponse({"detail": abort[1]}, abort[0])(scope, receive, send)


def _origin_ok(origin: str | None, host: str | None) -> bool:
    """Behind a TLS-terminating proxy Host is often rewritten, so production sets ALLOWED_ORIGINS explicitly.
    X-Forwarded-Host is deliberately NOT trusted: it is attacker-controlled when the app is reachable directly."""
    if not origin:
        return False
    if settings.ALLOWED_ORIGINS:
        return origin.lower().rstrip("/") in settings.ALLOWED_ORIGINS
    return urlparse(origin).netloc == host


def mount_ui(app: FastAPI) -> None:
    """Serve the static front end. Must be called LAST: a mount at "/" swallows every route registered after it."""
    import pathlib

    from starlette.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=pathlib.Path(__file__).resolve().parents[1] / "frontend", html=True), name="ui")


def create_app() -> FastAPI:
    app = FastAPI(title="Aegis", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def gate(request: Request, call_next):
        path, is_decoy, resp, real = request.url.path, False, None, False
        api_path = path.startswith("/api/v1/")
        if api_path and request.method not in ("GET", "HEAD", "OPTIONS") and not _origin_ok(request.headers.get("origin"), request.headers.get("host")):
            resp = JSONResponse({"detail": "bad origin"}, 403)  # CSRF: browsers always send Origin on fetch/XHR writes
        tok = request.cookies.get(COOKIE)
        if resp is None and tok and api_path and not path.endswith("/auth/logout"):
            try:
                is_decoy = bool(auth.decode_token(tok).get("decoy"))
            except jwt.PyJWTError:
                pass
        if resp is not None:
            pass
        elif is_decoy:  # duress session: never reaches routing, DB writes, the store or the ledger; answered by decoy.respond (read-only user lookup)
            def who():
                with database.ReadSession() as db:
                    return db.get(User, int(auth.decode_token(tok)["sub"]))
            u = await run_in_threadpool(who)
            if u is None or not u.is_active:
                resp = JSONResponse({"detail": "account inactive"}, 401)
            elif auth.decode_token(tok)["tv"] != u.token_version:
                resp = JSONResponse({"detail": "session revoked"}, 401)
            else:
                resp = await decoy.respond(request, u, path)
        else:
            resp, real = await call_next(request), True
        if api_path:
            resp.headers["Cache-Control"] = "no-store"
            uid = getattr(request.state, "uid", None)
            if real and uid:
                def log():
                    with database.WriteSession.begin() as db:
                        db.add(AuditLog(user_id=uid, role=request.state.role, action=request.method, endpoint=path[:120], status_code=resp.status_code))
                await run_in_threadpool(log)
        resp.headers.update({  # the same headers on real, decoy and rejected responses, so headers cannot reveal a decoy session
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
        return resp

    for r in (r_auth, r_ev, r_rl, r_ld, r_sys):
        app.include_router(r, prefix="/api/v1")
    app.add_middleware(UploadGuard)  # added last = outermost user middleware, so its 413 happens before form parsing
    return app
