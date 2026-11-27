import pytest
import asyncio
from fastapi.testclient import TestClient
from backend import api, auth, database, decoy, ledger
from backend.models import Evidence, MasterLedger, ReliefFund, User
from sqlalchemy import func, select

H = {"origin": "http://testserver"}
JPG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\0" * 9 + b"\xff\xe1\x00\x0aExif\0\0ab\xff\xda\x00\x04\x00\x00\x12\xff\xd9SECRET"


def mk(sub, role, email="ok@example.org"):
    u = auth.login_upsert(sub, email, True, None, "N")
    auth.admin_update(None, u.id, role=role)
    return u


def login(client, u, decoy=False, scope="full_access"):
    client.cookies.set("aegis", auth.issue_token(u.id, scope, decoy))
    return client


@pytest.fixture
def app(env):
    return api.create_app()


@pytest.fixture
def c(app):
    return TestClient(app)


def as_(app, u, **kw):
    return login(TestClient(app), u, **kw)


def up(cl, data=JPG, name="a.jpg"):
    return cl.post("/api/v1/evidence/upload", headers=H, files={"file": (name, data, "image/jpeg")}, data={"description": "desc", "location": "loc"})


def test_unauth_and_docs(c):
    assert c.get("/api/v1/auth/me").status_code == 401
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_pre2fa_token_rejected_on_data_routes(app, env):
    u = mk("a", "whistleblower")
    assert as_(app, u, scope="pre_2fa").get("/api/v1/auth/me").status_code == 401


def test_rbac_matrix(app, env):
    w, rw, hr, ad = mk("w", "whistleblower"), mk("r", "relief_worker"), mk("h", "hr_auditor"), mk("a", "admin")
    assert as_(app, rw).get("/api/v1/evidence/list").status_code == 403
    assert as_(app, w).get("/api/v1/system/users").status_code == 403
    assert as_(app, hr).get("/api/v1/system/users").status_code == 403
    assert as_(app, ad).get("/api/v1/system/users").status_code == 200
    assert as_(app, w).post("/api/v1/relief/allocate", headers=H, json={}).status_code == 403


def test_role_is_read_live(app, env):
    ad, u = mk("a", "admin"), mk("u", "whistleblower")
    cl = as_(app, u)
    assert cl.get("/api/v1/evidence/list").status_code == 200
    auth.admin_update(ad.id, u.id, active=False)
    assert cl.get("/api/v1/evidence/list").status_code == 401


def test_upload_roundtrip_and_scrub(app, env):
    w, hr, other = mk("w", "whistleblower"), mk("h", "hr_auditor"), mk("o", "whistleblower")
    cw = as_(app, w)
    r = up(cw)
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    d = cw.get(f"/api/v1/evidence/{eid}/download")
    assert d.status_code == 200 and b"Exif" not in d.content and b"SECRET" not in d.content and b"JFIF" in d.content
    assert d.headers["content-disposition"].startswith("attachment") and d.headers["x-content-type-options"] == "nosniff"
    assert as_(app, hr).get(f"/api/v1/evidence/{eid}").json()["description"] == "desc"
    assert as_(app, other).get(f"/api/v1/evidence/{eid}").status_code == 404
    assert as_(app, other).get("/api/v1/evidence/list").json()["items"] == []
    assert ledger.verify_chain()["is_valid"]
    # stored blob is ciphertext padded to 1 MB, and nothing readable is in the DB
    blobs = ledger.store.keys("blobs/")
    assert len(blobs) == 1 and len(ledger.store.get(blobs[0])) > 1024 * 1024 and b"JFIF" not in ledger.store.get(blobs[0])


def test_upload_rejections(app, env):
    cl = as_(app, mk("w", "whistleblower"))
    assert up(cl, b"MZ not allowed").status_code == 415
    assert up(cl, b"\xff\xd8\xff\xe0 truncated").status_code == 422
    assert up(cl, b"\xff\xd8\xff" + b"0" * (3 * 1024 * 1024)).status_code == 413  # Content-Length path
    r = cl.post("/api/v1/evidence/upload", headers={**H, "content-type": "multipart/form-data; boundary=x"},
                content=iter([b'--x\r\nContent-Disposition: form-data; name="file"; filename="a.jpg"\r\n\r\n'] + [b"a" * 1024 * 1024] * 4))  # chunked path, no Content-Length
    assert r.status_code == 413


def test_tampered_blob_fails_closed(app, env):
    cl = as_(app, mk("w", "whistleblower"))
    eid = up(cl).json()["id"]
    k = ledger.store.keys("blobs/")[0]
    b = bytearray(ledger.store.get(k)); b[100] ^= 1; ledger.store.put(k, bytes(b))
    assert cl.get(f"/api/v1/evidence/{eid}/download").status_code == 500


def test_relief_rules(app, env):
    a, b = mk("a", "relief_worker"), mk("b", "relief_worker")
    ca, cb = as_(app, a), as_(app, b)
    body = {"amount_cents": 5000, "category": "food", "recipient_name": "R", "destination": "D"}
    for bad in ({**body, "amount_cents": 0}, {**body, "amount_cents": -5}, {**body, "amount_cents": 1.5}, {**body, "currency": "XXX"}, {**body, "category": "x"}):
        assert ca.post("/api/v1/relief/allocate", headers=H, json=bad).status_code == 422
    rid = ca.post("/api/v1/relief/allocate", headers=H, json=body).json()["id"]
    put = lambda cl, s: cl.put(f"/api/v1/relief/{rid}/status", headers=H, json={"status": s}).status_code
    assert put(ca, "delivered") == 409           # cannot skip a step
    assert put(cb, "in_transit") == 404          # B cannot even see A's pending fund (same answer as a non-existent id)
    assert cb.put("/api/v1/relief/999/status", headers=H, json={"status": "in_transit"}).status_code == 404
    assert put(ca, "in_transit") == 200
    assert put(ca, "delivered") == 403           # two-person rule
    assert [i["id"] for i in cb.get("/api/v1/relief/ledger").json()["items"]] == [rid]  # in transit: visible to B, who must confirm it
    assert put(cb, "delivered") == 200
    assert put(ca, "in_transit") == 409          # no going back
    assert put(cb, "in_transit") == 404          # a delivered fund of someone else is no longer visible to B
    assert ca.get("/api/v1/relief/ledger").json()["items"][0]["recipient_name"] == "R"
    assert cb.get("/api/v1/relief/ledger").json()["items"] == []
    assert ledger.verify_chain()["is_valid"]


def test_land_finality(app, env):
    w, hr = mk("w", "whistleblower"), mk("h", "hr_auditor")
    cw, ch = as_(app, w), as_(app, hr)
    did = cw.post("/api/v1/land/register", headers=H, json={"owner_name": "O", "location": "L", "area_size": "2ha"}).json()["id"]
    assert cw.put(f"/api/v1/land/verify/{did}", headers=H, json={"status": "verified"}).status_code == 403
    assert ch.put(f"/api/v1/land/verify/{did}", headers=H, json={"status": "pending"}).status_code == 422
    assert ch.put(f"/api/v1/land/verify/{did}", headers=H, json={"status": "verified"}).status_code == 200
    assert ch.put(f"/api/v1/land/verify/{did}", headers=H, json={"status": "rejected"}).status_code == 409
    assert ch.get(f"/api/v1/land/{did}").json()["owner_name"] == "O"
    assert ledger.verify_chain()["is_valid"]


def _count(model):
    with database.ReadSession() as db:
        return db.execute(select(func.count(model.id))).scalar()


def test_decoy_isolated(app, env):
    w = mk("w", "whistleblower")
    cd = as_(app, w, decoy=True)
    from backend.models import AuditLog
    before = (_count(MasterLedger), _count(Evidence), _count(AuditLog))
    r = up(cd)
    assert r.status_code == 201
    assert [i["description"] for i in cd.get("/api/v1/evidence/list").json()["items"]] == ["desc"]  # consistent inside the decoy...
    assert (_count(MasterLedger), _count(Evidence), _count(AuditLog)) == before                      # ...and nothing real was touched
    assert not ledger.store.keys("blobs/") and len(ledger.store.keys("anchors/")) == before[0]


HDRS = ("allow", "cache-control", "x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy", "strict-transport-security")


def _shape(r):
    try:
        j = r.json()
    except ValueError:  # HEAD / empty bodies
        j = None
    return r.status_code, sorted(j) if isinstance(j, dict) else type(j).__name__


MULTI = lambda data, name="a.jpg": {"files": {"file": (name, data, "image/jpeg")}, "data": {"description": "d"}}
PARITY = {  # (method, path, kwargs) answered identically (status + top-level JSON keys) by the real API and by the decoy
    "whistleblower": [
        ("GET", "/auth/me", {}), ("GET", "/evidence/list", {}), ("GET", "/evidence/list?limit=0", {}), ("GET", "/evidence/list?offset=-1", {}),
        ("GET", "/evidence/42", {}), ("GET", "/evidence/42/download", {}), ("GET", "/relief/ledger", {}), ("GET", "/system/users", {}),
        ("GET", "/system/verify-chain", {}), ("POST", "/relief/allocate", {"json": {}}), ("GET", "/nope", {}), ("GET", "/land/list", {}),
        ("GET", "/land/7", {}), ("POST", "/land/register", {"json": {"owner_name": "O"}}),
        ("POST", "/land/register", {"json": {"owner_name": "O", "location": "L", "area_size": "1ha"}}),
        ("POST", "/evidence/upload", MULTI(JPG)), ("POST", "/evidence/upload", MULTI(b"MZ nope")), ("POST", "/evidence/upload", {"data": {"description": "d"}}),
        ("PUT", "/land/verify/1", {"json": {"status": "verified"}}),
        # found by the independent review: each of these used to tell a decoy session from a real one
        ("POST", "/evidence/upload", MULTI(b"\xff\xd8\xff\xe1\x00\x02garbage")),
        ("POST", "/evidence/upload", {"data": {"description": "d", "file": "just text"}}),
        ("POST", "/evidence/upload", {"content": b"--x\r\n garbage", "headers": {"content-type": "multipart/form-data; boundary=x"}}),
        ("POST", "/evidence/upload", {"files": {"file": ("a.jpg", JPG, "image/jpeg")}, "data": {"description": "d", "location": "L" * 201}}),
        ("GET", "/evidence/99999999999999999999", {}), ("GET", "/evidence/list?offset=99999999999999999999", {}),
        ("GET", "/evidence/0", {}), ("GET", "/evidence/-1", {}), ("HEAD", "/auth/me", {}), ("DELETE", "/evidence/list", {}),
        ("PUT", "/land/99999999999999999999", {"json": {}}),
    ],
    "relief_worker": [
        ("POST", "/relief/allocate", {"json": {"amount_cents": 5, "category": "food", "recipient_name": "R", "destination": "D"}}),
        ("POST", "/relief/allocate", {"json": {"amount_cents": 0, "category": "food", "recipient_name": "R", "destination": "D"}}),
        ("PUT", "/relief/1/status", {"json": {"status": "in_transit"}}), ("PUT", "/relief/1/status", {"json": {"status": "delivered"}}),
        ("PUT", "/relief/99/status", {"json": {"status": "in_transit"}}), ("GET", "/relief/ledger", {}), ("GET", "/evidence/list", {}),
    ],
    "admin": [
        ("GET", "/system/verify-chain", {}), ("GET", "/system/users", {}), ("GET", "/system/signups", {}), ("GET", "/system/audit-logs", {}),
        ("GET", "/system/audit-logs/csv", {}), ("PUT", "/system/users/999/role", {"json": {"role": "admin"}}),
        ("POST", "/system/users/999/reset-2fa", {}), ("POST", "/system/signups/9/reject", {}), ("GET", "/evidence/list", {}),
    ],
}


@pytest.mark.parametrize("role", PARITY)
def test_v02_decoy_matches_real_api(app, env, role):
    mk("admin0", "admin")  # keeps "last admin" rules out of the way
    u = mk("x", role)
    for method, path, kw in PARITY[role]:
        outs = []
        for decoy_mode in (False, True):
            cl = as_(app, u, decoy=decoy_mode)
            kw2 = dict(kw)
            r = cl.request(method, "/api/v1" + path, headers={**H, **kw2.pop("headers", {})}, **kw2)
            outs.append(_shape(r) + (tuple(r.headers.get(h) for h in HDRS),))  # status, keys, and the security headers must all match
        assert outs[0][0] == outs[1][0], (method, path, outs)
        assert outs[0][2] == outs[1][2], (method, path, outs)  # headers match on errors too
        if outs[0][0] < 300:
            assert outs[0] == outs[1], (method, path, outs)


def test_decoy_state_is_capped_and_per_user(app, env):
    a, b = mk("a", "relief_worker"), mk("b", "relief_worker")
    body = {"amount_cents": 5, "category": "food", "recipient_name": "R", "destination": "D"}
    ca, cb = as_(app, a, decoy=True), as_(app, b, decoy=True)
    for _ in range(decoy.CAP + 5):
        assert ca.post("/api/v1/relief/allocate", headers=H, json=body).status_code == 201
    assert len(decoy.STATE[a.id]["relief"]) == decoy.CAP and cb.get("/api/v1/relief/ledger").json()["items"] == []
    assert _count(ReliefFund) == 0


def test_duress_login_flow(app, env):
    import pyotp
    w = mk("w", "whistleblower")
    pre = as_(app, w, scope="pre_2fa")
    secret = pre.post("/api/v1/auth/2fa/setup", headers=H).json()["secret"]
    assert pre.post("/api/v1/auth/2fa/verify", headers=H, json={"code": "000000"}).status_code == 401
    ok = pre.post("/api/v1/auth/2fa/verify", headers=H, json={"code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200 and "aegis=" in ok.headers["set-cookie"] and "HttpOnly" in ok.headers["set-cookie"] and "SameSite=strict" in ok.headers["set-cookie"]
    full = TestClient(app); full.cookies.set("aegis", auth.issue_token(w.id, "full_access"))
    assert full.put("/api/v1/auth/duress", headers=H, json={"code": "Panic2024"}).status_code == 200
    pre = as_(app, w, scope="pre_2fa")  # the first login replaced the cookie, so start a fresh pre-2FA session
    d = pre.post("/api/v1/auth/2fa/verify", headers=H, json={"code": "Panic2024"})
    assert d.status_code == 200  # looks identical to a real login
    dc = TestClient(app); dc.cookies.set("aegis", d.cookies["aegis"])
    assert dc.get("/api/v1/auth/me").json() == {"id": w.id, "role": "whistleblower"}  # served by the decoy, same shape as the real answer
    assert full.get("/api/v1/auth/me").json()["id"] == w.id


def test_admin_self_mod_and_guard(app, env):
    ad, u = mk("a", "admin"), mk("u", "whistleblower")
    ca = as_(app, ad)
    assert ca.put(f"/api/v1/system/users/{ad.id}/role", headers=H, json={"role": "whistleblower"}).status_code == 409
    assert ca.put(f"/api/v1/system/users/{u.id}/role", headers=H, json={"role": "root"}).status_code == 422
    assert ca.put(f"/api/v1/system/users/{u.id}/role", headers=H, json={"role": "hr_auditor"}).status_code == 200
    assert ca.post(f"/api/v1/system/users/999/reset-2fa", headers=H).status_code == 404


def test_csrf_and_security_headers(app, env):
    cl = as_(app, mk("w", "whistleblower"))
    assert cl.post("/api/v1/auth/logout").status_code == 403
    assert cl.post("/api/v1/auth/logout", headers={"origin": "http://evil.com"}).status_code == 403
    r = cl.get("/api/v1/auth/me")
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"


def test_pagination_and_audit_csv(app, env):
    ad = mk("a", "admin"); ca = as_(app, ad)
    assert ca.get("/api/v1/system/users?limit=101").status_code == 422
    assert ca.get("/api/v1/system/users?limit=0").status_code == 422
    assert ca.get("/api/v1/system/users?offset=-1").status_code == 422
    with database.WriteSession.begin() as db:
        from backend.models import AuditLog
        db.add(AuditLog(user_id=ad.id, role="admin", action="=cmd|' /C calc'!A0", endpoint="/x", status_code=200))
    csv = ca.get("/api/v1/system/audit-logs/csv").text
    assert "'=cmd" in csv and ",=cmd" not in csv


def test_decoy_still_hides_audit(app, env):
    w = mk("w", "whistleblower")
    login(TestClient(app), w, decoy=True).get("/api/v1/auth/me")
    with database.ReadSession() as db:
        from backend.models import AuditLog
        assert db.execute(select(func.count(AuditLog.id))).scalar() == 0


def test_v06_allowed_origins_behind_proxy(app, env, monkeypatch):
    cl = as_(app, mk("w", "whistleblower"))
    proxy = {"origin": "https://aegis.ngo.org"}  # Host seen by the app is "testserver", as behind a rewriting proxy
    assert cl.post("/api/v1/auth/logout", headers=proxy).status_code == 403
    monkeypatch.setattr(api.settings, "ALLOWED_ORIGINS", ["https://aegis.ngo.org"])
    assert cl.post("/api/v1/auth/logout", headers=proxy).status_code == 200
    assert cl.post("/api/v1/auth/logout", headers={"origin": "https://evil.com"}).status_code == 403
    assert cl.post("/api/v1/auth/logout", headers=H).status_code == 403  # explicit list replaces the Host rule


def test_v05_signup_queue_admin_endpoints(app, env):
    ad, w = mk("a", "admin"), mk("w", "whistleblower")
    with pytest.raises(PermissionError): auth.login_upsert("p", "new@gmail.com", True, None, "Newbie")
    assert as_(app, w).get("/api/v1/system/signups").status_code == 403
    ca = as_(app, ad)
    item = ca.get("/api/v1/system/signups").json()["items"][0]
    assert item["email"] == "new@gmail.com"
    assert ca.post(f"/api/v1/system/signups/{item['id']}/approve", headers=H, json={"role": "root"}).status_code == 422
    r = ca.post(f"/api/v1/system/signups/{item['id']}/approve", headers=H, json={"role": "hr_auditor"})
    assert r.status_code == 201 and r.json()["role"] == "hr_auditor"
    assert ca.post(f"/api/v1/system/signups/{item['id']}/reject", headers=H).status_code == 404
    assert ca.post(f"/api/v1/system/signups/{item['id']}/approve", headers=H, json={}).status_code == 404
    assert ledger.verify_chain()["is_valid"]


def test_v07_upload_scrubs_mp4_and_pdf_end_to_end(app, env):
    import io, pikepdf
    cl = as_(app, mk("w", "whistleblower"))
    box = lambda t, p=b"": (8 + len(p)).to_bytes(4, "big") + t + p
    mp4 = box(b"ftyp", b"isom\0\0\2\0isom") + box(b"moov", box(b"udta", b"\xa9xyz+37.7749-122.4194/")) + box(b"mdat", b"VIDEO")
    pdf = pikepdf.new(); pdf.add_blank_page(); pdf.docinfo["/Author"] = "Alice Whistle"
    buf = io.BytesIO(); pdf.save(buf)
    for data, name, forbidden in ((mp4, "v.mp4", b"37.7749"), (buf.getvalue(), "d.pdf", b"Alice")):
        r = cl.post("/api/v1/evidence/upload", headers=H, files={"file": (name, data, "application/octet-stream")}, data={"description": "d"})
        assert r.status_code == 201 and r.json()["metadata_scrubbed"] is True, r.text
        got = cl.get(f"/api/v1/evidence/{r.json()['id']}/download").content
        assert forbidden not in got and forbidden in data


def test_f3_sessions_are_revocable(app, env):
    ad, w = mk("a", "admin"), mk("w", "whistleblower")
    old, ca = as_(app, w), as_(app, ad)
    assert old.get("/api/v1/auth/me").status_code == 200
    assert ca.post(f"/api/v1/system/users/{w.id}/reset-2fa", headers=H).status_code == 200
    assert old.get("/api/v1/auth/me").json()["detail"] == "session revoked"  # a stolen cookie dies when the admin resets 2FA
    new = as_(app, w)
    assert new.get("/api/v1/auth/me").status_code == 200
    stale = as_(app, w)                                        # logout revokes every token of the user
    assert new.post("/api/v1/auth/logout", headers=H).status_code == 200
    assert stale.get("/api/v1/auth/me").status_code == 401 and new.get("/api/v1/auth/me").status_code == 401


def test_f3_stale_token_cannot_log_the_user_out(app, env):
    w = mk("w", "whistleblower")
    stale = as_(app, w)
    auth.revoke_sessions(w.id, 0)                              # token_version is now 1; `stale` carries 0
    fresh = as_(app, w)
    assert stale.post("/api/v1/auth/logout", headers=H).status_code == 200
    assert fresh.get("/api/v1/auth/me").status_code == 200     # the thief's logout did not touch the new session


def test_f3_decoy_logout_does_not_revoke_real_session(app, env):
    w = mk("w", "whistleblower")
    real, dec = as_(app, w), as_(app, w, decoy=True)
    assert dec.post("/api/v1/auth/logout", headers=H).status_code == 200
    assert real.get("/api/v1/auth/me").status_code == 200


# ---- upload-slot exhaustion (independent review, finding 1)
def _asgi(method="POST", path="/api/v1/evidence/upload", cookie=None, body_chunks=()):
    scope = {"type": "http", "method": method, "path": path, "headers": [(b"cookie", f"aegis={cookie}".encode())] if cookie else []}
    sent, chunks = [], list(body_chunks)

    async def receive():
        if chunks:
            c = chunks.pop(0)
            return {"type": "http.request", "body": c, "more_body": bool(chunks)}
        await asyncio.sleep(3600)  # a stalled client

    async def send(m):
        sent.append(m)
    return scope, receive, send, sent


def test_f1_strangers_cannot_hold_slots_and_stalls_time_out(env, monkeypatch):
    import asyncio as aio
    monkeypatch.setattr(api.settings, "UPLOAD_IDLE_SECONDS", 0.2)
    w = mk("w", "whistleblower")
    tok = auth.issue_token(w.id, "full_access")

    async def scenario():
        statuses = lambda sent: [m["status"] for m in sent if m["type"] == "http.response.start"]
        async def inner(scope, receive, send):
            while True:
                m = await receive()
                if not m.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 201, "headers": []}); await send({"type": "http.response.body", "body": b"ok"})
        guard = api.UploadGuard(inner)
        # 10 strangers with no cookie and a stalled body: all refused immediately, and no slot is taken
        for _ in range(10):
            sc, rc, sd, sent = _asgi(cookie=None)
            await aio.wait_for(guard(sc, rc, sd), 1)
            assert statuses(sent) == [401]
        assert not guard.sem.locked() and guard.sem._value == api.settings.MAX_CONCURRENT_UPLOADS
        sc, rc, sd, sent = _asgi(cookie="garbage.token.value")
        await guard(sc, rc, sd); assert statuses(sent) == [401]
        # a logged-in client that stalls is dropped with 408 and its slot comes back
        sc, rc, sd, sent = _asgi(cookie=tok)
        await aio.wait_for(guard(sc, rc, sd), 2)
        assert statuses(sent) == [408] and guard.sem._value == api.settings.MAX_CONCURRENT_UPLOADS
        # a normal client still works afterwards
        sc, rc, sd, sent = _asgi(cookie=tok, body_chunks=[b"abc", b"def"])
        await guard(sc, rc, sd); assert statuses(sent) == [201]
    aio.run(scenario())
