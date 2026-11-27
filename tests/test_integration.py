"""Integration tests at the network edge. S3 is MOCKED (moto) and Google is MOCKED: these prove our code paths, not AWS or Google behaviour."""
import threading, http.client, socket
import pytest, uvicorn
from fastapi.testclient import TestClient
from backend import api, auth, database, ledger
from backend.stores import S3Store

H = {"origin": "http://testserver"}


# ---------------------------------------------------------------- S3Store against moto
@pytest.fixture
def s3(monkeypatch):
    from moto import mock_aws
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test"); monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test"); monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        import boto3
        boto3.client("s3").create_bucket(Bucket="aegis-test")
        yield S3Store("aegis-test")


def test_s3store_put_get_keys_and_write_once(s3):
    s3.put("blobs/a", b"one"); s3.put("blobs/b", b"two"); s3.put("anchors/0000000001.json", b"{}", once=True)
    assert s3.get("blobs/a") == b"one" and s3.keys("blobs/") == ["blobs/a", "blobs/b"] and s3.keys("anchors/") == ["anchors/0000000001.json"]
    with pytest.raises(FileExistsError): s3.put("anchors/0000000001.json", b"tamper", once=True)  # an anchor cannot be replaced
    assert s3.get("anchors/0000000001.json") == b"{}"
    s3.put("blobs/a", b"overwritten")                                                                # normal puts still overwrite
    assert s3.get("blobs/a") == b"overwritten"


def test_s3store_lists_more_than_one_page(s3):
    for i in range(1105):  # list_objects_v2 returns 1000 per page; verify_chain must see all anchors
        s3.put(f"anchors/{i:010d}.json", b"{}")
    assert len(s3.keys("anchors/")) == 1105


def test_ledger_and_evidence_on_s3(env, s3):
    ledger.store = s3
    ledger.ensure_genesis()                                     # `env` already created the genesis block on the local store; this anchors it on S3
    with database.ReadSession() as db:
        first = db.execute(__import__("sqlalchemy").text("select * from master_ledger where id=1")).first()
    ledger.publish_anchor(type("B", (), {"id": 1, "current_hash": first.current_hash})())
    u = auth.login_upsert("s", "ok@example.org", True, None, "N")
    assert u.is_active
    r = ledger.verify_chain()
    assert r["is_valid"] and r["anchors_checked"] == 2
    cl = TestClient(api.create_app()); cl.cookies.set("aegis", auth.issue_token(u.id, "full_access"))
    up = cl.post("/api/v1/evidence/upload", headers=H, files={"file": ("a.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\0" * 9 + b"\xff\xda\x00\x04\x00\x00\x12\xff\xd9", "image/jpeg")}, data={"description": "d"})
    assert up.status_code == 201 and len(s3.keys("blobs/")) == 1
    assert cl.get(f"/api/v1/evidence/{up.json()['id']}/download").status_code == 200
    assert not s3.get(s3.keys("blobs/")[0]).startswith(b"\xff\xd8")  # stored encrypted
    s3.c.delete_object(Bucket="aegis-test", Key=s3.keys("anchors/")[-1])  # deleting only the NEWEST anchor...
    assert ledger.verify_chain()["is_valid"]                      # ...is not noticed (documented limit): auditors need an external copy of tip_hash


# ---------------------------------------------------------------- OAuth callback with a mocked Google token
@pytest.fixture
def oauth_app(env, monkeypatch):
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://testserver/auth/callback")
    from backend import oauth
    app = api.create_app(); app.include_router(oauth.router)
    return oauth, app


def _callback(oauth_app, monkeypatch, userinfo):
    oauth, app = oauth_app

    async def fake(request):
        return {"userinfo": userinfo}
    monkeypatch.setattr(oauth.oauth.google, "authorize_access_token", fake)
    return TestClient(app).get("/auth/callback", follow_redirects=False)


def test_oauth_callback_allowlisted_user_gets_pre2fa_cookie_only(oauth_app, monkeypatch):
    r = _callback(oauth_app, monkeypatch, {"sub": "g1", "email": "ok@example.org", "email_verified": True, "name": "N"})
    assert r.status_code == 303 and "aegis=" in r.headers["set-cookie"] and "httponly" in r.headers["set-cookie"].lower()
    tok = r.headers["set-cookie"].split("aegis=")[1].split(";")[0]
    assert auth.decode_token(tok)["scope"] == "pre_2fa"          # signing in with Google never gives full access by itself
    cl = TestClient(oauth_app[1]); cl.cookies.set("aegis", tok)
    assert cl.get("/api/v1/auth/me").status_code == 401           # and the pre_2fa cookie opens no data route


def test_oauth_callback_refusals(oauth_app, monkeypatch):
    r = _callback(oauth_app, monkeypatch, {"sub": "g2", "email": "x@gmail.com", "email_verified": False, "name": "N"})
    assert r.status_code == 403 and "not verified" in r.text and "set-cookie" not in r.headers
    r = _callback(oauth_app, monkeypatch, {"sub": "g3", "email": "x@gmail.com", "email_verified": True, "name": "N"})
    assert r.status_code == 403 and "awaiting" in r.text and "set-cookie" not in r.headers      # parked in the queue
    r = _callback(oauth_app, monkeypatch, {"sub": "g4", "email": "x@evil.org", "email_verified": True, "hd": "ngo.org.evil.org", "name": "N"})
    assert r.status_code == 403                                                                    # lookalike hosted domain is not the allowed domain
    r = _callback(oauth_app, monkeypatch, {"sub": "g5", "email": "w@ngo.org", "email_verified": True, "hd": "ngo.org", "name": "N"})
    assert r.status_code == 303


def test_oauth_callback_queue_full_is_503(oauth_app, monkeypatch):
    monkeypatch.setattr(auth.settings, "MAX_PENDING_SIGNUPS", 0)
    r = _callback(oauth_app, monkeypatch, {"sub": "g6", "email": "q@gmail.com", "email_verified": True, "name": "N"})
    assert r.status_code == 503


# ---------------------------------------------------------------- real HTTP through a Host-rewriting proxy
class Proxy(threading.Thread):
    """Minimal reverse proxy: like an ALB/nginx that terminates TLS and rewrites Host to the upstream, keeping the browser's Origin."""

    def __init__(self, upstream_port):
        super().__init__(daemon=True)
        import http.server

        up = upstream_port

        class H_(http.server.BaseHTTPRequestHandler):
            def _fwd(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                hdrs = {k: v for k, v in self.headers.items() if k.lower() != "host"}
                c = http.client.HTTPConnection("127.0.0.1", up)
                c.request(self.command, self.path, body, {**hdrs, "Host": f"127.0.0.1:{up}"})  # Host rewritten, Origin untouched
                r = c.getresponse(); data = r.read()
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers(); self.wfile.write(data)
            do_GET = do_POST = do_PUT = _fwd

            def log_message(self, *a): pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H_)
        self.port = self.srv.server_address[1]

    def run(self):
        self.srv.serve_forever()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


def test_real_http_behind_host_rewriting_proxy(env, monkeypatch):
    import time
    w = auth.login_upsert("w", "ok@example.org", True, None, "N")
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(api.create_app(), host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    proxy = Proxy(port); proxy.start()
    cookie = f"aegis={auth.issue_token(w.id, 'full_access')}"
    try:
        def post(origin):
            c = http.client.HTTPConnection("127.0.0.1", proxy.port)
            c.request("POST", "/api/v1/auth/logout", b"", {"Origin": origin, "Cookie": cookie, "Host": "aegis.ngo.org"})
            return c.getresponse().status
        assert post("https://aegis.ngo.org") == 403                            # without ALLOWED_ORIGINS the rewritten Host breaks every write
        monkeypatch.setattr(api.settings, "ALLOWED_ORIGINS", ["https://aegis.ngo.org"])
        assert post("https://aegis.ngo.org") == 200                            # with it, the same request works
        assert post("https://evil.example") == 403                             # and a foreign origin is still refused
    finally:
        server.should_exit = True; proxy.srv.shutdown()
