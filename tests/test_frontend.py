"""Front end: static safety rules + a real Chromium driving the real server (2FA enrolment, upload, XSS payload, duress login, admin views)."""
import pathlib, re, shutil, subprocess, threading, time
import pyotp, pytest, uvicorn
from backend import api, auth, database
from backend.models import Evidence

FRONT = pathlib.Path(__file__).resolve().parents[1] / "frontend"
JPG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\0" * 9 + b"\xff\xda\x00\x04\x00\x00\x12\xff\xd9"
XSS = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'


def test_front_end_has_no_unsafe_html_apis_and_no_inline_code():
    js = "\n".join(l for l in (FRONT / "app.js").read_text().splitlines() if not l.strip().startswith("//"))
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setTimeout\(\s*[\"']", js)
    html = (FRONT / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and not re.search(r"\son\w+\s*=", html) and "style=" not in html  # CSP default-src 'self' forbids all of these
    assert "style=" not in js.replace("setAttribute", "")


@pytest.mark.skipif(not shutil.which("node"), reason="needs node")
def test_front_end_js_parses():
    subprocess.run(["node", "--check", str(FRONT / "app.js")], check=True)


@pytest.fixture
def live(env):
    app = api.create_app(); api.mount_ui(app)
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


def test_static_files_served_with_security_headers(live):
    import httpx
    r = httpx.get(live + "/")
    assert r.status_code == 200 and "app.js" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
    assert httpx.get(live + "/app.js").status_code == 200 and httpx.get(live + "/docs").status_code == 404
    assert httpx.get(live + "/api/v1/auth/me").status_code == 401           # API routes still win over the static mount


def test_browser_end_to_end(env, live):
    sync_api = pytest.importorskip("playwright.sync_api")
    w = auth.login_upsert("w", "ok@example.org", True, None, "Whistle")
    admin = auth.login_upsert("a", "boss@example.org", True, None, "Boss")
    problems = []
    with sync_api.sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--no-sandbox"])

        def new_page(user_id, scope):
            ctx = browser.new_context(accept_downloads=True)
            ctx.add_cookies([{"name": "aegis", "value": auth.issue_token(user_id, scope), "url": live, "httpOnly": True, "sameSite": "Strict"}])
            page = ctx.new_page()
            page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
            page.on("console", lambda m: problems.append(f"console: {m.text}") if m.type == "error" and "401" not in m.text else None)
            return ctx, page

        # ---- whistleblower: enrol 2FA through the UI, upload with an XSS payload
        ctx, page = new_page(w.id, "pre_2fa")
        page.goto(live + "/")
        page.get_by_role("button", name="Set up 2FA").click()
        secret = page.locator("code").first.inner_text()
        page.get_by_label("6-digit code").fill(pyotp.TOTP(secret).now())
        page.get_by_role("button", name="Continue").click()
        page.get_by_role("button", name="Evidence", exact=True).wait_for()
        assert "whistleblower" in page.locator("#who").inner_text()

        page.get_by_label("File (JPEG").set_input_files({"name": "a.jpg", "mimeType": "image/jpeg", "buffer": JPG})
        page.get_by_label("Description").fill(XSS)
        page.get_by_role("button", name="Upload").click()
        page.get_by_text("Uploaded as evidence #1").wait_for()
        page.get_by_role("cell", name=XSS, exact=True).wait_for()               # the payload is shown as literal text
        assert page.evaluate("window.__pwned") is None and page.locator("img[src='x']").count() == 0
        dl = ctx.request.get(live + "/api/v1/evidence/1/download")
        assert dl.status == 200 and dl.headers["content-disposition"].startswith("attachment") and dl.body().startswith(b"\xff\xd8")

        # ---- duress code, sign out, sign in again with it: a decoy workspace
        page.get_by_role("button", name="Account").click()
        page.get_by_label("New duress code").fill("Panic2024")
        page.get_by_role("button", name="Save duress code").click()
        page.get_by_text("Duress code saved.").wait_for()
        page.get_by_role("button", name="Sign out").click()
        page.get_by_text("Two-factor code").wait_for()
        ctx.add_cookies([{"name": "aegis", "value": auth.issue_token(w.id, "pre_2fa"), "url": live, "httpOnly": True, "sameSite": "Strict"}])
        page.reload()
        page.get_by_label("6-digit code").fill("Panic2024")
        page.get_by_role("button", name="Continue").click()
        page.get_by_role("button", name="Evidence", exact=True).wait_for()
        page.get_by_text("Nothing here yet.").wait_for()                       # the decoy shows an empty workspace...
        with database.ReadSession() as db:
            assert db.query(Evidence).count() == 1                              # ...while the real evidence is untouched
        ctx.close()

        # ---- admin: users table and ledger check
        ctx, page = new_page(admin.id, "full_access")
        page.goto(live + "/")
        page.get_by_role("button", name="Users").click()
        page.get_by_role("cell", name="ok@example.org").wait_for()
        page.get_by_role("cell", name="boss@example.org").wait_for()
        page.get_by_role("button", name="Sign-ups").click()
        page.get_by_text("Pending sign-ups").wait_for()
        page.get_by_role("button", name="Ledger check").click()
        page.get_by_role("button", name="Verify now").click()
        page.get_by_text("Ledger is valid").wait_for()
        ctx.close(); browser.close()
    assert not problems, problems  # no JavaScript errors, no CSP violations
