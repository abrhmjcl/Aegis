"""Automated verification test suite for Day 6 (Frontend Security & UI Mounting) - v3.2 Protocol."""
import base64
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_b64 = lambda: base64.urlsafe_b64encode(os.urandom(32)).decode()
os.environ.setdefault("JWT_SECRET", os.urandom(32).hex())
os.environ.setdefault("APP_SECRET", os.urandom(32).hex())
os.environ.setdefault("AES_PII_KEY_B64", _b64())
os.environ.setdefault("AES_EVIDENCE_KEY_B64", _b64())
os.environ.setdefault("HMAC_KEY_B64", _b64())
os.environ.setdefault(
    "ED25519_PRIVATE_KEY_HEX",
    Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex(),
)
os.environ.setdefault("INITIAL_ADMIN_EMAIL", "admin@example.org")
os.environ.setdefault("COOKIE_SECURE", "0")

import httpx
import uvicorn

# Add project root to sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from backend import api, database, ledger
from backend.stores import LocalStore

FRONT = pathlib.Path(__file__).resolve().parents[1] / "frontend"

def run_tests():
    print("==================================================")
    print("⚡ AEGIS v3.2 DAY 6 VERIFICATION TEST SUITE")
    print("==================================================")

    # 1. Static Anti-XSS Check
    print("[1/5] Auditing Frontend Source Code for Unsafe HTML Sinks...")
    js_path = FRONT / "app.js"
    html_path = FRONT / "index.html"
    assert js_path.exists(), "frontend/app.js missing!"
    assert html_path.exists(), "frontend/index.html missing!"

    js_lines = [l for l in js_path.read_text(encoding="utf-8").splitlines() if not l.strip().startswith("//")]
    js_code = "\n".join(js_lines)

    # Invariant: innerHTML, outerHTML, eval, etc. strictly prohibited
    unsafe_pattern = r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setTimeout\(\s*[\"']"
    match = re.search(unsafe_pattern, js_code)
    assert not match, f"Security Violation: Found unsafe sink '{match.group()}' in frontend/app.js!"

    html_code = html_path.read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html_code), "Security Violation: Found inline <script> in index.html!"
    assert not re.search(r"\son\w+\s*=", html_code), "Security Violation: Found inline event handler in index.html!"
    assert "style=" not in html_code, "Security Violation: Found inline style attribute in index.html!"
    print("      PASS: Zero unsafe HTML sinks detected. Strict DOM text-node policy confirmed.")

    # 2. Node.js parse check
    print("[2/5] Checking JavaScript Syntax Validity...")
    if shutil.which("node"):
        res = subprocess.run(["node", "--check", str(js_path)], capture_output=True, text=True)
        assert res.returncode == 0, f"Node syntax check failed: {res.stderr}"
        print("      PASS: frontend/app.js parsed cleanly by Node.js engine.")
    else:
        print("      SKIP: Node.js not detected in PATH; skipping external AST check.")

    # 3. Live Server Initialization
    print("[3/5] Starting Ephemeral Uvicorn Live Server with UI Mounted...")
    temp_dir = tempfile.mkdtemp(prefix="aegis_day6_")
    db_path = os.path.join(temp_dir, "test.db")
    blob_dir = os.path.join(temp_dir, "blobs")

    try:
        database.init(f"sqlite:///{db_path}")
        ledger.store = LocalStore(blob_dir)
        ledger.ensure_genesis()

        app = api.create_app()
        api.mount_ui(app)

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        while not server.started:
            time.sleep(0.05)
        base_url = f"http://127.0.0.1:{port}"

        # 4. Security Headers & Static Serving
        print("[4/5] Verifying Static Serving & CSP Security Headers...")
        r_index = httpx.get(f"{base_url}/")
        assert r_index.status_code == 200, f"GET / failed with {r_index.status_code}"
        assert "app.js" in r_index.text
        assert "default-src 'self'" in r_index.headers.get("content-security-policy", ""), "Missing CSP header!"
        assert r_index.headers.get("x-frame-options") == "DENY", "Missing X-Frame-Options: DENY!"
        assert r_index.headers.get("x-content-type-options") == "nosniff"

        # App.js and style.css assets
        r_js = httpx.get(f"{base_url}/app.js")
        assert r_js.status_code == 200
        assert "use strict" in r_js.text

        r_css = httpx.get(f"{base_url}/style.css")
        assert r_css.status_code == 200

        # /docs must be disabled (404)
        r_docs = httpx.get(f"{base_url}/docs")
        assert r_docs.status_code == 404, "Swagger /docs must be disabled in production!"
        print("      PASS: Static files served with strict CSP and security headers.")

        # 5. Routing Priority: API Routes Win Over Static UI
        print("[5/5] Testing Routing Priority (API Routes Over UI Mount)...")
        r_api = httpx.get(f"{base_url}/api/v1/auth/me")
        assert r_api.status_code == 401, f"Expected 401 from API route, got {r_api.status_code}"
        print("      PASS: API routes win over static file mount at root.")

        server.should_exit = True
        t.join(timeout=2)

        print("==================================================")
        print("🎉 ALL DAY 6 FRONTEND & UI TESTS PASSED!")
        print("==================================================")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    run_tests()
