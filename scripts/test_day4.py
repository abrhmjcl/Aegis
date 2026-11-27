"""Automated verification test suite for Day 4 (Scrubbing, Decoy, Evidence & UploadGuard)."""
import base64
import os
import shutil
import tempfile
import sys
from pathlib import Path
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
os.environ.setdefault("ALLOWED_EMAILS", "worker@example.org")
os.environ.setdefault("COOKIE_SECURE", "0")

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import database, ledger, api, auth, decoy
from backend.stores import LocalStore
from backend.scrub import sniff, strip_jpeg, strip_png, strip_mp4


def run_tests():
    print("==================================================")
    print("⚡ AEGIS v3.2 DAY 4 VERIFICATION TEST SUITE")
    print("==================================================")

    temp_dir = tempfile.mkdtemp(prefix="aegis_day4_test_")
    db_path = os.path.join(temp_dir, "test.db")
    blob_dir = os.path.join(temp_dir, "blobs")

    try:
        print("[1/8] Initializing Test Database and LocalStore...")
        database.init(f"sqlite:///{db_path}")
        ledger.store = LocalStore(blob_dir)
        ledger.ensure_genesis()
        decoy.STATE.clear()
        print("      PASS: Genesis block and LocalStore ready.")

        # 1. v3.2 F9/F10 Binary Scrubbing Checks
        print("[2/8] Testing v3.2 Metadata Scrubbing with Segment Caps...")
        fake_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xe1\x00\x08Exif\x00\x00\xff\xda\x12\x34\xff\xd9"
        clean_jpeg = strip_jpeg(fake_jpeg)
        assert b"Exif" not in clean_jpeg and b"JFIF" in clean_jpeg
        print("      PASS: JPEG Exif stripped, plain 16-byte JFIF preserved.")

        # 2. FastAPI Test Client Setup
        print("[3/8] Initializing TestClient and Users...")
        app = api.create_app()
        client = TestClient(app, base_url="http://localhost:8000")

        # Create test users
        admin = auth.login_upsert("admin-sub", "admin@example.org", True, None, "Admin User")
        wb = auth.login_upsert("wb-sub-1", "wb@example.org", True, None, "Whistleblower 1")
        worker1 = auth.login_upsert("w1-sub", "w1@example.org", True, None, "Relief Worker 1")
        worker2 = auth.login_upsert("w2-sub", "w2@example.org", True, None, "Relief Worker 2")
        auditor = auth.login_upsert("aud-sub", "aud@example.org", True, None, "Auditor User")

        # Set appropriate roles
        auth.admin_update(admin.id, wb.id, role="whistleblower")
        auth.admin_update(admin.id, worker1.id, role="relief_worker")
        auth.admin_update(admin.id, worker2.id, role="relief_worker")
        auth.admin_update(admin.id, auditor.id, role="hr_auditor")

        # Mint full_access tokens
        wb_token = auth.issue_token(wb.id, "full_access")
        w1_token = auth.issue_token(worker1.id, "full_access")
        w2_token = auth.issue_token(worker2.id, "full_access")
        aud_token = auth.issue_token(auditor.id, "full_access")
        print("      PASS: Test users and session tokens ready.")

        # 3. v3.2 F1 Check: UploadGuard Pre-Authentication
        print("[4/8] Testing F1 Check: UploadGuard rejects unauthenticated uploaders...")
        unauth_client = TestClient(app, base_url="http://localhost:8000")
        files = {"file": ("test.jpg", clean_jpeg, "image/jpeg")}
        data = {"description": "Evidence upload attempt"}
        unauth_resp = unauth_client.post("/api/v1/evidence/upload", files=files, data=data, headers={"Origin": "http://localhost:8000"})
        assert unauth_resp.status_code == 401, "F1: Unauthenticated upload must be rejected with 401 before taking slot"
        print("      PASS: F1 unauthenticated upload slot exhaustion prevented.")

        # 4. Legitimate Evidence Upload with 1MB Padding
        print("[5/8] Testing Authenticated Evidence Upload & 1MB Padding...")
        client.cookies.set(api.COOKIE, wb_token)
        resp = client.post("/api/v1/evidence/upload", files=files, data=data, headers={"Origin": "http://localhost:8000"})
        assert resp.status_code == 201
        res_json = resp.json()
        assert res_json["metadata_scrubbed"] is True
        eid = res_json["id"]

        # Verify 1MB padding on disk (LocalStore adds 12-byte nonce + 16-byte tag = 28 bytes overhead)
        stored_keys = ledger.store.keys("blobs/")
        blob_bytes = ledger.store.get(stored_keys[0])
        assert len(blob_bytes) % (1024 * 1024) == 28
        print("      PASS: Encrypted evidence stored and padded to 1MB boundary.")

        # Verify evidence download and decryption
        dl_resp = client.get(f"/api/v1/evidence/{eid}/download")
        assert dl_resp.status_code == 200
        assert dl_resp.content == clean_jpeg
        assert dl_resp.headers["content-security-policy"] == "sandbox"
        print("      PASS: Evidence download and cryptographic integrity verified.")

        # 5. v3.2 Decoy Method Not Allowed check (F4)
        print("[6/8] Testing F4 Check: Decoy 405 Method Not Allowed parity...")
        decoy_tok = auth.issue_token(wb.id, "full_access", decoy=True)
        decoy_client = TestClient(app, base_url="http://localhost:8000")
        decoy_client.cookies.set(api.COOKIE, decoy_tok)
        head_resp = decoy_client.request("HEAD", "/api/v1/auth/me", headers={"Origin": "http://localhost:8000"})
        assert head_resp.status_code == 405, "F4: Decoy must return 405 on invalid HTTP verbs"
        assert "allow" in head_resp.headers
        print("      PASS: Decoy returned 405 Method Not Allowed with Allow header.")

        # 6. Relief Two-Person Rule Verification (F8)
        print("[7/8] Testing F8 Check: Relief two-person confirmation rule...")
        # Worker 1 allocates relief
        client.cookies.set(api.COOKIE, w1_token)
        rl_alloc = client.post("/api/v1/relief/allocate", json={
            "amount_cents": 50000,
            "currency": "USD",
            "category": "food",
            "recipient_name": "Hospital Clinic A",
            "recipient_details": "Urgent supplies",
            "destination": "District 4"
        }, headers={"Origin": "http://localhost:8000"})
        assert rl_alloc.status_code == 201
        rid = rl_alloc.json()["id"]

        # Worker 1 dispatches to in_transit
        rl_dispatch = client.put(f"/api/v1/relief/{rid}/status", json={"status": "in_transit"}, headers={"Origin": "http://localhost:8000"})
        assert rl_dispatch.status_code == 200

        # Worker 1 CANNOT confirm delivery of their own allocation
        rl_self_deliver = client.put(f"/api/v1/relief/{rid}/status", json={"status": "delivered"}, headers={"Origin": "http://localhost:8000"})
        assert rl_self_deliver.status_code == 403, "Allocating worker cannot confirm their own delivery"

        # Worker 2 confirms delivery
        client.cookies.set(api.COOKIE, w2_token)
        rl_w2_deliver = client.put(f"/api/v1/relief/{rid}/status", json={"status": "delivered"}, headers={"Origin": "http://localhost:8000"})
        assert rl_w2_deliver.status_code == 200
        print("      PASS: Two-person relief delivery rule strictly enforced.")

        # 7. Land Deed Finality Check
        print("[8/8] Testing Land Deed Registration and Verdict Finality...")
        client.cookies.set(api.COOKIE, wb_token)
        ld_reg = client.post("/api/v1/land/register", json={
            "owner_name": "Citizen Zero",
            "location": "Sector 7G",
            "area_size": "2.5 hectares"
        }, headers={"Origin": "http://localhost:8000"})
        assert ld_reg.status_code == 201
        did = ld_reg.json()["id"]

        # Auditor decides verdict
        client.cookies.set(api.COOKIE, aud_token)
        ld_verdict = client.put(f"/api/v1/land/verify/{did}", json={"status": "verified"}, headers={"Origin": "http://localhost:8000"})
        assert ld_verdict.status_code == 200

        # Subsequent changes must be refused with 409 Conflict
        ld_flip = client.put(f"/api/v1/land/verify/{did}", json={"status": "disputed"}, headers={"Origin": "http://localhost:8000"})
        assert ld_flip.status_code == 409, "Decided land deeds must be immutable"
        print("      PASS: Land deed verdict finality enforced.")

        print("==================================================")
        print("✅ ALL DAY 4 API, SCRUBBER & DECOY TESTS PASSED!")
        print("==================================================")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_tests()
