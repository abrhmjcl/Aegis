"""Automated verification test suite for Day 3 (Authentication, Gates, 2FA, token_version & Duress)."""
import base64
import os
import shutil
import sys
import tempfile
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
os.environ.setdefault("ALLOWED_EMAILS", "worker@example.org,auditor@example.org")
os.environ.setdefault("COOKIE_SECURE", "0")

import pyotp

# Ensure project root is in Python module search path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import auth, database, ledger
from backend.config import settings
from backend.models import User
from backend.stores import LocalStore


def run_tests():
    print("==================================================")
    print("⚡ AEGIS v3.2 DAY 3 VERIFICATION TEST SUITE")
    print("==================================================")

    temp_dir = tempfile.mkdtemp(prefix="aegis_day3_test_")
    db_path = os.path.join(temp_dir, "test.db")
    blob_dir = os.path.join(temp_dir, "blobs")

    try:
        print("[1/8] Initializing Environment & Genesis Ledger...")
        database.init(f"sqlite:///{db_path}")
        ledger.store = LocalStore(blob_dir)
        ledger.ensure_genesis()
        print("      PASS: Environment and Genesis verified.")

        # 1. First Admin Bootstrap
        print("[2/8] Testing First Admin Bootstrap Rule...")
        admin = auth.login_upsert("admin-sub-1", "admin@example.org", True, None, "Admin Boss")
        assert admin.role == "admin" and admin.is_active is True
        print(f"      PASS: Admin #{admin.id} registered as first active admin.")

        # 2. Allow-List vs. Pending Queue
        print("[3/8] Testing Allow-List and Pending Signup Queue...")
        user_ok = auth.login_upsert("worker-sub-2", "worker@example.org", True, None, "Verified Worker")
        assert user_ok.role == "whistleblower"

        try:
            auth.login_upsert("intruder-sub-3", "intruder@hacker.io", True, None, "Intruder")
            assert False, "Should have raised PermissionError"
        except PermissionError as e:
            assert "awaiting admin approval" in str(e)
            print("      PASS: Unknown email parked in pending_signups queue.")

        # 3. v3.2 F3 Check: Session Revocation via token_version
        print("[4/8] Testing F3 Check: Token Revocation on Logout & 2FA Reset...")
        tok1 = auth.issue_token(user_ok.id, "full_access")
        claims1 = auth.decode_token(tok1)
        assert claims1["tv"] == 0

        # Simulate logout / revocation
        assert auth.revoke_sessions(user_ok.id, claims1["tv"]) is True
        
        # New token gets updated version
        tok2 = auth.issue_token(user_ok.id, "full_access")
        claims2 = auth.decode_token(tok2)
        assert claims2["tv"] == 1
        print("      PASS: F3 session revocation bumped token_version to 1.")

        # 4. 2FA Setup Flow & Anti-Replay
        print("[5/8] Testing TOTP 2FA Enrollment & Anti-Replay Guard...")
        secret, uri = auth.begin_2fa_setup(user_ok.id)
        totp = pyotp.TOTP(secret)
        code = totp.now()
        res = auth.verify_code(user_ok.id, code)
        assert res == "ok"

        # Replay must fail
        replay_res = auth.verify_code(user_ok.id, code)
        assert replay_res == "replay"
        print("      PASS: 2FA enrolled and replay blocked.")

        # 5. Atomic Attempt Reservation & Account Lockout
        print(f"[6/8] Testing Atomic 2FA Reservation & Lockout (Max {settings.MAX_2FA_ATTEMPTS} attempts)...")
        for _ in range(settings.MAX_2FA_ATTEMPTS):
            auth.verify_code(user_ok.id, "000000")
        assert auth.verify_code(user_ok.id, "000000") == "locked"
        print(f"      PASS: Account locked after {settings.MAX_2FA_ATTEMPTS} invalid attempts.")

        # 6. Pre-Lockout Duress Engine
        print("[7/8] Testing Pre-Lockout Duress Engine...")
        auth.set_duress_code(user_ok.id, "Hostage99")
        # Duress code bypasses lockout and clears failed attempts
        duress_res = auth.verify_code(user_ok.id, "Hostage99")
        assert duress_res == "decoy"
        print("      PASS: Duress code bypassed lockout and issued decoy session.")

        # 7. Last-Admin Invariant Protection
        print("[8/8] Testing Last-Admin Protection Invariant...")
        try:
            auth.admin_update(None, admin.id, active=False)
            assert False, "Should not be able to deactivate sole admin"
        except ValueError as e:
            assert "leave the system without an active admin" in str(e)
            print("      PASS: System refused deactivation of sole active administrator.")

        print("==================================================")
        print("✅ ALL DAY 3 AUTHENTICATION TESTS PASSED!")
        print("==================================================")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_tests()
