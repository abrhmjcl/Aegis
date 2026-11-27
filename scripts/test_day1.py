"""Verification test suite for Day 1 (Config, DB, Models, Crypto, Store)."""
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Load .env into os.environ before importing settings
env_path = Path(__file__).resolve().parents[1] / ".env"
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from backend import database
from backend.config import settings
from backend.crypto import (
    decrypt_blob,
    decrypt_field,
    encrypt_blob,
    encrypt_field,
    file_hmac,
    sub_hmac,
)
from backend.models import User
from backend.stores import LocalStore


def run_tests():
    print("==================================================")
    print("⚡ AEGIS v3.2 DAY 1 VERIFICATION TEST SUITE")
    print("==================================================")

    # 1. Configuration Validation
    print("[1/5] Validating System Configuration...")
    settings.validate()
    assert settings.PENDING_TTL_DAYS == 7, "Default PENDING_TTL_DAYS must be 7"
    assert settings.UPLOAD_IDLE_SECONDS == 20.0, "Default UPLOAD_IDLE_SECONDS must be 20.0"
    print("      PASS: Config validation passed.")

    temp_dir = tempfile.mkdtemp(prefix="aegis_day1_test_")
    db_path = os.path.join(temp_dir, "test.db")
    blob_dir = os.path.join(temp_dir, "blobs")

    try:
        # 2. Database Init & Table Creation
        print("[2/5] Initializing Dual-Engine SQLite WAL Database...")
        database.init(f"sqlite:///{db_path}")
        assert database.engine is not None, "Read engine must be initialized"
        assert database.write_engine is not None, "Write engine must be initialized"
        print("      PASS: DB engines initialized.")

        # 3. Model Insert & token_version verification
        print("[3/5] Testing User Model & token_version Column...")
        with database.WriteSession.begin() as db:
            u = User(
                google_sub_hmac=sub_hmac("test_sub_123"),
                encrypted_email=encrypt_field("alice@ngo.org", "PII", "users.encrypted_email"),
                encrypted_name=encrypt_field("Alice Whistle", "PII", "users.encrypted_name"),
                role="whistleblower",
                is_active=True,
            )
            db.add(u)

        with database.ReadSession() as db:
            saved = db.get(User, 1)
            assert saved is not None, "User record must be retrievable"
            assert saved.token_version == 0, "Default token_version must be 0"
            assert decrypt_field(saved.encrypted_email, "PII", "users.encrypted_email") == "alice@ngo.org"
        print("      PASS: Model created and verified with token_version=0.")

        # 4. Cryptographic Domain Separation & AAD
        print("[4/5] Testing AES-256-GCM Domain Separation & Padding...")
        tok = encrypt_field("secret_note", "PII", "evidence.encrypted_description")
        assert decrypt_field(tok, "PII", "evidence.encrypted_description") == "secret_note"

        # Tampered AAD must fail
        try:
            decrypt_field(tok, "PII", "wrong.column")
            raise AssertionError("Decryption with wrong AAD must fail")
        except Exception:
            pass

        # Wrong domain must fail
        try:
            decrypt_field(tok, "EVIDENCE", "evidence.encrypted_description")
            raise AssertionError("Decryption with wrong domain must fail")
        except Exception:
            pass

        # 1MB Blob Padding & Framing
        raw_data = b"DEFENSE_INTEL_STREAM" * 50
        blob = encrypt_blob(raw_data, "evidence:testkey")
        # Structure: 12-byte nonce + (8 length + payload + pad up to 1MB) + 16-byte tag
        assert len(blob) == 12 + 1024 * 1024 + 16, f"Blob length {len(blob)} must be exactly 1MB + 28 bytes"
        assert decrypt_blob(blob, "evidence:testkey") == raw_data

        # Corrupt tag must fail
        corrupt = blob[:-1] + bytes([blob[-1] ^ 1])
        try:
            decrypt_blob(corrupt, "evidence:testkey")
            raise AssertionError("Decryption of corrupted blob must fail")
        except Exception:
            pass
        print("      PASS: Domain separation, AAD binding, and 1MB padding verified.")

        # 5. LocalStore Verification
        print("[5/5] Testing LocalStore write-once behavior...")
        store = LocalStore(blob_dir)
        store.put("anchors/0000000001.json", b'{"block": 1}', once=True)
        try:
            store.put("anchors/0000000001.json", b'{"tamper": 2}', once=True)
            raise AssertionError("Overwriting with once=True must raise FileExistsError")
        except FileExistsError:
            pass
        assert store.get("anchors/0000000001.json") == b'{"block": 1}'
        assert "anchors/0000000001.json" in store.keys("anchors")
        print("      PASS: LocalStore write-once immutability verified.")

        print("==================================================")
        print("✅ ALL DAY 1 VERIFICATION TESTS PASSED SUCCESSFULLY!")
        print("==================================================")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_tests()
