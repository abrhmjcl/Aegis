"""Verification script for Day 2: Ledger Core, Ed25519 Signatures, and verify_chain."""
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

# Add project root to Python search path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import database, ledger
from backend.config import settings
from backend.crypto import encrypt_field, sub_hmac
from backend.models import User
from backend.stores import LocalStore


def setup_test_env():
    """Ensure minimal valid cryptographic settings are present in the environment."""
    defaults = {
        "DATABASE_URL": "sqlite:///./test_aegis.db",
        "JWT_SECRET": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "APP_SECRET": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "AES_PII_KEY_B64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AES_EVIDENCE_KEY_B64": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "HMAC_KEY_B64": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
        "ED25519_PRIVATE_KEY_HEX": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "ALLOWED_ORIGINS": "http://localhost:8000",
        "ALLOWED_DOMAIN": "ngo.org",
        "INITIAL_ADMIN_EMAIL": "admin@ngo.org",
    }
    for k, v in defaults.items():
        if not os.environ.get(k):
            os.environ[k] = v

    settings.__init__()
    settings.validate()


def run_ledger_tests():
    print("==================================================================")
    print("⚡ AEGIS v3.2 DAY 2: CRYPTOGRAPHIC LEDGER VERIFICATION SUITE")
    print("==================================================================")

    setup_test_env()

    # Use a temporary directory for clean isolation
    temp_dir = tempfile.mkdtemp(prefix="aegis_ledger_test_")
    db_path = os.path.join(temp_dir, "ledger_test.db")
    blob_dir = os.path.join(temp_dir, "blobs")

    try:
        # 1. Initialize Dual-Engine Database & Storage Provider
        print("\n[Step 1] Initializing Dual-Engine SQLite WAL and LocalStore...")
        database.init(f"sqlite:///{db_path}")
        ledger.store = LocalStore(blob_dir)
        print("         Dual SQLite engines and LocalStore initialized successfully.")

        # 2. Genesis Block Initialization
        print("\n[Step 2] Testing ensure_genesis() and Genesis Anchor Publishing...")
        ledger.ensure_genesis()
        
        # Verify genesis state
        result = ledger.verify_chain()
        print(f"         verify_chain() result: {result}")
        assert result["is_valid"] is True, f"Genesis verification failed: {result}"
        assert result["blocks"] == 1, f"Expected 1 block, found {result['blocks']}"
        assert result["anchors_checked"] == 1, f"Expected 1 anchor, found {result['anchors_checked']}"
        assert result["tip_block"] == 1
        print(f"         SUCCESS: Genesis Block #1 created.")
        print(f"         Tip Hash: {result['tip_hash']}")

        # 3. Append Legitimate User Record and Publish Anchor
        print("\n[Step 3] Appending Authorized User Record & Block #2...")
        with database.WriteSession.begin() as db:
            user = User(
                google_sub_hmac=sub_hmac("google-oauth2|10987654321"),
                role="whistleblower",
                is_active=True,
                encrypted_email=encrypt_field("whistleblower@ngo.org", "PII", "users.email"),
                encrypted_name=encrypt_field("Witness One", "PII", "users.name"),
            )
            blk = ledger.append_block(
                db=db,
                module="USER",
                action="REGISTER",
                record=user,
                actor_id=None,
                snapshot="User #{id} registered role=whistleblower",
            )
        ledger.publish_anchor(blk)

        result = ledger.verify_chain()
        assert result["is_valid"] is True
        assert result["blocks"] == 2
        assert result["anchors_checked"] == 2
        print(f"         SUCCESS: Block #2 appended and verified. Tip Block: {result['tip_block']}.")

        # 4. Tamper Simulation 1: Direct SQL Role Escalation (ROW_TAMPERED)
        print("\n[Step 4] Simulating Direct SQLite Role Escalation (Attack 1)...")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE users SET role = 'admin' WHERE id = 1")
        conn.commit()
        conn.close()

        result = ledger.verify_chain()
        print(f"         verify_chain() response: {result}")
        assert result["is_valid"] is False
        assert result["error_type"] == "ROW_TAMPERED"
        assert result["broken_at_block"] == 2
        print("         SUCCESS: Tampered role detected via row_hash mismatch.")

        # Revert role change
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE users SET role = 'whistleblower' WHERE id = 1")
        conn.commit()
        conn.close()
        assert ledger.verify_chain()["is_valid"] is True

        # 5. Tamper Simulation 2: Vulnerability F2 Identity Swap (ROW_TAMPERED)
        print("\n[Step 5] Simulating Identity Swap in SQLite (Attack 2 — Vulnerability F2)...")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE users SET encrypted_email = 'tampered_ciphertext_token' WHERE id = 1")
        conn.commit()
        conn.close()

        result = ledger.verify_chain()
        print(f"         verify_chain() response: {result}")
        assert result["is_valid"] is False
        assert result["error_type"] == "ROW_TAMPERED"
        print("         SUCCESS: Identity swap caught by v3.2 USER_HASHED column binding.")

        # Revert email change
        with database.WriteSession.begin() as db:
            u_restore = db.get(User, 1)
            u_restore.encrypted_email = encrypt_field("whistleblower@ngo.org", "PII", "users.email")
        assert ledger.verify_chain()["is_valid"] is True

        # 6. Tamper Simulation 3: Ghost Row Injection (GHOST_ROW)
        print("\n[Step 6] Simulating Direct SQL Row Insertion (Attack 3 — Ghost Row)...")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO relief_funds (
                worker_id, amount_cents, currency, category,
                encrypted_recipient_name, encrypted_destination, status, created_at, updated_at
            ) VALUES (1, 100000, 'USD', 'cash', 'enc_name', 'enc_dest', 'pending', '2026-10-26T00:00:00Z', '2026-10-26T00:00:00Z')
        """)
        conn.commit()
        conn.close()

        result = ledger.verify_chain()
        print(f"         verify_chain() response: {result}")
        assert result["is_valid"] is False
        assert result["error_type"] == "GHOST_ROW"
        print("         SUCCESS: Unrecorded ghost row caught by reverse row->block check.")

        # Clean up ghost row
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM relief_funds WHERE id = 1")
        conn.commit()
        conn.close()
        assert ledger.verify_chain()["is_valid"] is True

        # 7. Tamper Simulation 4: Chain Truncation / Rollback (TAIL_TRUNCATED)
        print("\n[Step 7] Simulating DB Rollback / Block Deletion (Attack 4 — Tail Truncation)...")
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM master_ledger WHERE id = 2")
        conn.commit()
        conn.close()

        result = ledger.verify_chain()
        print(f"         verify_chain() response: {result}")
        assert result["is_valid"] is False
        assert result["error_type"] == "TAIL_TRUNCATED"
        print("         SUCCESS: Chain rollback caught by external immutability anchor.")

        # 8. Tamper Simulation 5: Corrupted Anchor File (ANCHOR_MALFORMED)
        print("\n[Step 8] Simulating Corrupted Anchor File in Object Store (Attack 5)...")
        anchor_file = os.path.join(blob_dir, "anchors", "0000000001.json")
        with open(anchor_file, "wb") as f:
            f.write(b"NOT_VALID_JSON_BINARY_GARBAGE")

        result = ledger.verify_chain()
        print(f"         verify_chain() response: {result}")
        assert result["is_valid"] is False
        assert result["error_type"] == "ANCHOR_MALFORMED"
        print("         SUCCESS: Corrupted anchor safely returns ANCHOR_MALFORMED (no 500 crash).")

        print("\n==================================================================")
        print("✅ ALL DAY 2 LEDGER AND VERIFICATION AUDIT TESTS PASSED!")
        print("==================================================================")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_ledger_tests()
