"""Interactive Tamper Detection, Identity Protection & Duress CLI - v3.2 Protocol."""
import base64
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_b64 = lambda: base64.urlsafe_b64encode(os.urandom(32)).decode()
os.environ.update(
    JWT_SECRET=os.urandom(32).hex(),
    APP_SECRET=os.urandom(32).hex(),
    AES_PII_KEY_B64=_b64(),
    AES_EVIDENCE_KEY_B64=_b64(),
    HMAC_KEY_B64=_b64(),
    ED25519_PRIVATE_KEY_HEX=Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex(),
    INITIAL_ADMIN_EMAIL="boss@example.org",
    ALLOWED_EMAILS="ok@example.org",
    COOKIE_SECURE="0",
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import auth, database, ledger
from backend.stores import LocalStore


def print_banner(text: str) -> None:
    print("\n" + "=" * 65)
    print(f" {text}")
    print("=" * 65)


def run_demo() -> None:
    print_banner("AEGIS v3.2 LIVE TAMPERING & DURESS DEMONSTRATION")
    temp_dir = tempfile.mkdtemp(prefix="aegis_demo_v32_")
    db_path = os.path.join(temp_dir, "demo.db")
    blob_dir = os.path.join(temp_dir, "blobs")

    try:
        print("[STAGE 1/6] Initializing Clean Ledger Baseline...")
        database.init(f"sqlite:///{db_path}")
        ledger.store = LocalStore(blob_dir)
        ledger.ensure_genesis()

        admin = auth.login_upsert("admin-sub", "boss@example.org", True, None, "Admin Boss")
        auth.begin_2fa_setup(admin.id)
        w = auth.login_upsert("demo-user", "ok@example.org", True, None, "Ahmad Whistle")
        auth.begin_2fa_setup(w.id)

        report = ledger.verify_chain()
        assert report["is_valid"] is True, report
        print(f"  [+] Genesis & Users Registered. Total Blocks: {report['blocks']}")
        print(f"  [+] Chain Status: VALID (Anchors Verified: {report['anchors_checked']})")

        print_banner("STAGE 2/6: Direct SQLite Database Tampering (ROW_TAMPERED)")
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE users SET role = 'admin' WHERE id = 2")
            conn.commit()
        report = ledger.verify_chain()
        print(f"  [!] Caught: {report['error_type']} | {report['detail']}")
        assert report["error_type"] == "ROW_TAMPERED"
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE users SET role = 'whistleblower' WHERE id = 2")
            conn.commit()

        print_banner("STAGE 3/6: Identity Swap Attack (v3.2 F2 Fix Verification)")
        with sqlite3.connect(db_path) as conn:
            orig_email, orig_name = conn.execute(
                "SELECT encrypted_email, encrypted_name FROM users WHERE id = 2"
            ).fetchone()
            conn.execute(
                "UPDATE users SET encrypted_email = (SELECT encrypted_email FROM users WHERE id = 1), "
                "encrypted_name = (SELECT encrypted_name FROM users WHERE id = 1) WHERE id = 2"
            )
            conn.commit()
        report = ledger.verify_chain()
        print(f"  [!] Caught: {report['error_type']} | {report['detail']}")
        assert report["error_type"] == "ROW_TAMPERED" and "USER #2" in report["detail"]
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE users SET encrypted_email = ?, encrypted_name = ? WHERE id = 2",
                (orig_email, orig_name),
            )
            conn.commit()

        print_banner("STAGE 4/6: Unrecorded Direct SQL Injection (GHOST_ROW)")
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO relief_funds (worker_id, amount_cents, currency, category, "
                "encrypted_recipient_name, encrypted_destination, status, created_at, updated_at) "
                "VALUES (1, 1000000, 'USD', 'cash', 'enc_ghost', 'enc_dest', 'delivered', "
                "'2026-10-19T00:00:00.000000Z', '2026-10-19T00:00:00.000000Z')"
            )
            conn.commit()
        report = ledger.verify_chain()
        print(f"  [!] Caught: {report['error_type']} | {report['detail']}")
        assert report["error_type"] == "GHOST_ROW"
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM relief_funds WHERE id = 1")
            conn.commit()

        print_banner("STAGE 5/6: Tail Truncation / Rollback Attack (TAIL_TRUNCATED)")
        with sqlite3.connect(db_path) as conn:
            tip_id = conn.execute("SELECT MAX(id) FROM master_ledger").fetchone()[0]
            # Simulate a clean DB rollback of the newest block (e.g. restoring DB backup before block #5)
            conn.execute("DELETE FROM master_ledger WHERE id = ?", (tip_id,))
            conn.execute("UPDATE users SET totp_secret_encrypted = NULL WHERE id = 2")
            conn.commit()
        report = ledger.verify_chain()
        print(f"  [!] Caught: {report['error_type']} | {report['detail']}")
        assert report["error_type"] == "TAIL_TRUNCATED"

        print_banner("STAGE 6/6: Physical Coercion & Duress Sandbox Isolation")
        database.init(f"sqlite:///{temp_dir}/duress.db")
        ledger.store = LocalStore(Path(temp_dir) / "duress_blobs")
        ledger.ensure_genesis()
        u2 = auth.login_upsert("coerced-user", "ok@example.org", True, None, "Field Officer")
        auth.begin_2fa_setup(u2.id)
        auth.set_duress_code(u2.id, "HostageAlpha")
        res = auth.verify_code(u2.id, "HostageAlpha")
        assert res == "decoy"
        _decoy_tok = auth.issue_token(u2.id, "full_access", decoy=True)
        print("  [+] Duress code returned 'decoy' and issued isolated decoy token.")

        print_banner("ALL 6 DEMONSTRATION CHECKPOINTS VERIFIED!")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_demo()
