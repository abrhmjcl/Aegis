import base64, os, sys, pathlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

b64 = lambda: base64.urlsafe_b64encode(os.urandom(32)).decode()
os.environ.update(  # generated per run, never committed; must be set BEFORE backend is imported
    JWT_SECRET=os.urandom(32).hex(), APP_SECRET=os.urandom(32).hex(), AES_PII_KEY_B64=b64(), AES_EVIDENCE_KEY_B64=b64(), HMAC_KEY_B64=b64(),
    ED25519_PRIVATE_KEY_HEX=Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
    INITIAL_ADMIN_EMAIL="boss@example.org", ALLOWED_EMAILS="ok@example.org", ALLOWED_DOMAIN="ngo.org", COOKIE_SECURE="0",
    MAX_UPLOAD_BYTES=str(2 * 1024 * 1024),
)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from backend import database, decoy, ledger
from backend.stores import LocalStore


@pytest.fixture
def env(tmp_path):
    database.init(f"sqlite:///{tmp_path}/t.db")
    ledger.store = LocalStore(tmp_path / "objs")
    ledger.ensure_genesis()
    decoy.STATE.clear()  # decoy state is keyed by user id, and ids repeat in every fresh test DB
    return tmp_path
