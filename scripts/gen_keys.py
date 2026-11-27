"""Prints fresh secrets for .env. Run once; store them in a secrets manager; never commit them."""
import base64, os, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

b64 = lambda: base64.urlsafe_b64encode(os.urandom(32)).decode()
k = Ed25519PrivateKey.generate()
print(f"JWT_SECRET={secrets.token_hex(32)}\nAPP_SECRET={secrets.token_hex(32)}\nAES_PII_KEY_B64={b64()}\nAES_EVIDENCE_KEY_B64={b64()}\nHMAC_KEY_B64={b64()}")
print("ED25519_PRIVATE_KEY_HEX=" + k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
print("# auditor public key (share freely): " + k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
