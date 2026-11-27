"""AES-256-GCM everywhere. Two key domains (PII, EVIDENCE) so one leaked key does not open both.

Fields : nonce(12) || ciphertext, url-safe base64, AAD = "table.column" (a ciphertext moved to another column fails).
Blobs  : one AES-GCM call over [8-byte length | file | zero padding up to a 1 MB multiple], so
         - any flipped/removed/reordered byte makes decryption fail (no partial output),
         - the stored object size only reveals the 1 MB bucket.
         Files are capped (MAX_UPLOAD_BYTES), so one call is fine; no streaming code to get wrong.
"""
import base64
import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

BUCKET = 1024 * 1024


def _key(domain: str) -> bytes:
    b64 = {"PII": settings.AES_PII_KEY_B64, "EVIDENCE": settings.AES_EVIDENCE_KEY_B64}[domain]
    k = base64.urlsafe_b64decode(b64)
    if len(k) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    return k


def encrypt_field(text: str | None, domain: str, aad: str) -> str | None:
    if text is None:
        return None
    nonce = os.urandom(12)
    ct = AESGCM(_key(domain)).encrypt(nonce, text.encode(), aad.encode())
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_field(token: str | None, domain: str, aad: str) -> str | None:
    if token is None:
        return None
    raw = base64.urlsafe_b64decode(token)
    return AESGCM(_key(domain)).decrypt(raw[:12], raw[12:], aad.encode()).decode()


def encrypt_blob(data: bytes, aad: str) -> bytes:
    framed = struct.pack(">Q", len(data)) + data
    framed += b"\0" * (-len(framed) % BUCKET)  # pad up to the next 1 MB multiple
    nonce = os.urandom(12)
    return nonce + AESGCM(_key("EVIDENCE")).encrypt(nonce, framed, aad.encode())


def decrypt_blob(blob: bytes, aad: str) -> bytes:
    framed = AESGCM(_key("EVIDENCE")).decrypt(blob[:12], blob[12:], aad.encode())
    (n,) = struct.unpack(">Q", framed[:8])
    if 8 + n > len(framed):
        raise ValueError("corrupt length header")
    return framed[8 : 8 + n]


def file_hmac(data: bytes) -> str:
    """Keyed, so someone holding the original video cannot just hash it and search the database."""
    return hmac.new(_key("EVIDENCE"), data, hashlib.sha256).hexdigest()


def sub_hmac(google_sub: str) -> str:
    return hmac.new(base64.urlsafe_b64decode(settings.HMAC_KEY_B64), google_sub.encode(), hashlib.sha256).hexdigest()
