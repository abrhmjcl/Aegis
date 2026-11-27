"""All configuration comes from environment variables (see .env.example)."""
import base64
import os


def _csv(v: str) -> list[str]:
    return [x.strip().lower() for x in v.split(",") if x.strip()]


class Settings:
    def __init__(self):
        e = os.environ
        self.DATABASE_URL = e.get("DATABASE_URL", "sqlite:///./aegis.db")
        self.JWT_SECRET = e.get("JWT_SECRET", "")
        self.APP_SECRET = e.get("APP_SECRET", "")  # signs the OAuth state cookie only
        self.AES_PII_KEY_B64 = e.get("AES_PII_KEY_B64", "")
        self.AES_EVIDENCE_KEY_B64 = e.get("AES_EVIDENCE_KEY_B64", "")
        self.HMAC_KEY_B64 = e.get("HMAC_KEY_B64", "")
        self.ED25519_PRIVATE_KEY_HEX = e.get("ED25519_PRIVATE_KEY_HEX", "")
        self.ALLOWED_EMAILS = _csv(e.get("ALLOWED_EMAILS", ""))
        self.ALLOWED_DOMAIN = e.get("ALLOWED_DOMAIN", "").lower()  # compared with Google's verified `hd` claim
        self.INITIAL_ADMIN_EMAIL = e.get("INITIAL_ADMIN_EMAIL", "").lower()
        self.ALLOWED_ORIGINS = _csv(e.get("ALLOWED_ORIGINS", ""))  # e.g. https://aegis.ngo.org ; empty = Origin must equal Host
        self.MAX_PENDING_SIGNUPS = int(e.get("MAX_PENDING_SIGNUPS", 500))
        self.PENDING_TTL_DAYS = int(e.get("PENDING_TTL_DAYS", 7))  # unapproved sign-ups expire, so a flood cannot block onboarding for ever
        self.MAX_UPLOAD_BYTES = int(e.get("MAX_UPLOAD_BYTES", 25 * 1024 * 1024))
        self.UPLOAD_IDLE_SECONDS = float(e.get("UPLOAD_IDLE_SECONDS", 20))  # a client that sends nothing for this long loses its slot
        self.MAX_CONCURRENT_UPLOADS = int(e.get("MAX_CONCURRENT_UPLOADS", 4))
        self.BLOB_DIR = e.get("BLOB_DIR", "")  # local object store (dev); empty -> S3
        self.S3_BUCKET = e.get("S3_BUCKET", "")
        self.COOKIE_SECURE = e.get("COOKIE_SECURE", "1") == "1"
        self.SESSION_MINUTES = int(e.get("SESSION_MINUTES", 480))
        self.PRE_2FA_MINUTES = 5
        self.LOCK_MINUTES = 15
        self.MAX_2FA_ATTEMPTS = 3

    def validate(self):
        """Fail at start-up, not at the first request."""
        if len(self.JWT_SECRET) < 32:
            raise RuntimeError("JWT_SECRET must be at least 32 characters")
        for name in ("AES_PII_KEY_B64", "AES_EVIDENCE_KEY_B64", "HMAC_KEY_B64"):
            if len(base64.urlsafe_b64decode(getattr(self, name) or "")) != 32:
                raise RuntimeError(f"{name} must be 32 bytes, url-safe base64")
        if len(bytes.fromhex(self.ED25519_PRIVATE_KEY_HEX or "")) != 32:
            raise RuntimeError("ED25519_PRIVATE_KEY_HEX must be 32 bytes of hex")


settings = Settings()
