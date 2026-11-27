"""Tables. Timestamps are fixed-format UTC strings (no tz/format drift when hashed).
Money is integer cents (no float round-trips). Sensitive text columns are `encrypted_*`."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, Column, ForeignKey, Integer, String, Text

from .database import Base

TS = "%Y-%m-%dT%H:%M:%S.%fZ"
ROLES = ("whistleblower", "relief_worker", "hr_auditor", "admin")


def now_str() -> str:
    return datetime.now(timezone.utc).strftime(TS)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    google_sub_hmac = Column(String(64), unique=True, nullable=False)  # HMAC of Google `sub`; raw sub never stored
    encrypted_email = Column(Text, nullable=False)
    encrypted_name = Column(Text, nullable=False)
    role = Column(String(20), nullable=False, default="whistleblower")
    is_active = Column(Boolean, nullable=False, default=False)
    totp_secret_encrypted = Column(Text)
    duress_scrypt = Column(String(200))
    is_2fa_enabled = Column(Boolean, nullable=False, default=False)
    last_totp_timestep = Column(Integer, nullable=False, default=0)
    failed_2fa_attempts = Column(Integer, nullable=False, default=0)
    token_version = Column(Integer, nullable=False, default=0, server_default="0")  # bumped on logout, 2FA reset and deactivation: older tokens stop working
    locked_until = Column(String(27))
    created_at = Column(String(27), nullable=False, default=now_str)
    updated_at = Column(String(27), nullable=False, default=now_str)
    __table_args__ = (CheckConstraint("role IN ('whistleblower','relief_worker','hr_auditor','admin')"),)


class PendingSignup(Base):
    """Verified Google accounts that are not allow-listed wait here. Deliberately NOT in the ledger: anyone with a Google account can
    reach this point, and ledger blocks are permanent. Capped by MAX_PENDING_SIGNUPS. Approval creates the real user (and its block)."""
    __tablename__ = "pending_signups"
    id = Column(Integer, primary_key=True)
    google_sub_hmac = Column(String(64), unique=True, nullable=False)
    encrypted_email = Column(Text, nullable=False)
    encrypted_name = Column(Text, nullable=False)
    created_at = Column(String(27), nullable=False, default=now_str)


class MasterLedger(Base):
    __tablename__ = "master_ledger"
    id = Column(Integer, primary_key=True)
    timestamp = Column(String(27), nullable=False)
    module = Column(String(10), nullable=False)  # SYSTEM | USER | EVIDENCE | RELIEF | LAND
    action = Column(String(30), nullable=False)
    record_id = Column(Integer, nullable=False)  # 0 for SYSTEM blocks
    actor_id = Column(Integer, ForeignKey("users.id"))  # NULL for genesis / bootstrap
    record_hash = Column(String(64), nullable=False)
    data_snapshot = Column(Text, nullable=False)  # IDs and labels only, never names/places/filenames
    previous_hash = Column(String(64), nullable=False, unique=True)  # unique => the chain cannot fork
    current_hash = Column(String(64), nullable=False, unique=True)
    signature = Column(String(128), nullable=False)  # Ed25519 over current_hash


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_description = Column(Text, nullable=False)
    encrypted_location = Column(Text)
    encrypted_blob_key = Column(Text, nullable=False)
    encrypted_filename = Column(Text, nullable=False)
    raw_hmac = Column(String(64), nullable=False)  # HMAC of the bytes exactly as received
    file_hmac = Column(String(64), nullable=False)  # HMAC of the bytes after metadata scrub
    file_type = Column(String(30), nullable=False)
    padded_mb = Column(Integer, nullable=False)
    created_at = Column(String(27), nullable=False, default=now_str)


class ReliefFund(Base):
    __tablename__ = "relief_funds"
    id = Column(Integer, primary_key=True)
    worker_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount_cents = Column(Integer, nullable=False)
    currency = Column(String(3), nullable=False, default="USD")
    category = Column(String(30), nullable=False)
    encrypted_recipient_name = Column(Text, nullable=False)
    encrypted_recipient_details = Column(Text)
    encrypted_destination = Column(Text, nullable=False)
    status = Column(String(12), nullable=False, default="pending")
    delivered_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(String(27), nullable=False, default=now_str)
    updated_at = Column(String(27), nullable=False, default=now_str)
    __table_args__ = (
        CheckConstraint("amount_cents > 0"),
        CheckConstraint("currency IN ('USD','EUR','GBP')"),
        CheckConstraint("status IN ('pending','in_transit','delivered')"),
    )


class LandDeed(Base):
    __tablename__ = "land_deeds"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_owner_name = Column(Text, nullable=False)
    encrypted_location = Column(Text, nullable=False)
    area_size = Column(String(100), nullable=False)
    status = Column(String(12), nullable=False, default="pending")
    verified_by = Column(Integer, ForeignKey("users.id"))
    verified_at = Column(String(27))
    created_at = Column(String(27), nullable=False, default=now_str)
    __table_args__ = (CheckConstraint("status IN ('pending','verified','disputed','rejected')"),)


class AuditLog(Base):
    """Operational log. NOT tamper-evident (mutable, unsigned). The ledger is the tamper-evident record."""
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    role = Column(String(20))
    action = Column(String(40), nullable=False)
    endpoint = Column(String(120), nullable=False)
    status_code = Column(Integer, nullable=False)
    details = Column(Text)  # IDs only
    timestamp = Column(String(27), nullable=False, default=now_str)
