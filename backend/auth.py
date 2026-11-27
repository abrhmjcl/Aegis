"""Login, tokens, 2FA, duress code and admin user changes. All writes use a fresh WriteSession (see database.py)."""
import hashlib
import hmac
import os
import re
import time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from sqlalchemy import delete, func, select, text

from . import database
from .config import settings
from .crypto import decrypt_field, encrypt_field, sub_hmac
from .ledger import append_block, publish_anchor
from .models import ROLES, TS, PendingSignup, User, now_str

CRED_NOTE = "User #{id} credentials updated"
TOTP_RE = re.compile(r"[0-9]{6}")  # ASCII digits only
DURESS_RE = re.compile(r"(?=.*[A-Za-z])[A-Za-z0-9]{6,12}")  # needs a letter => can never equal a 6-digit TOTP


def _now() -> float:  # indirection so tests can fix the clock
    return time.time()


# ---------------------------------------------------------------- tokens
def issue_token(user_id: int, scope: str, decoy: bool = False) -> str:
    minutes = settings.PRE_2FA_MINUTES if scope == "pre_2fa" else settings.SESSION_MINUTES
    now = datetime.now(timezone.utc)
    with database.ReadSession() as db:
        tv = db.execute(select(User.token_version).where(User.id == user_id)).scalar() or 0
    claims = {"sub": str(user_id), "scope": scope, "decoy": decoy, "tv": tv, "iat": now, "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(claims, settings.JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"], options={"require": ["exp", "sub", "scope", "tv"]})


def revoke_sessions(user_id: int, expected_tv: int) -> bool:
    """Invalidate every token of this user. Only a token that is still valid can do it (an old stolen one cannot log the user out)."""
    with database.WriteSession.begin() as db:
        return db.execute(text("UPDATE users SET token_version = token_version + 1 WHERE id = :id AND token_version = :tv"),
                          {"id": user_id, "tv": expected_tv}).rowcount == 1


# ---------------------------------------------------------------- registration gate
def _allowed(email: str, hd: str | None) -> bool:
    e = email.lower()
    return e == settings.INITIAL_ADMIN_EMAIL or e in settings.ALLOWED_EMAILS or bool(
        settings.ALLOWED_DOMAIN and hd and hd.lower() == settings.ALLOWED_DOMAIN  # exact match on Google's `hd`, never endswith()
    )


def login_upsert(sub: str, email: str, email_verified: bool, hd: str | None, name: str) -> User:
    """Existing users are returned unchanged. Allow-listed newcomers become active users (+ ledger block).
    Everyone else is parked in pending_signups (no ledger block) and gets PermissionError until an admin approves them."""
    if not email_verified:
        raise PermissionError("email not verified")
    blk, pending = None, False
    with database.WriteSession.begin() as db:
        u = db.execute(select(User).where(User.google_sub_hmac == sub_hmac(sub))).scalar_one_or_none()
        if u is None:
            admin_exists = db.execute(select(User.id).where(User.role == "admin").limit(1)).first() is not None
            first_admin = bool(settings.INITIAL_ADMIN_EMAIL) and email.lower() == settings.INITIAL_ADMIN_EMAIL and not admin_exists
            if first_admin or _allowed(email, hd):
                db.execute(delete(PendingSignup).where(PendingSignup.google_sub_hmac == sub_hmac(sub)))  # a stale queue entry must not linger
                u = User(
                    google_sub_hmac=sub_hmac(sub), role="admin" if first_admin else "whistleblower", is_active=True,
                    encrypted_email=encrypt_field(email.lower(), "PII", "users.email"),
                    encrypted_name=encrypt_field(name, "PII", "users.name"),
                )
                blk = append_block(db, "USER", "REGISTER", u, None, f"User #{{id}} registered role={u.role}")
            else:
                pending = True
                h = sub_hmac(sub)
                cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.PENDING_TTL_DAYS)).strftime(TS)
                db.execute(delete(PendingSignup).where(PendingSignup.created_at < cutoff))
                if db.execute(select(PendingSignup.id).where(PendingSignup.google_sub_hmac == h)).first() is None:
                    if db.execute(select(func.count(PendingSignup.id))).scalar() >= settings.MAX_PENDING_SIGNUPS:
                        pending = None  # queue full; nothing is stored
                    else:
                        db.add(PendingSignup(google_sub_hmac=h, encrypted_email=encrypt_field(email.lower(), "PII", "pending_signups.email"),
                                             encrypted_name=encrypt_field(name, "PII", "pending_signups.name")))
    if pending is None:
        raise OverflowError("sign-up queue is full")
    if pending:
        raise PermissionError("account is awaiting admin approval")
    if blk:
        publish_anchor(blk)
    return u


def approve_signup(actor_id: int, pending_id: int, role: str = "whistleblower") -> User:
    if role not in ROLES:
        raise ValueError("unknown role")
    stale = False
    with database.WriteSession.begin() as db:
        p = db.get(PendingSignup, pending_id)
        if p is None:
            raise LookupError("no such sign-up")
        if db.execute(select(User.id).where(User.google_sub_hmac == p.google_sub_hmac)).first() is not None:
            db.delete(p)  # committed below; the error is raised only after the commit so the cleanup is not rolled back
            stale = True
    if stale:
        raise ValueError("this account is already registered")
    with database.WriteSession.begin() as db:
        p = db.get(PendingSignup, pending_id)
        u = User(
            google_sub_hmac=p.google_sub_hmac, role=role, is_active=True,
            encrypted_email=encrypt_field(decrypt_field(p.encrypted_email, "PII", "pending_signups.email"), "PII", "users.email"),
            encrypted_name=encrypt_field(decrypt_field(p.encrypted_name, "PII", "pending_signups.name"), "PII", "users.name"),
        )
        db.delete(p)
        blk = append_block(db, "USER", "APPROVE_SIGNUP", u, actor_id, f"User #{{id}} approved by #{actor_id} role={role}")
    publish_anchor(blk)
    return u


def reject_signup(pending_id: int) -> None:
    with database.WriteSession.begin() as db:
        p = db.get(PendingSignup, pending_id)
        if p is None:
            raise LookupError("no such sign-up")
        db.delete(p)


# ---------------------------------------------------------------- 2FA
def begin_2fa_setup(user_id: int) -> tuple[str, str]:
    with database.WriteSession.begin() as db:
        u = db.get(User, user_id)
        if u is None or not u.is_active:
            raise LookupError("inactive")
        if u.is_2fa_enabled:
            raise ValueError("2FA already enabled")  # an enrolled secret can never be overwritten; admin reset is the only way
        secret = pyotp.random_base32()
        u.totp_secret_encrypted = encrypt_field(secret, "PII", f"users.totp:{u.id}")
        blk = append_block(db, "USER", "CREDENTIAL_UPDATE", u, u.id, CRED_NOTE)
    publish_anchor(blk)
    return secret, pyotp.TOTP(secret).provisioning_uri(name=f"user{u.id}", issuer_name="Aegis")


def set_duress_code(user_id: int, code: str) -> None:
    if not DURESS_RE.fullmatch(code):
        raise ValueError("duress code must be 6-12 letters/digits and contain at least one letter")
    salt = os.urandom(16)
    digest = hashlib.scrypt(code.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    with database.WriteSession.begin() as db:
        u = db.get(User, user_id)
        u.duress_scrypt = f"{salt.hex()}${digest.hex()}"
        blk = append_block(db, "USER", "CREDENTIAL_UPDATE", u, user_id, CRED_NOTE)  # generic text: the ledger must not reveal that a duress code exists
    publish_anchor(blk)


def _duress_ok(code: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    digest = hashlib.scrypt(code.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(digest.hex(), digest_hex)


# An attempt is RESERVED (counted) before the code is checked, in the same write transaction. Parallel guesses
# therefore queue on the write lock and each one is counted; nobody can guess "in flight" past the lock.
RESERVE = text("""
UPDATE users SET
  failed_2fa_attempts = CASE WHEN locked_until IS NOT NULL AND locked_until <= :now THEN 1 ELSE failed_2fa_attempts + 1 END,
  locked_until = CASE WHEN locked_until IS NOT NULL AND locked_until <= :now THEN NULL
                      WHEN failed_2fa_attempts + 1 >= :max THEN :lock ELSE locked_until END
WHERE id = :id AND is_active = 1 AND (locked_until IS NULL OR locked_until <= :now)""")
SUCCESS = text("""
UPDATE users SET last_totp_timestep = :step, failed_2fa_attempts = 0, locked_until = NULL, is_2fa_enabled = 1, updated_at = :now
WHERE id = :id AND last_totp_timestep < :step""")
RESET = text("UPDATE users SET failed_2fa_attempts = 0, locked_until = NULL, updated_at = :now WHERE id = :id")


DUMMY_DURESS = "00" * 16 + "$" + "00" * 32  # so "has a duress code" and "has none" take the same time


def verify_code(user_id: int, code: str) -> str:
    """Returns 'ok' | 'decoy' | 'bad' | 'replay' | 'locked' | 'inactive' | 'not_setup'. Never raises on bad input."""
    if DURESS_RE.fullmatch(code):
        # Checked first and outside the write lock: a coerced user must reach the decoy even if an attacker locked the account
        # beforehand. Success clears the lock; failure falls through to the normal counted path below.
        with database.ReadSession() as rdb:
            row = rdb.execute(select(User.is_active, User.duress_scrypt).where(User.id == user_id)).first()
        if row and row.is_active and _duress_ok(code, row.duress_scrypt or DUMMY_DURESS) and row.duress_scrypt:
            with database.WriteSession.begin() as db:
                db.execute(RESET, {"now": now_str(), "id": user_id})
            return "decoy"
    now = now_str()
    lock = (datetime.now(timezone.utc) + timedelta(minutes=settings.LOCK_MINUTES)).strftime(TS)
    with database.WriteSession.begin() as db:
        if db.execute(RESERVE, {"now": now, "max": settings.MAX_2FA_ATTEMPTS, "lock": lock, "id": user_id}).rowcount != 1:
            u = db.get(User, user_id)
            return "locked" if u and u.is_active else "inactive"
        u = db.get(User, user_id)
        if not u.totp_secret_encrypted:
            return "not_setup"
        result, blk = "bad", None
        if TOTP_RE.fullmatch(code):
            totp = pyotp.TOTP(decrypt_field(u.totp_secret_encrypted, "PII", f"users.totp:{u.id}"))
            step = int(_now()) // 30
            match = next((s for s in (step - 1, step, step + 1) if hmac.compare_digest(totp.at(s * 30), code)), None)
            if match is not None:
                was_enabled = u.is_2fa_enabled
                if db.execute(SUCCESS, {"step": match, "now": now, "id": user_id}).rowcount != 1:
                    result = "replay"  # a step that was already used (or an older one) is a replay
                else:
                    result = "ok"
                    if not was_enabled:  # enrolment completes here, and is_2fa_enabled is part of the signed user hash
                        db.refresh(u)
                        blk = append_block(db, "USER", "CREDENTIAL_UPDATE", u, user_id, CRED_NOTE)
    if blk:
        publish_anchor(blk)
    return result


# ---------------------------------------------------------------- admin
def admin_update(actor_id: int | None, user_id: int, *, role: str | None = None, active: bool | None = None, reset_2fa: bool = False) -> User:
    """actor_id=None is for seeding/bootstrap only. Every change is a signed ledger block."""
    if actor_id is not None and actor_id == user_id:
        raise ValueError("an admin cannot modify their own account")
    with database.WriteSession.begin() as db:
        u = db.get(User, user_id)
        if u is None:
            raise LookupError("no such user")
        was_admin = u.role == "admin" and u.is_active
        notes = []
        if role is not None:
            if role not in ROLES:
                raise ValueError("unknown role")
            u.role = role
            notes.append(f"role={role}")
        if active is not None:
            u.is_active = active
            notes.append(f"active={active}")
            if not active:
                u.token_version += 1
        if reset_2fa:
            u.token_version += 1  # a stolen session must not survive the admin's response to it
        if reset_2fa:
            u.totp_secret_encrypted = u.duress_scrypt = u.locked_until = None
            u.is_2fa_enabled, u.last_totp_timestep, u.failed_2fa_attempts = False, 0, 0
            notes.append("2fa_reset")
        u.updated_at = now_str()
        db.flush()
        if db.execute(select(func.count(User.id)).where(User.role == "admin", User.is_active == True)).scalar() == 0 and was_admin:  # noqa: E712  (only a change that removes the last admin is refused)
            raise ValueError("this change would leave the system without an active admin")
        blk = append_block(db, "USER", "ADMIN_UPDATE", u, actor_id, f"User #{{id}} changed by #{actor_id}: {', '.join(notes)}")
    publish_anchor(blk)
    return u
