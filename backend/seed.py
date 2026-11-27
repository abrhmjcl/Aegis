"""Demo data: python -m backend.seed   (creates one user per role, all active, NO 2FA secrets; use real Google login or tests)."""
from . import auth, database, ledger
from .main import settings  # noqa: F401  (runs init + validate)


def seed_demo():
    """Demo accounts are not allow-listed, so they queue as pending sign-ups and are approved here with their role."""
    from sqlalchemy import select
    from .crypto import decrypt_field
    from .models import PendingSignup

    for role in ("whistleblower", "relief_worker", "hr_auditor", "admin"):
        try:
            auth.login_upsert(f"demo-{role}", f"{role}@demo.local", True, None, role.title())
        except PermissionError:
            pass
    with database.ReadSession() as db:
        pend = [(p.id, decrypt_field(p.encrypted_email, "PII", "pending_signups.email")) for p in db.execute(select(PendingSignup)).scalars()]
    for pid, email in pend:
        auth.approve_signup(None, pid, email.split("@")[0])


if __name__ == "__main__":
    seed_demo()
    print(ledger.verify_chain())
