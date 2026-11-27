"""Run: uvicorn backend.main:app   (single worker is fine; SQLite handles cross-process locking)"""
from starlette.middleware.sessions import SessionMiddleware

from . import api, database, ledger, oauth
from .config import settings
from .stores import LocalStore, S3Store

settings.validate()
database.init()
ledger.store = LocalStore(settings.BLOB_DIR) if settings.BLOB_DIR else S3Store(settings.S3_BUCKET)
ledger.ensure_genesis()
app = api.create_app()
app.add_middleware(SessionMiddleware, secret_key=settings.APP_SECRET, https_only=settings.COOKIE_SECURE, same_site="lax", max_age=600)  # OAuth state only
app.include_router(oauth.router)
api.mount_ui(app)  # last: a mount at "/" catches everything registered after it
