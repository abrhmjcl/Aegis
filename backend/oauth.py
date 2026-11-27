"""Google sign-in. Tested only with a MOCKED Google token exchange (test_integration.py); never run against real Google. It only turns a verified Google identity into a pre_2fa cookie;
all authorisation decisions live in auth.login_upsert (tested)."""
import os

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import auth
from .api import COOKIE, _set_cookie
from .config import settings

oauth = OAuth()
oauth.register("google", client_id=os.environ.get("GOOGLE_CLIENT_ID"), client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
               server_metadata_url="https://accounts.google.com/.well-known/openid-configuration", client_kwargs={"scope": "openid email profile"})
router = APIRouter()


@router.get("/login")
async def login(request: Request):
    return await oauth.google.authorize_redirect(request, os.environ["OAUTH_REDIRECT_URI"])  # Authlib stores/validates state + nonce in the session


@router.get("/auth/callback")
async def callback(request: Request):
    tok = await oauth.google.authorize_access_token(request)
    info = tok["userinfo"]  # ID token already verified by Authlib (signature, aud, exp, nonce)
    try:
        u = await run_in_threadpool(auth.login_upsert, info["sub"], info["email"], bool(info.get("email_verified")), info.get("hd"), info.get("name", ""))
    except PermissionError as e:  # unverified email, or parked in the approval queue
        raise HTTPException(403, str(e))
    except OverflowError:
        raise HTTPException(503, "sign-up queue is full; try again later")
    resp = RedirectResponse("/", 303)
    _set_cookie(resp, auth.issue_token(u.id, "pre_2fa"), settings.PRE_2FA_MINUTES)
    return resp
