# Aegis — Humanitarian Crisis & Recovery Ledger

A FastAPI + SQLite (WAL) platform for conflict zones and natural disasters that records three workflows on a single Ed25519-signed hash chain:

| Module | Role | Purpose |
|---|---|---|
| **Evidence Archive** | `whistleblower` | Encrypted photo, PDF, and video uploads with scrubbed metadata |
| **Relief Tracker** | `relief_worker` | Aid/fund allocations, dispatch, and two-person delivery confirmation |
| **Land Registry** | `whistleblower` / `relief_worker` submit, `hr_auditor` decides | Land-deed claims with immutable verdict transitions |

Every state change appends a signed block to `master_ledger` and publishes an immutable anchor JSON object. An external auditor can verify the chain using only the server's Ed25519 public key.

---

## Request Flow & Architecture

```text
Browser ──► UploadGuard (pre-auth cookie, size cap, concurrency cap, stall timeout)
             └► Gate middleware (Origin CSRF check → decoy check → security headers → audit log)
                 └► RBAC dependency (JWT + live DB user check for role, is_active, token_version)
                     └► Handler (validate → AES-256-GCM encrypt → atomic DB write + ledger block)
                         └► After commit: write-once Ed25519 anchor to LocalStore / S3Store
```

```text
backend/
  config.py     env settings + fail-fast startup validation
  database.py   dual SQLite WAL engines (deferred read snapshot / BEGIN IMMEDIATE writes)
  models.py     7 SQLAlchemy tables, fixed-format UTC strings, integer cents
  crypto.py     AES-256-GCM (PII/EVIDENCE key separation, AAD binding, 1 MB blob padding), HMAC
  scrub.py      magic-byte sniff + metadata stripping for JPEG, PNG, MP4, PDF
  stores.py     LocalStore and S3Store (write-once once=True for anchors & blobs)
  ledger.py     SHA-256 hash chain, Ed25519 signatures, anchors, 4-layer verify_chain()
  auth.py       scoped JWTs, token_version revocation, allow-list/queue, 2FA, lockout, duress
  api.py        FastAPI routes, UploadGuard ASGI middleware, gate middleware, static UI mount
  decoy.py      in-memory decoy responses mirroring /api/v1/* for coerced logins
  oauth.py      Google OAuth2 login/callback router
  main.py       app wiring and genesis initialization
  seed.py       creates demo users for all 4 roles
scripts/
  gen_keys.py     generates .env cryptographic secrets and prints auditor Ed25519 public key
  demo_tamper.py  interactive CLI demonstrating SQL tamper, ghost row, rollback, and duress detection
frontend/
  index.html, style.css, app.js   vanilla JS SPA (textContent only, zero innerHTML, no build step)
tests/
  95 collected pytest items across test_core.py (47), test_api.py (26),
  test_realmedia.py (11), test_integration.py (7), test_frontend.py (4)
```

### Dual SQLite Engines

SQLite runs in WAL mode with two separate engines:

- **Read engine (`ReadSession`)**: deferred `BEGIN` gives each read session a consistent snapshot without blocking writers.
- **Write engine (`WriteSession`)**: `BEGIN IMMEDIATE` acquires the write lock up front so "read chain tip, append block" and 2FA attempt counters cannot race across threads or processes.

---

## Security Design

- **Tamper-Evident Ledger (`backend/ledger.py`):** Each block hashes canonical JSON of `(previous_hash, module, action, record_id, actor_id, record_hash, data_snapshot, timestamp)` and signs `current_hash` with Ed25519. `record_hash` hashes all column values of the target row (`USER_HASHED` for `users`, excluding mutable login counters). `verify_chain()` detects `CHAIN_BROKEN`, `BLOCK_TAMPERED`, `BAD_SIGNATURE`, `ROW_TAMPERED`, `ROW_DELETED`, `GHOST_ROW`, `ANCHOR_MALFORMED`, `ANCHOR_SIGNATURE`, `TAIL_TRUNCATED`, and `ANCHORS_UNAVAILABLE`.
- **Encryption (`backend/crypto.py`):** Two independent AES-256-GCM keys (`AES_PII_KEY_B64` and `AES_EVIDENCE_KEY_B64`). Fields bind AAD=`table.column`; blobs pack `[8-byte length | bytes | zero padding to 1 MB multiple]` with AAD=`evidence:<key>`. File hashes (`AES_EVIDENCE_KEY_B64`) and Google `sub` (`HMAC_KEY_B64`) use keyed HMACs.
- **Authentication & Access Control (`backend/auth.py`):**
  - Google OAuth2 SSO sets a 5-minute `pre_2fa` cookie; TOTP verification issues an 8-hour `full_access` cookie (`HttpOnly`, `SameSite=Strict`, `Secure` when `COOKIE_SECURE=1`).
  - Unlisted Google accounts wait in `pending_signups` (capped by `MAX_PENDING_SIGNUPS`, expiring after `PENDING_TTL_DAYS`) with no user row or ledger block until admin approval.
  - 2FA attempts are reserved atomically inside `BEGIN IMMEDIATE` before checking the TOTP code (3 failures trigger a 15-minute lock; replay of current/older timesteps is rejected via `last_totp_timestep`).
  - Logout, 2FA reset, and deactivation increment `token_version` to revoke older JWTs immediately.
- **Duress Mode (`backend/decoy.py`):** Users can set an alphanumeric duress code (6–12 chars, at least 1 letter — disjoint from 6-digit TOTP). Entering it at 2FA clears any lock and issues a `decoy=true` session served entirely by in-memory `decoy.py` before routing (no DB writes, blobs, ledger blocks, or audit logs).
- **Upload & Metadata Scrubbing (`backend/scrub.py`, `backend/api.py`):** `UploadGuard` enforces valid auth, size caps (`MAX_UPLOAD_BYTES`), stall timeouts (`UPLOAD_IDLE_SECONDS`), and concurrency caps (`MAX_CONCURRENT_UPLOADS`) before buffering uploads. Files are sniffed by magic bytes (`JPEG`, `PNG`, `PDF`, `MP4`) and stripped before encryption:
  - **JPEG:** drops EXIF/XMP/IPTC/comments/trailers while keeping JFIF, ICC, Adobe flag, and untouched pixels (100K segment cap).
  - **PNG:** drops text/time/EXIF chunks and trailing bytes while keeping rendering chunks intact (100K chunk cap).
  - **MP4:** overwrites `udta`/`meta`/`uuid` boxes in place with `free` boxes and zeroes timestamps (100K box cap).
  - **PDF:** rewrites via `pikepdf`/`qpdf` to drop Info dictionary, XMP, and old incremental revisions.
- **Web Hardening:** Strict `Origin` validation on writes, `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS, `Cache-Control: no-store` on `/api/v1/*`, `/docs` disabled (`404`), `attachment` + `CSP: sandbox` on downloads, formula-escaped CSV export, and `textContent`-only DOM updates.

---

## Roles & Database Schema

| Role | Permissions |
|---|---|
| `whistleblower` | Upload/view own evidence, register/view own land deeds |
| `relief_worker` | Allocate/dispatch relief, view own + `in_transit` relief, confirm delivery of someone else's allocation, register/view own land |
| `hr_auditor` | Read all evidence/relief/land, decide land verdicts, run `verify-chain` |
| `admin` | Approve/reject pending sign-ups, manage other users (cannot self-modify or deactivate last active admin), read audit logs, run `verify-chain` |

Core tables (`backend/models.py`, `✱` = AES-256-GCM encrypted):
- `users`: `id`, `google_sub_hmac`, `✱email`, `✱name`, `role`, `is_active`, `✱totp_secret`, `duress_scrypt`, `is_2fa_enabled`, `last_totp_timestep`, `failed_2fa_attempts`, `locked_until`, `token_version`, `created_at`, `updated_at`
- `master_ledger`: `id`, `timestamp`, `module`, `action`, `record_id`, `actor_id`, `record_hash`, `data_snapshot`, `previous_hash`, `current_hash`, `signature`
- `evidence`: `id`, `uploader_id`, `✱description`, `✱location`, `✱blob_key`, `✱filename`, `raw_hmac`, `file_hmac`, `file_type`, `padded_mb`, `created_at`
- `relief_funds`: `id`, `worker_id`, `amount_cents`, `currency`, `category`, `✱recipient_name`, `✱recipient_details`, `✱destination`, `status`, `delivered_by`, `created_at`, `updated_at`
- `land_deeds`: `id`, `owner_id`, `✱owner_name`, `✱location`, `area_size`, `status`, `verified_by`, `verified_at`, `created_at`
- `pending_signups`: `id`, `google_sub_hmac`, `✱email`, `✱name`, `created_at`
- `audit_logs`: `id`, `user_id`, `role`, `action`, `endpoint`, `status_code`, `details`, `timestamp` (IDs only, no IP column)

---

## API Endpoints

Base API prefix: `/api/v1` (cookie auth: `aegis`; list endpoints support `limit` 1–100 and `offset` ≥ 0; write endpoints require matching `Origin`).

| Area | Endpoints |
|---|---|
| **Auth** | `GET /login`, `GET /auth/callback`, `POST /api/v1/auth/2fa/setup`, `POST /api/v1/auth/2fa/verify`, `PUT /api/v1/auth/duress`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` |
| **Evidence** | `POST /api/v1/evidence/upload`, `GET /api/v1/evidence/list`, `GET /api/v1/evidence/{id}`, `GET /api/v1/evidence/{id}/download` |
| **Relief** | `POST /api/v1/relief/allocate`, `GET /api/v1/relief/ledger`, `PUT /api/v1/relief/{id}/status` |
| **Land** | `POST /api/v1/land/register`, `GET /api/v1/land/list`, `GET /api/v1/land/{id}`, `PUT /api/v1/land/verify/{id}` |
| **System** | `GET /api/v1/system/verify-chain`, `GET /api/v1/system/users`, `GET /api/v1/system/signups`, `POST /api/v1/system/signups/{id}/approve`, `POST /api/v1/system/signups/{id}/reject`, `PUT /api/v1/system/users/{id}/role`, `PUT /api/v1/system/users/{id}/status`, `POST /api/v1/system/users/{id}/reset-2fa`, `GET /api/v1/system/audit-logs`, `GET /api/v1/system/audit-logs/csv` |

---

## Threat Model

| Scenario | Status | Notes |
|---|---|---|
| Unauthenticated / unauthorized user | **Blocked** | OAuth + allow-list/approval queue, live DB role check, `404` on other users' records |
| Direct SQLite row edits, deletes, ghost rows | **Detected** | `verify_chain()` checks hashes, Ed25519 signatures, row bindings, and external anchors |
| Stolen database or blob store | **Mostly protected** | PII and blobs encrypted with separate keys; metadata counts/timestamps/roles remain visible |
| Upload abuse / slowloris stalls | **Blocked** | `UploadGuard` caps size, concurrency, and idle time before slot allocation |
| Coerced login under duress | **Partial** | Duress code opens an isolated in-memory decoy view; forensic timing/detail parity is partial |
| Compromised server (code + keys) | **Out of scope** | An attacker holding the Ed25519 signing key can forge valid blocks |
| Malicious admin | **Out of scope** | Admins can view decrypted PII; no two-admin approval yet |
| Network observer / nation-state | **Out of scope** | Does not provide network anonymity |

---

## Technology Stack

- **Backend:** FastAPI, SQLAlchemy (SQLite WAL), Authlib (Google OAuth2), PyJWT (HS256), PyOTP, `cryptography` (AES-256-GCM, Ed25519, scrypt, HMAC), `pikepdf`/`qpdf`, `boto3`, Uvicorn
- **Frontend:** HTML5, CSS3, Vanilla JS (`Fetch API`, `textContent`)
- **Testing:** `pytest` (95 collected items across 5 files), `moto`, Playwright (Chromium), Pillow, ReportLab
- **Python:** 3.13+ (also verified on Python 3.14)

---

## Setup & Running Locally

### 1. Install Dependencies

```bash
git clone https://github.com/abrhmjcl/Aegis.git
cd Aegis
python -m venv .venv
```

Activate the virtual environment:

```powershell
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)

`.env.example` documents all 21 parameters (`DATABASE_URL`, keys, OAuth credentials, upload/queue limits). Generate fresh keys and copy the template:

```bash
python scripts/gen_keys.py > .env.keys
cp .env.example .env
```

Paste the generated values into `.env`, set `INITIAL_ADMIN_EMAIL` (and `COOKIE_SECURE=0` + `BLOB_DIR=./blobs` for local HTTP development), and configure Google OAuth credentials (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `OAUTH_REDIRECT_URI`).

### 3. Seed & Run Server

`backend/config.py` reads directly from `os.environ` (no `python-dotenv` dependency), so load `.env` into your terminal session before running `seed` or `uvicorn`:

```powershell
# Windows (PowerShell)
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $k,$v = $_ -split '=',2; [Environment]::SetEnvironmentVariable($k.Trim(), ($v -split '\s+#',2)[0].Trim(), 'Process') }
python -m backend.seed
uvicorn backend.main:app
```

```bash
# macOS / Linux
set -a && source .env && set +a
python -m backend.seed
uvicorn backend.main:app
```

The app serves the UI at `http://127.0.0.1:8000/` and the API at `/api/v1`.

### 4. Run Tests & Tamper Demo

```bash
pip install -r requirements-test.txt
playwright install chromium
pytest tests -q
python scripts/demo_tamper.py
```

Note: `tests/test_realmedia.py` (11 tests) requires external CLI tools (`ffmpeg`, `ffprobe`, `pdftotext`, `libreoffice`, `qpdf`) on `PATH` and cleanly skips any test whose binary is absent. On a machine without those CLI tools, `84` tests run and pass while `11` skip.

---

## Production Checklist & Known Limitations

**Production Checklist:**
- Set `COOKIE_SECURE=1` and `ALLOWED_ORIGINS=https://your-host` behind HTTPS reverse proxy (Nginx/Caddy)
- Use `S3_BUCKET` (leave `BLOB_DIR` empty) with S3 Object Lock (Compliance Mode), Block Public Access, and IAM least privilege (`s3:PutObject`, `s3:GetObject`, `s3:ListBucket` — no `DeleteObject`)
- Keep database backups separate from signing keys, distribute the Ed25519 public key out-of-band, and track `tip_block`/`tip_hash` externally

**Known Limitations:**
- Google OAuth2 and AWS S3 have only been tested against mocks (`moto` / mock tokens), not live cloud credentials
- MP4 timed-metadata GPS tracks (`gpmd`, `camm`, `mebx`) and PDF attachments/JavaScript are not stripped by `scrub.py`
- `token_version` revokes all sessions globally (no per-device logout yet)
- No rate-limiting or post-rejection blocklist on `pending_signups` (500-entry queue can fill during a sustained flood)
- No two-admin approval on sensitive admin updates yet

---

## License

Educational security prototype. Use in production at your own risk after completing live OAuth/S3 verification and independent testing.
