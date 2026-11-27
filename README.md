# Aegis v3.2 — Humanitarian Crisis & Recovery Ledger

> **A cryptographically secured logistics and reporting platform for conflict zones and natural disasters.**

Aegis is a unified, tamper-evident ledger serving NGOs, human rights auditors, and victims. It manages three core modules on a single immutable, Ed25519-signed hash chain:

| Module | Who uses it | What it records |
|---|---|---|
| **Evidence Archive** | Whistleblower | Encrypted photos/PDFs/videos with descriptions and locations |
| **Relief Tracker** | Relief Worker | Money/aid allocations, dispatch, and delivery confirmed by a *second* person |
| **Land Registry** | Whistleblower / Relief Worker submit, HR Auditor decides | Land-deed claims with a final verdict |

Every change to any module appends one **signed block** to the hash-chained ledger. An auditor can later prove — with only a public key — that nothing was edited, deleted, inserted, or rolled back.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Architecture](#architecture)
3. [5-Pillar Security Design](#5-pillar-security-design)
4. [Roles & Access Control](#roles--access-control)
5. [Database Schema](#database-schema)
6. [API Contract](#api-contract)
7. [Threat Model](#threat-model)
8. [Verification Status](#verification-status)
9. [Technology Stack](#technology-stack)
10. [Setup & Installation](#setup--installation)
11. [7-Day Build Plan](#7-day-build-plan)
12. [Build Phases Overview](#build-phases-overview)
13. [Production Checklist](#production-checklist)
14. [Known Limits & Future Work](#known-limits--future-work)

---

## How It Works

```
Browser ──HTTPS──► UploadGuard (size cap, concurrency cap)
                   └► Gate middleware: Origin check (CSRF) → decoy check → security headers → audit log
                      └► RBAC dependency: token → live user row (role, is_active) → allowed?
                         └► Handler: validate input → encrypt → write in ONE transaction + ledger block
                            └► after commit: publish signed anchor to the object store
```

### The Lifecycle of One Request

1. User authenticates via **Google OAuth2 SSO** → receives a `pre_2fa` cookie (5 min TTL).
2. User passes **TOTP 2FA** via Google Authenticator → receives a `full_access` cookie (8 h, `HttpOnly`, `SameSite=Strict`).
3. Every API request is gated: Origin/CSRF check → decoy session check → security headers → RBAC role from live DB row.
4. Handler validates input → encrypts sensitive fields with **AES-256-GCM** → writes DB row + ledger block in one atomic transaction.
5. After commit: an **Ed25519-signed anchor** is published to the object store (write-once, immutable).
6. The action is logged in `audit_logs` for accountability.

---

## Architecture

```
backend/
  config.py     env settings + start-up validation (fails fast on a bad key)
  database.py   two SQLite engines (read snapshot / write immediate), WAL
  models.py     tables; fixed-format UTC strings; integer cents
  crypto.py     AES-256-GCM (fields + padded blobs), keyed HMACs
  scrub.py      sniff + metadata strip for JPEG, PNG, MP4 (in place) and PDF (qpdf)
  stores.py     LocalStore (tested) / S3Store (MOCKED with moto, real AWS UNTESTED)
  ledger.py     hash chain, Ed25519 signatures, anchors, verify_chain
  auth.py       tokens, registration gate, 2FA, duress, admin rules
  api.py        routes, middleware, UploadGuard, header/Origin/decoy gate, mount_ui
  decoy.py      duress-session responses (mirrors the real API, in-memory state)
  oauth.py      Google sign-in (MOCKED token, real Google UNTESTED)
  main.py       wiring
  seed.py       demo users
scripts/gen_keys.py   prints fresh secrets
frontend/             index.html, app.js, style.css (static; server data only via textContent)
tests/                95 tests: core 47 · api 26 · real media 11 · integration 7 · front end 4
```

### Why Two SQLite Engines

SQLite in WAL mode lets many readers run while one writer works:

- **Read engine**: deferred `BEGIN` — every query in a session sees one consistent snapshot and never blocks writers.
- **Write engine**: `BEGIN IMMEDIATE` — takes the write lock up front. "Read the chain tip, then append" cannot interleave with another request across threads **and** processes.

**Rule:** `with database.WriteSession.begin() as db:` on a **fresh** session; never call `.begin()` on a session that already ran a query.

---

## 5-Pillar Security Design

### Pillar 1 — Tamper-Evident Ledger (Integrity)

```
block.current_hash = SHA-256( canonical JSON of: previous_hash, module, action, record_id,
                              actor_id, record_hash, data_snapshot, timestamp )
block.signature    = Ed25519( current_hash )          ← only the server key can produce this
block.record_hash  = SHA-256( canonical JSON of EVERY column of the row it describes )
anchor object      = { block_id, hash, Ed25519("ANCHOR:id:hash") }   ← one immutable object per block
```

`verify_chain()` runs inside one read snapshot and detects:

| `error_type` | Meaning |
|---|---|
| `CHAIN_BROKEN` | A block's `previous_hash` ≠ the block before it |
| `BLOCK_TAMPERED` | Block fields don't match its hash |
| `BAD_SIGNATURE` | Hash is right but the signature isn't (attacker rehashed without the key) |
| `ROW_TAMPERED` / `ROW_DELETED` | Live row differs from / is missing for its newest block |
| `GHOST_ROW` | A row exists that has no block |
| `ANCHOR_SIGNATURE` / `TAIL_TRUNCATED` | An anchor is forged, or an anchored block was removed/rewritten |
| `ANCHORS_UNAVAILABLE` | An anchor store is configured but holds no anchors (wiped or unreachable) |
| `ANCHOR_MALFORMED` | A file under `anchors/` is not a valid anchor |

Auditors need **only the public key** (printed by `scripts/gen_keys.py`).

### Pillar 2 — Encryption (Confidentiality)

| What | How |
|---|---|
| Text fields (names, descriptions, locations) | AES-256-GCM, random 12-byte nonce, **AAD = `table.column`** so a ciphertext copied to another column fails to decrypt |
| Evidence files | One AES-GCM call over `[8-byte length | file | zero padding to 1 MB multiple]`. Any flipped byte → decrypt fails. Stored size reveals only the 1 MB bucket |
| Key separation | Two key domains: `PII` and `EVIDENCE`. One leaked key does not open both |
| Blob AAD | `evidence:<random key>` so blobs can't be swapped between records |
| Google `sub` | Stored only as `HMAC(sub)` with its own key |
| File hashes | Keyed HMAC so someone holding the original can't just hash it and search the DB |

### Pillar 3 — SSO + 2FA (Authentication)

- **Google OAuth2 SSO** → verified identity → `login_upsert`.
- Existing users and allow-listed newcomers get a `pre_2fa` cookie (5 min, works **only** on 2FA endpoints).
- Non-allow-listed accounts wait in a **capped approval queue** (default 500) — no ledger block, no user row.
- **2FA verify** → `full_access` cookie (8 h). HS256, `HttpOnly`, `SameSite=Strict`, `Secure` in production.
- Role and `is_active` read from DB on **every request** — disabling a user takes effect immediately.
- Per-user **`token_version`** in JWT: bumped on logout, 2FA reset, and deactivation → invalidates all earlier tokens.

### Pillar 4 — RBAC via JWT (Authorization)

Four strict roles with live database enforcement. See [Roles & Access Control](#roles--access-control).

### Pillar 5 — Audit Trail (Accountability)

Every API request involving data access is logged in `audit_logs` with timestamp and JWT user IDs. No IP column (operational privacy). The audit log is mutable and operational — the **ledger** is the tamper-evident record.

---

## Roles & Access Control

| Role | Can do |
|---|---|
| `whistleblower` | Upload evidence, see **own** evidence, register land, see own land |
| `relief_worker` | Allocate and dispatch relief, see **own** allocations plus funds **in transit**, confirm delivery of **someone else's** allocation, register land |
| `hr_auditor` | Read all evidence/relief/land, decide land verdicts, run `verify-chain` |
| `admin` | Manage users (never themselves), reset 2FA, read audit logs, `verify-chain` |

A Google account that is not allow-listed does **not** get a user row or a ledger block. It waits in a capped approval queue; an admin approves it (creating the user and its block) or rejects it.

### 2FA and Lockout

```
FIRST (outside the write lock): if the code looks like a duress code (letters+digits)
       and matches the stored hash → clear the lock → return "decoy"  ← works even when locked

BEGIN IMMEDIATE
  UPDATE users SET failed = failed+1 (or reset if lock expired), lock at the 3rd  ← reserve attempt FIRST
  if no row updated → "locked"
  verify code:
     6 ASCII digits → TOTP, window ±1 step, step must be > last_totp_timestep, else "replay"
     anything else  → "bad"   (a wrong duress guess counts like any other failure)
  success → reset counter, store step
COMMIT
```

- Parallel guesses queue on the write lock and each one is counted.
- Lock = 15 min after 3 failures.
- A second enrolment can never overwrite an enrolled secret; only an admin reset can.

### Duress Code & Decoy Session

A user may register a duress code (6–12 letters/digits, ≥1 letter, scrypt with per-user salt). Entering it at the 2FA prompt returns the **same** response as a real login but sets `decoy=true` in the token. From then on every `/api/v1/*` request is answered by `decoy.py` **before routing**: no DB writes, no object store, no ledger, no audit entry. The decoy:

- Applies the same role rules (a whistleblower still gets 403 on admin routes)
- Returns the same JSON shapes, 404 for unknown ids, 422 for bad paging/JSON, 415 for unsupported uploads
- Keeps a small per-user in-memory state (capped at 100 items per kind)
- Shows the user only their own record on `/system/users`, and a fixed one-block chain on `verify-chain`

### Upload Pipeline

1. **UploadGuard** (before any slot is taken): no valid session cookie → 401; `Content-Length` > cap → 413; chunked bytes counted → 413; idle for `UPLOAD_IDLE_SECONDS` → 408; all slots busy → 503.
2. Read ≤ cap+1 bytes; empty → 400; over cap → 413.
3. **Sniff magic bytes** (client `Content-Type` and filename ignored): JPEG, PNG, PDF, MP4 only → else 415.
4. **Scrub** by type; malformed → 422 (never stored).
5. Compute HMACs, encrypt, write blob (`once=True`), write DB row + ledger block in one transaction, publish anchor.

### Metadata Scrubbing

| Format | What's removed | What's kept | Limits |
|---|---|---|---|
| **JPEG** | EXIF, XMP, IPTC (APP1–APP15), comments, JFXX, any APP0 beyond JFIF, reserved JPGn, everything after EOI | ICC profile, Adobe flag, plain 16-byte JFIF header, pixels untouched | 100K segment cap |
| **PNG** | Text/EXIF/time chunks, everything after IEND | Rendering chunks (CRC valid), pixels untouched | 100K chunk cap |
| **MP4** | `udta`/`meta`/`uuid` boxes (overwritten with same-size `free`), creation/modification times zeroed | Audio/video frames identical, file size unchanged | GPS **tracks** NOT removed; 100K box cap |
| **PDF** | Info dictionary, XMP, page/image metadata, old incremental revisions | Text content, encrypted PDFs rejected | Attachments/JS NOT removed; relies on qpdf |

### Web Hardening

- Origin must match `ALLOWED_ORIGINS` (or Host if empty) on every write
- Security headers: CSP `default-src 'self'`, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, HSTS
- `Cache-Control: no-store` on the API
- `/docs` and OpenAPI disabled (404)
- Downloads: `attachment` only with `CSP: sandbox`
- Frontend: `textContent` only (never `innerHTML`)
- CSV export: formula injection defense (cells starting `= + - @ \t \r` get leading `'`)

---

## Database Schema

| Table | Columns (✱ = encrypted) | Key Constraints |
|---|---|---|
| `users` | id, google_sub_hmac, ✱email, ✱name, role, is_active, ✱totp_secret, duress_scrypt, is_2fa_enabled, last_totp_timestep, failed_2fa_attempts, locked_until, token_version, created_at, updated_at | `google_sub_hmac` UNIQUE; role ∈ 4 roles; `is_active` default **false** |
| `master_ledger` | id, timestamp, module, action, record_id, actor_id, record_hash, data_snapshot, previous_hash, current_hash, signature | `previous_hash` UNIQUE, `current_hash` UNIQUE |
| `evidence` | id, uploader_id, ✱description, ✱location, ✱blob_key, ✱filename, raw_hmac, file_hmac, file_type, padded_mb, created_at | FK uploader |
| `relief_funds` | id, worker_id, amount_cents, currency, category, ✱recipient_name, ✱recipient_details, ✱destination, status, delivered_by, created_at, updated_at | `amount_cents > 0`; currency ∈ USD/EUR/GBP; status ∈ pending/in_transit/delivered |
| `land_deeds` | id, owner_id, ✱owner_name, ✱location, area_size, status, verified_by, verified_at, created_at | status ∈ pending/verified/disputed/rejected |
| `pending_signups` | id, google_sub_hmac, ✱email, ✱name, created_at | `google_sub_hmac` UNIQUE; capped (`MAX_PENDING_SIGNUPS`); **not** in the ledger |
| `audit_logs` | id, user_id, role, action, endpoint, status_code, details, timestamp | No IP, IDs only |

- Timestamps: fixed-format UTC strings `YYYY-MM-DDTHH:MM:SS.ffffffZ` (no format drift when hashed).
- Money: integer cents with `CHECK > 0`.
- Role, activation, 2FA and credential changes are signed ledger blocks.
- Login counters, `locked_until` and `last_totp_timestep` are deliberately **not** part of the user hash.

---

## API Contract

Base path: `/api/v1`. Auth = cookie `aegis`. Every write needs `Origin` matching `Host`.
List endpoints take `limit` (1–100, default 50) and `offset` (≥ 0).

Common errors: `401` not logged in / wrong scope / inactive · `403` wrong role or bad Origin · `404` not found *or not yours* · `422` validation · `413` too large · `503` upload slots busy · `408` upload stalled · `401 "session revoked"` after logout/reset.

### Auth

| Method & Path | Scope/Role | Input | Success Output | Errors |
|---|---|---|---|---|
| `POST /auth/2fa/setup` | pre_2fa | – | `{secret, otpauth_uri}` | 409 already enabled |
| `POST /auth/2fa/verify` | pre_2fa | `{code}` | `{status:"ok"}` + sets full_access cookie (**identical for duress**) | 401 bad/replayed · 423 locked · 409 not set up |
| `PUT /auth/duress` | any role | `{code}` 6–12 alnum, ≥1 letter | `{status:"ok"}` | 422 |
| `POST /auth/logout` | – | – | `{status:"ok"}`, cookie cleared, **all tokens revoked** | – |
| `GET /auth/me` | any role | – | `{id, role}` | 401 |
| `GET /login`, `GET /auth/callback` | – | Google flow | redirect, sets pre_2fa cookie | 403 / 503 |

### Evidence

| Method & Path | Role | Input | Output |
|---|---|---|---|
| `POST /evidence/upload` | whistleblower | multipart: `file`, `description` (≤2000), `location` (≤200) | `201 {id, file_type, file_hmac, ledger_block, ledger_hash, metadata_scrubbed}` |
| `GET /evidence/list` | whistleblower (own), hr_auditor, admin | paging | `{items, limit, offset}` |
| `GET /evidence/{id}` | same | – | one item (404 if not visible) |
| `GET /evidence/{id}/download` | same | – | decrypted bytes, `attachment`, `X-File-HMAC` |

### Relief

| Method & Path | Role | Input | Output |
|---|---|---|---|
| `POST /relief/allocate` | relief_worker | `{amount_cents, currency, category, recipient_name, recipient_details?, destination}` | `201 {id, status:"pending", ledger_block}` |
| `GET /relief/ledger` | relief_worker (own + in transit), hr_auditor, admin | paging | items with decrypted PII |
| `PUT /relief/{id}/status` | relief_worker | `{status: "in_transit"\|"delivered"}` | `{id, status, ledger_block}` · 403/404/409 |

### Land

| Method & Path | Role | Input | Output |
|---|---|---|---|
| `POST /land/register` | whistleblower, relief_worker | `{owner_name, location, area_size}` | `201 {id, status:"pending", ledger_block}` |
| `GET /land/list`, `GET /land/{id}` | submitters (own), hr_auditor, admin | paging | items with decrypted PII |
| `PUT /land/verify/{id}` | hr_auditor | `{status: "verified"\|"disputed"\|"rejected"}` | `{id, status, ledger_block}` · 409 if decided |

### System

| Method & Path | Role | Input | Output |
|---|---|---|---|
| `GET /system/verify-chain` | hr_auditor, admin | – | `{is_valid, blocks, tip_block, tip_hash, anchors_checked, warning?}` or error details |
| `GET /system/users` | admin | paging | users with decrypted email/name |
| `GET /system/signups` | admin | paging | pending approvals |
| `POST /system/signups/{id}/approve` | admin | `{role?}` | `201 {id, role}` |
| `POST /system/signups/{id}/reject` | admin | – | `{status:"ok"}` |
| `PUT /system/users/{id}/role` | admin | `{role}` | `{status:"ok"}` · 409 self/last-admin |
| `PUT /system/users/{id}/status` | admin | `{is_active}` | same |
| `POST /system/users/{id}/reset-2fa` | admin | – | same |
| `GET /system/audit-logs` | admin | paging | log rows |
| `GET /system/audit-logs/csv` | admin | paging | CSV (formula-escaped) |

---

## Threat Model

**Scope tiers (decided on purpose):**

| Tier | Meaning | Items |
|---|---|---|
| **1 — must work** | The 7-day build | Signed hash-chain ledger + anchors · encrypted evidence · RBAC · 2FA with lockout · metadata scrub · decoy gate · admin controls · tests |
| **2 — only if time remains** | Nice to have | Duress code as a decoy *view* (built) · relief two-person rule (built) · land finality (built) |
| **3 — future work, NOT features** | Documented, not promised | Anonymous/Tor intake, multi-party quorums, HSM/KMS signing, dead-man's switch, mesh sync, zero-knowledge proofs, post-quantum signatures |

**Who we defend against, and who we do not:**

| Attacker | Defended? | How / Why not |
|---|---|---|
| Random internet user | ✅ Yes | OAuth + allow-list + approval queue, RBAC, input validation, upload caps |
| Logged-in low-privilege user | ✅ Yes | Role read live from DB, own-records-only queries, 404 not 403 on others' IDs |
| Someone who steals the database file | ✅ Mostly | PII/evidence encrypted (AES-256-GCM); ledger edits detected. *Can* see row counts, timestamps, role |
| Someone who edits the DB directly (SQL) | ⚠️ Detected | `verify-chain` flags edits, deletes, ghost rows, tail truncation (needs anchors) |
| Someone who steals the object store | ✅ Yes for blobs | Blobs are ciphertext padded to 1 MB buckets |
| Abusive uploader | ✅ Yes | 413 on size, 503 when busy |
| Coerced user ("unlock it now") | ⚠️ Partly | Duress code opens a decoy workspace. A forensic examiner may still tell them apart |
| **Server fully compromised (code + keys)** | ❌ No | Attacker with signing key can forge a chain. Mitigation = HSM/KMS (Tier 3) |
| **Malicious admin** | ❌ No | Admin can read all decrypted PII. Mitigation = two-admin approval (Tier 3) |
| Network-level observer / ISP | ❌ No | Aegis is not anonymous. Tor intake is Tier 3 |
| Nation-state targeting users | ❌ No | Out of scope |

---

## Verification Status

| Area | Status | Evidence |
|---|---|---|
| Ledger (chain, signatures, anchors, ghost/deleted/edited rows, credential swap, wiped anchors, concurrency) | **Tested** | `test_core.py` |
| Auth (gates, approval queue + expiry, 2FA, replay, lockout, parallel guesses, duress, revocable sessions, admin rules) | **Tested** | `test_core.py`, `test_api.py` |
| Crypto, scrubbers (hand-built **and** tool-made files), part caps, LocalStore | **Tested** | `test_core.py`, `test_realmedia.py` |
| API (RBAC, upload round-trip, size/stall limits, relief, land, decoy parity ~46 probes, CSRF, headers, pagination, CSV, signup queue) | **Tested** | `test_api.py` |
| Real HTTP through a Host-rewriting proxy | **Tested** | `test_integration.py` |
| Front end (no unsafe HTML APIs, no inline code, real Chromium flow, decoy, XSS payload) | **Tested** | `test_frontend.py` |
| `S3Store` | **MOCKED** (moto) | Real AWS, Object Lock, IAM are **UNTESTED** |
| Google sign-in | **MOCKED** token | Real Google flow and `hd` claim are **UNTESTED** |
| Scrubbers on real phone footage | **Not tested** | Only ffmpeg/PIL/reportlab/LibreOffice stand-ins |
| Video timed-metadata (GPS) tracks, PDF attachments/JS | **Not removed** | One test pins the video-track gap |
| Load test, penetration test, third-party audit | **Not done** | Independent *code* review was done on frozen v3.1 |

---

## Technology Stack

### Backend
| Component | Technology |
|---|---|
| Framework | FastAPI (Python) |
| Database | SQLAlchemy + SQLite (WAL mode, dual-engine) |
| Cloud Storage | AWS S3 (via boto3) / LocalStore for development |
| Authentication | Authlib (Google OAuth2), PyOTP (TOTP 2FA), Python-JOSE (JWT HS256) |
| Cryptography | `cryptography` (AES-256-GCM), `hashlib` (SHA-256), Ed25519 signatures, scrypt, keyed HMACs |
| Metadata Scrubbing | Byte-level (JPEG/PNG/MP4), pikepdf/qpdf (PDF) |
| Server | Uvicorn |
| Python Version | 3.13 (tested) |

### Frontend
| Component | Technology |
|---|---|
| Markup | HTML5 (minimal shell) |
| Styling | CSS3 (custom properties, native dark mode) |
| Logic | Vanilla JavaScript (Fetch API, `textContent` only — zero `innerHTML`) |
| Dependencies | **None** (zero npm, zero build step, zero supply-chain attack surface) |

### Testing
| Component | Technology |
|---|---|
| Framework | pytest (95 tests across 5 files) |
| Browser Testing | Playwright (headless Chromium) |
| AWS Mock | moto |
| Media Tools | ffmpeg, Pillow, reportlab, LibreOffice, pikepdf |

---

## Setup & Installation

### Prerequisites

- Python 3.13+
- qpdf (for PDF scrubbing)
- A Google Cloud project with OAuth2 credentials (for production SSO)

### Quick Start

```bash
# 1. Clone and set up virtual environment
git clone <your-repo-url>
cd aegis
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate cryptographic keys (NEVER commit these)
python scripts/gen_keys.py > .env.keys

# 4. Configure environment
cp .env.example .env
# Paste the generated keys into .env
# Set INITIAL_ADMIN_EMAIL to your Google email
# Set Google OAuth credentials (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

# 5. Load .env into your shell (required for both seed and uvicorn) and seed demo data
# PowerShell: Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $k,$v = $_ -split '=',2; [Environment]::SetEnvironmentVariable($k.Trim(), ($v -split '\s+#',2)[0].Trim(), 'Process') }
# Bash/Zsh:   set -a && source .env && set +a
python -m backend.seed

# 6. Run the server (in the same terminal session with .env loaded)
uvicorn backend.main:app
# Serves API at /api/v1 and the web page at /
# First user with INITIAL_ADMIN_EMAIL becomes admin
```

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Install Playwright browser
playwright install chromium

# Run the full suite
pytest tests -q    # 95 passed (tests needing missing tools are skipped, not failed)
```

### Environment Variables

See `.env.example` for the full list (18 parameters). Key settings:

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Signs session cookies (HS256) |
| `APP_SECRET` | Signs the OAuth state cookie only |
| `AES_PII_KEY_B64` | Encrypts names, descriptions, locations |
| `AES_EVIDENCE_KEY_B64` | Encrypts evidence files (separate key domain) |
| `HMAC_KEY_B64` | Keyed HMACs for file hashes and Google sub |
| `ED25519_PRIVATE_KEY_HEX` | Signs ledger blocks and anchors |
| `INITIAL_ADMIN_EMAIL` | Bootstrap admin (only while no admin exists) |
| `ALLOWED_ORIGINS` | Required behind a reverse proxy |
| `MAX_PENDING_SIGNUPS` | Approval queue cap (default 500) |
| `PENDING_TTL_DAYS` | Queue entry expiry (default 7) |
| `UPLOAD_IDLE_SECONDS` | Stall timeout for uploads (default 20) |
| `COOKIE_SECURE` | Set to `1` for HTTPS-only cookies in production |

---

## 7-Day Build Plan

| Day | Build | Done when |
|---|---|---|
| **1** | config, database, models, crypto, stores | Key validation fails fast; field/blob round-trip tests pass |
| **2** | ledger + anchors + `verify-chain` | All tamper cases in `test_core.py` detected |
| **3** | auth: registration gate, 2FA, lockout, duress, admin rules | Replay/lockout/parallel tests pass |
| **4** | API: evidence (+ scrub), RBAC, middleware, decoy | Upload round-trip, 413/415, decoy tests pass |
| **5** | oauth + main.py + seed.py + relief + land + system routes | State-machine and finality tests pass |
| **6** | Front end (style.css + index.html + app.js) + browser testing | Manual end-to-end login → 2FA → upload → verify-chain |
| **7** | Tests (95) + polish + production checklist | Full suite green, production runbook reviewed |

---

## Build Phases Overview

The project was built incrementally across 34 phases over 7 milestones:

| Milestone | Scope | Phases |
|---|---|---|
| **Day 1** | config, database, models, crypto, stores | 0–6 |
| **Day 2** | ledger, anchors, verify-chain | 7–9 |
| **Day 3** | auth: registration gate, 2FA, lockout, duress, admin rules | 10–12 |
| **Day 4** | scrub + decoy + api (all routes + middleware) | 13–15 |
| **Day 5** | oauth, main.py, seed.py, first run, API walkthrough | 16–20 |
| **Day 6** | frontend (style.css, index.html, app.js), browser testing | 21–25 |
| **Day 7** | 95 tests (5 files), tamper demo CLI, production checklist | 26–34 |
---

## Production Checklist

- [ ] **HTTPS only**: `COOKIE_SECURE=1`
- [ ] **Allowed origins**: `ALLOWED_ORIGINS=https://your-host`
- [ ] **Reverse proxy**: Configure Nginx/Caddy with strict timeouts
- [ ] **AWS S3 Object Lock**: Compliance Mode, 10-year retention, Block Public Access
- [ ] **IAM least privilege**: `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` only — **no delete**
- [ ] **Database backups**: Separate from the signing key
- [ ] **Ed25519 public key**: Distribute out-of-band to external auditors
- [ ] **Nightly `verify-chain`**: Automated cron job
- [ ] **Auditor tip tracking**: Auditors keep their own copy of `tip_block`/`tip_hash` outside the server
- [ ] **Keep `pikepdf`/qpdf patched**: It parses untrusted PDFs
- [ ] **Orphan blob cleanup**: S3 lifecycle rule to expire orphans
- [ ] **Never commit secrets**: `.env`, `.env.keys`, signing keys in `.gitignore`

---

## Known Limits & Future Work

### What This Document Could NOT Verify

- Real Google OAuth (mocked token only)
- Real AWS S3 (mocked with moto)
- Real phone footage through scrubbers
- Penetration test of a live deployment

### Documented Gaps

- **Timed-metadata GPS tracks** in videos (GoPro, Android, iPhone) are NOT removed
- **PDF attachments and JavaScript** are NOT removed
- **Decoy indistinguishability** is partial (timing, exact 422 text, id numbering differ)
- **Logout is "everywhere"** — no per-device sessions
- **Admin can read all decrypted PII** — no two-admin approval
- **A flood within one week can fill the signup queue** — no blocklist after reject

### Future Work (Tier 3 — Not Promised)

Anonymous/Tor intake · multi-party quorums and key release · HSM/KMS signing (removes the "server key stolen" gap) · two-admin approval for sensitive admin actions · dead-man's switch · offline/mesh sync · zero-knowledge proofs · post-quantum signatures · Postgres for multi-node · per-device sessions · named delivery confirmer for relief · per-IP limits and a blocklist for sign-ups · QR code for 2FA enrolment in the UI · scrubbing of video metadata *tracks* and PDF attachments · rate-limiting duress guesses · persistent/shared decoy state · independent security audit.

---

## Review History

Aegis v3.2 underwent **five review rounds**:

1. **v3.0 → v3.1**: Self-review identifying 26 findings (all fixed, all tested)
2. **v3.1 external red team**: Independent reviewer found 7 issues (V-01 through V-07, all fixed)
3. **v3.1 → v3.2 independent review**: Fresh reviewer proved 10 more findings with scripts (F1–F10, all fixed)
4. **Edge testing**: Real MP4/JPEG/PNG/PDF, reverse proxy, mocked S3, mocked Google callback
5. **Browser testing**: Real Chromium — 2FA enrollment, XSS payload, duress session, admin workflows

All 5 review rounds and their fixes are covered in the v3.2 test suite (`tests/test_core.py`, `tests/test_api.py`, `tests/test_realmedia.py`, `tests/test_integration.py`, `tests/test_frontend.py`).

---

## License

This project was developed as an educational prototype demonstrating enterprise-grade security implementation. Use at your own risk in production — see the [threat model](#threat-model) for honest limitations.

---

> **Built with Defense in Depth.** Every layer assumes the layer above it has already been compromised.
