"""Tamper-evident ledger.

block.current_hash = SHA-256(canonical JSON of the block fields)     -> anyone can recompute it
block.signature    = Ed25519(current_hash)                           -> only the server's private key can create it
block.record_hash  = SHA-256(canonical JSON of EVERY stored column of the row it describes)
anchors            = signed (block_id, hash) copies kept in the object store, one immutable object per block

verify_chain() checks, inside ONE consistent read snapshot:
  1. every block links to the previous one, its hash matches its fields, its signature verifies
  2. block -> row : the newest block of each record matches the live row (edit / delete detected)
  3. row -> block : every row in every table has a block (rows inserted behind the app's back detected)
  4. anchors      : each signed anchor is still in the chain with the same hash (tail deletion / rollback detected)
"""
import hashlib
import json
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from . import database
from .config import settings
from .models import Evidence, LandDeed, MasterLedger, ReliefFund, User, now_str

log = logging.getLogger("aegis.ledger")
store = None  # object store used for anchors (set by the app / tests)

TABLES = {"USER": User, "EVIDENCE": Evidence, "RELIEF": ReliefFund, "LAND": LandDeed}
# Credentials are hashed, so swapping a TOTP secret or duress hash in the DB is detected. Excluded on purpose because they change on
# every login: last_totp_timestep, failed_2fa_attempts, locked_until, updated_at (so rolling back last_totp_timestep is NOT detected).
USER_HASHED = ("id", "google_sub_hmac", "encrypted_email", "encrypted_name", "role", "is_active", "created_at",
               "totp_secret_encrypted", "duress_scrypt", "is_2fa_enabled")


def sha(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def row_hash(module: str, row) -> str:
    cols = USER_HASHED if module == "USER" else [c.key for c in row.__table__.columns]  # all columns, none forgotten
    return sha({c: getattr(row, c) for c in cols})


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(settings.ED25519_PRIVATE_KEY_HEX))


def sign(msg: str) -> str:
    return _key().sign(msg.encode()).hex()


def verify_sig(msg: str, sig: str, public_key=None) -> bool:
    pub = public_key or _key().public_key()
    try:
        pub.verify(bytes.fromhex(sig), msg.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def _payload(b) -> dict:
    return {
        "previous_hash": b.previous_hash, "module": b.module, "action": b.action, "record_id": b.record_id,
        "actor_id": b.actor_id, "record_hash": b.record_hash, "data_snapshot": b.data_snapshot, "timestamp": b.timestamp,
    }


def append_block(db, module: str, action: str, record, actor_id, snapshot: str) -> MasterLedger:
    """Call INSIDE `with database.WriteSession.begin() as db:` (BEGIN IMMEDIATE holds the write lock).
    `record` is a new or modified ORM row (or None for SYSTEM blocks). `{id}` in `snapshot` becomes the row id.
    Snapshots may contain IDs and labels only: never names, places or filenames."""
    rid = 0
    if record is not None:
        db.add(record)
        db.flush()  # assigns the id, applies defaults, persists edits
        rid = record.id
    tip = db.execute(select(MasterLedger).order_by(MasterLedger.id.desc()).limit(1)).scalar_one_or_none()
    blk = MasterLedger(
        timestamp=now_str(), module=module, action=action, record_id=rid, actor_id=actor_id,
        record_hash=row_hash(module, record) if record is not None else sha({"module": module, "record": None}),
        data_snapshot=snapshot.format(id=rid), previous_hash=tip.current_hash if tip else "0" * 64,
    )
    blk.current_hash = sha(_payload(blk))
    blk.signature = sign(blk.current_hash)
    db.add(blk)
    db.flush()
    return blk


def ensure_genesis() -> None:
    blk = None
    with database.WriteSession.begin() as db:
        if db.execute(select(func.count(MasterLedger.id))).scalar() == 0:
            blk = append_block(db, "SYSTEM", "GENESIS", None, None, "Aegis ledger initialised")
    if blk:
        publish_anchor(blk)


def publish_anchor(blk: MasterLedger) -> None:
    """Call AFTER the transaction committed. Best effort: if it fails, the next block's anchor covers this one."""
    if store is None:
        return
    body = {"block_id": blk.id, "hash": blk.current_hash, "sig": sign(f"ANCHOR:{blk.id}:{blk.current_hash}")}
    try:
        store.put(f"anchors/{blk.id:010d}.json", json.dumps(body).encode(), once=True)
    except FileExistsError:
        pass
    except Exception:
        log.exception("anchor publish failed for block %s", blk.id)


def _bad(kind: str, block_id=None, detail: str = "") -> dict:
    return {"is_valid": False, "error_type": kind, "broken_at_block": block_id, "detail": detail}


def verify_chain() -> dict:
    with database.ReadSession() as db:  # one deferred BEGIN => one snapshot for every query below
        blocks = db.execute(select(MasterLedger).order_by(MasterLedger.id)).scalars().all()
        if not blocks:
            return _bad("EMPTY", detail="no genesis block")
        prev, newest, seen = "0" * 64, {}, {m: set() for m in TABLES}
        for b in blocks:
            if b.previous_hash != prev:
                return _bad("CHAIN_BROKEN", b.id, "previous_hash does not match the block before it")
            if sha(_payload(b)) != b.current_hash:
                return _bad("BLOCK_TAMPERED", b.id, "block fields do not match its hash")
            if not verify_sig(b.current_hash, b.signature):
                return _bad("BAD_SIGNATURE", b.id, "signature does not verify")
            prev = b.current_hash
            if b.module in TABLES:
                newest[(b.module, b.record_id)] = b
                seen[b.module].add(b.record_id)
        for (module, rid), b in newest.items():
            row = db.get(TABLES[module], rid)
            if row is None:
                return _bad("ROW_DELETED", b.id, f"{module} #{rid} has a block but no row")
            if row_hash(module, row) != b.record_hash:
                return _bad("ROW_TAMPERED", b.id, f"{module} #{rid} was changed outside the ledger")
        for module, table in TABLES.items():
            extra = set(db.execute(select(table.id)).scalars()) - seen[module]
            if extra:
                return _bad("GHOST_ROW", None, f"{module} row(s) {sorted(extra)} have no ledger block")
        by_id, checked = {b.id: b for b in blocks}, 0
        for key in store.keys("anchors/") if store else []:
            try:
                a = json.loads(store.get(key))
                a["block_id"], a["hash"], a["sig"]
            except (ValueError, KeyError, TypeError):
                return _bad("ANCHOR_MALFORMED", None, f"{key} is not a valid anchor")
            if not verify_sig(f"ANCHOR:{a['block_id']}:{a['hash']}", a["sig"]):
                return _bad("ANCHOR_SIGNATURE", None, f"{key} has an invalid signature")
            if a["block_id"] not in by_id or by_id[a["block_id"]].current_hash != a["hash"]:
                return _bad("TAIL_TRUNCATED", a["block_id"], "an anchored block is missing or was rewritten")
            checked += 1
        if store is not None and checked == 0:  # genesis is anchored at start-up, so an empty store means it was wiped or is unreachable
            return _bad("ANCHORS_UNAVAILABLE", None, "anchor store is configured but holds no anchors")
        out = {"is_valid": True, "blocks": len(blocks), "tip_block": blocks[-1].id, "tip_hash": blocks[-1].current_hash, "anchors_checked": checked}
        if store is None:
            out["warning"] = "no anchor store configured: deleting the newest blocks would not be detected"
        return out
