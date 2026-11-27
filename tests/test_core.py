import sqlite3, threading, time
import pyotp, pytest
from sqlalchemy import select
from backend import auth, database, ledger
from backend.crypto import decrypt_blob, decrypt_field, encrypt_blob, encrypt_field
from backend.models import MasterLedger, PendingSignup, User
from backend.scrub import Unsupported, scrub, sniff, strip_jpeg, strip_png
from backend.stores import LocalStore


def mkuser(sub="s1", email="ok@example.org", role=None):
    u = auth.login_upsert(sub, email, True, None, "Name")
    if role:
        auth.admin_update(None, u.id, role=role)
    return u


def raw(tmp, sql, *a):
    c = sqlite3.connect(f"{tmp}/t.db"); c.execute(sql, a); c.commit(); c.close()


def test_chain_ok_and_user_block(env):
    mkuser()
    r = ledger.verify_chain()
    assert r["is_valid"] and r["blocks"] == 2 and r["anchors_checked"] == 2


def test_gates(env):
    with pytest.raises(PermissionError):
        auth.login_upsert("x", "a@b.c", False, None, "n")
    for sub, email, hd in (("a", "rand@gmail.com", None), ("b", "x@evil-ngo.org", "evil-ngo.org")):
        with pytest.raises(PermissionError):  # parked, not created
            auth.login_upsert(sub, email, True, hd, "n")
    assert auth.login_upsert("c", "x@ngo.org", True, "ngo.org", "n").is_active
    adm = auth.login_upsert("d", "boss@example.org", True, None, "n")
    assert adm.role == "admin"
    assert auth.login_upsert("e", "boss@example.org", True, None, "n").role == "whistleblower"  # only the first
    assert ledger.verify_chain()["blocks"] == 4  # genesis + c + d + e: the two parked sign-ups left no block and no user


def test_v05_flooding_does_not_grow_ledger_and_is_capped(env, monkeypatch):
    monkeypatch.setattr(auth.settings, "MAX_PENDING_SIGNUPS", 3)
    before = ledger.verify_chain()["blocks"]
    for i in range(3):
        for _ in range(2):  # repeat sign-ins of the same account are idempotent
            with pytest.raises(PermissionError): auth.login_upsert(f"f{i}", f"f{i}@gmail.com", True, None, "n")
    with pytest.raises(OverflowError): auth.login_upsert("f9", "f9@gmail.com", True, None, "n")
    r = ledger.verify_chain()
    assert r["is_valid"] and r["blocks"] == before


def test_v05_admin_approval_creates_user_and_block(env):
    ad = auth.login_upsert("a", "boss@example.org", True, None, "n")
    with pytest.raises(PermissionError): auth.login_upsert("p", "new@gmail.com", True, None, "Newbie")
    with database.ReadSession() as db:
        pid = db.execute(select(PendingSignup.id)).scalar_one()
    u = auth.approve_signup(ad.id, pid, "relief_worker")
    assert u.is_active and u.role == "relief_worker" and decrypt_field(u.encrypted_email, "PII", "users.email") == "new@gmail.com"
    assert auth.login_upsert("p", "new@gmail.com", True, None, "n").id == u.id  # now an ordinary existing user
    with pytest.raises(LookupError): auth.approve_signup(ad.id, pid)
    assert ledger.verify_chain()["is_valid"]


@pytest.mark.parametrize("sql", [
    "UPDATE master_ledger SET data_snapshot='x' WHERE id=2",
    "UPDATE users SET role='admin' WHERE id=1",
    "UPDATE users SET is_active=0 WHERE id=1",
    "DELETE FROM users WHERE id=1",
    "DELETE FROM master_ledger WHERE id=1",
])
def test_tamper_detected(env, sql):
    mkuser()
    raw(env, "PRAGMA foreign_keys=OFF") if False else None
    c = sqlite3.connect(f"{env}/t.db"); c.execute("PRAGMA foreign_keys=OFF"); c.execute(sql); c.commit(); c.close()
    assert not ledger.verify_chain()["is_valid"]


def test_ghost_row(env):
    mkuser()
    raw(env, "INSERT INTO users(google_sub_hmac,encrypted_email,encrypted_name,role,is_active,is_2fa_enabled,last_totp_timestep,failed_2fa_attempts,created_at,updated_at) VALUES('g','e','n','admin',1,0,0,0,'t','t')")
    assert ledger.verify_chain()["error_type"] == "GHOST_ROW"


def test_rehash_without_key_fails(env):
    mkuser()
    with database.WriteSession.begin() as db:
        b = db.get(MasterLedger, 2)
        b.data_snapshot = "forged"; b.current_hash = ledger.sha(ledger._payload(b))  # attacker recomputes the hash, lacks the key
    assert ledger.verify_chain()["error_type"] in ("CHAIN_BROKEN", "BAD_SIGNATURE")


def test_tail_deletion_caught_by_anchor(env):
    mkuser(); mkuser("s2", "ok@example.org")
    c = sqlite3.connect(f"{env}/t.db"); c.execute("PRAGMA foreign_keys=OFF")
    c.execute("DELETE FROM master_ledger WHERE id=3"); c.execute("DELETE FROM users WHERE id=2"); c.commit(); c.close()
    assert ledger.verify_chain()["error_type"] == "TAIL_TRUNCATED"


def test_no_store_warns(env):
    ledger.store = None
    r = ledger.verify_chain()
    assert r["is_valid"] and "warning" in r


def test_concurrent_appends_linear(env):
    errs = []
    def w(i):
        try: auth.login_upsert(f"u{i}", f"u{i}@ngo.org", True, "ngo.org", "n")
        except Exception as e: errs.append(e)
    ts = [threading.Thread(target=w, args=(i,)) for i in range(12)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errs and ledger.verify_chain()["blocks"] == 13


def test_reader_not_blocked_by_writer(env):
    with database.WriteSession.begin() as db:
        db.execute(select(MasterLedger.id)).all()
        t0 = time.time(); assert ledger.verify_chain()["is_valid"]; assert time.time() - t0 < 2


def test_login_counters_do_not_break_chain(env):
    u = mkuser(); auth.begin_2fa_setup(u.id)
    for _ in range(2): auth.verify_code(u.id, "000000")
    assert ledger.verify_chain()["is_valid"]


def test_admin_rules(env):
    a = auth.login_upsert("a", "boss@example.org", True, None, "n")
    u = mkuser()
    with pytest.raises(ValueError): auth.admin_update(a.id, a.id, role="whistleblower")
    with pytest.raises(ValueError): auth.admin_update(None, a.id, active=False)  # last admin
    auth.admin_update(a.id, u.id, role="hr_auditor")
    assert ledger.verify_chain()["is_valid"]


# ---- 2FA
def enrolled(clock):
    u = mkuser(); secret, _ = auth.begin_2fa_setup(u.id)
    return u, pyotp.TOTP(secret)

def test_2fa_flow(env, monkeypatch):
    monkeypatch.setattr(auth, "_now", lambda: 1_000_000)
    u, t = enrolled(None)
    code = t.at(1_000_000)
    assert auth.verify_code(u.id, code) == "ok"
    assert auth.verify_code(u.id, code) == "replay"
    assert auth.verify_code(u.id, t.at(1_000_000 - 30)) == "replay"  # older window
    with pytest.raises(ValueError): auth.begin_2fa_setup(u.id)

def test_lockout_and_expiry(env, monkeypatch):
    monkeypatch.setattr(auth, "_now", lambda: 1_000_000)
    u, t = enrolled(None)
    assert [auth.verify_code(u.id, "000000") for _ in range(4)] == ["bad", "bad", "bad", "locked"]
    assert auth.verify_code(u.id, t.at(1_000_000)) == "locked"
    with database.WriteSession.begin() as db:
        db.get(User, u.id).locked_until = "2000-01-01T00:00:00.000000Z"
    assert auth.verify_code(u.id, "000000") == "bad"  # fresh count of 1
    with database.WriteSession.begin() as db:
        assert db.get(User, u.id).failed_2fa_attempts == 1

def test_parallel_guesses_counted(env):
    u, _ = enrolled(None)
    res = []
    ts = [threading.Thread(target=lambda: res.append(auth.verify_code(u.id, "000000"))) for _ in range(10)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert res.count("bad") == 3 and res.count("locked") == 7

def test_garbage_and_not_setup(env):
    u = mkuser()
    assert auth.verify_code(u.id, "123456") == "not_setup"
    auth.begin_2fa_setup(u.id)
    for bad in ["١٢٣٤٥٦", "12345", "abcdef!", "", "é" * 8]:
        assert auth.verify_code(u.id, bad) in ("bad", "locked")

def test_duress(env, monkeypatch):
    monkeypatch.setattr(auth, "_now", lambda: 1_000_000)
    u, t = enrolled(None)
    for bad in ["123456", "short", "a" * 13]:
        with pytest.raises(ValueError): auth.set_duress_code(u.id, bad)
    auth.set_duress_code(u.id, "Panic2024")
    assert auth.verify_code(u.id, "Panic2024") == "decoy"
    assert auth.verify_code(u.id, "Wrong2024") == "bad"

def test_inactive(env):
    u = mkuser("z"); auth.admin_update(None, u.id, active=False)
    assert auth.verify_code(u.id, "123456") == "inactive"

def test_token_alg_and_scope(env):
    import jwt as J
    t = auth.issue_token(1, "full_access")
    assert auth.decode_token(t)["scope"] == "full_access"
    with pytest.raises(J.PyJWTError): auth.decode_token(J.encode({"sub": "1", "scope": "x", "exp": 9999999999}, "", algorithm="none"))


# ---- crypto / scrub / store
def test_crypto(env):
    t = encrypt_field("hello", "PII", "a.b")
    assert decrypt_field(t, "PII", "a.b") == "hello"
    with pytest.raises(Exception): decrypt_field(t, "PII", "a.c")
    with pytest.raises(Exception): decrypt_field(t, "EVIDENCE", "a.b")
    b = encrypt_blob(b"x" * 100, "k")
    assert len(b) == 12 + 1024 * 1024 + 16 and decrypt_blob(b, "k") == b"x" * 100
    with pytest.raises(Exception): decrypt_blob(b[:-1] + bytes([b[-1] ^ 1]), "k")
    with pytest.raises(Exception): decrypt_blob(b, "other")

JPG = b"\xff\xd8" + b"\xff\xe0\x00\x10JFIF\x00" + b"\0" * 9 + b"\xff\xe1\x00\x0aExif\0\0ab" + b"\xff\xfe\x00\x05cmt" + b"\xff\xda\x00\x04\x00\x00" + b"\x12\xff\x00\x34\xff\xd0\x56" + b"\xff\xd9" + b"TRAILER-SECRET"
def test_jpeg_strip():
    o = strip_jpeg(JPG)
    assert b"Exif" not in o and b"cmt" not in o and b"TRAILER" not in o and b"JFIF" in o
    assert b"\x12\xff\x00\x34\xff\xd0\x56\xff\xd9" in o and o.endswith(b"\xff\xd9")
    with pytest.raises(ValueError): strip_jpeg(JPG[: JPG.index(b"\xff\xd9")])

def _chunk(t, d):
    import zlib
    return len(d).to_bytes(4, "big") + t + d + zlib.crc32(t + d).to_bytes(4, "big")
def test_png_strip():
    p = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", b"\0" * 13) + _chunk(b"PLTE", b"\1\2\3") + _chunk(b"tEXt", b"GPS=1") + _chunk(b"eXIf", b"x") + _chunk(b"IDAT", b"z") + _chunk(b"IEND", b"") + b"HIDDEN"
    o = strip_png(p)
    assert b"GPS" not in o and b"eXIf" not in o and b"HIDDEN" not in o and b"PLTE" in o and o.endswith(_chunk(b"IEND", b""))

def test_sniff():
    assert sniff(JPG) == "image/jpeg"
    with pytest.raises(Unsupported): sniff(b"MZ\x90\x00 not allowed")
    with pytest.raises(ValueError): scrub(b"%PDF-1.4", "application/pdf")  # sniffed as PDF but not parseable -> rejected, never stored

def test_store_once(tmp_path):
    s = LocalStore(tmp_path); s.put("a/1", b"x", once=True)
    with pytest.raises(FileExistsError): s.put("a/1", b"y", once=True)
    assert s.keys("a/") == ["a/1"] and s.get("a/1") == b"x"


# ---- v3.1 review fixes
def test_v01_duress_works_while_locked(env, monkeypatch):
    monkeypatch.setattr(auth, "_now", lambda: 1_000_000)
    u, t = enrolled(None)
    auth.set_duress_code(u.id, "Panic2024")
    assert [auth.verify_code(u.id, "000000") for _ in range(4)] == ["bad", "bad", "bad", "locked"]
    assert auth.verify_code(u.id, "Panic2024") == "decoy"        # attacker pre-locked the account; duress still reaches the decoy
    assert auth.verify_code(u.id, t.at(1_000_000)) == "ok"        # and the lock was cleared
    assert auth.verify_code(u.id, "Wrong2024") == "bad"           # a wrong alphanumeric guess is still counted


def test_v04_wiped_anchor_store_fails_closed(env):
    mkuser()
    import shutil
    shutil.rmtree(env / "objs" / "anchors")
    assert ledger.verify_chain()["error_type"] == "ANCHORS_UNAVAILABLE"


def _enrolled_with_duress(monkeypatch):
    monkeypatch.setattr(auth, "_now", lambda: 1_000_000)
    u, t = enrolled(None)
    assert auth.verify_code(u.id, t.at(1_000_000)) == "ok"
    auth.set_duress_code(u.id, "Panic2024")
    return u


def test_v03_credential_blocks_are_generic(env, monkeypatch):
    _enrolled_with_duress(monkeypatch)
    assert ledger.verify_chain()["is_valid"]  # enrolment, duress and login all leave a valid chain
    with database.ReadSession() as db:
        notes = [b.data_snapshot for b in db.execute(select(MasterLedger)).scalars() if b.action == "CREDENTIAL_UPDATE"]
    assert len(notes) == 3 and all("duress" not in n.lower() and "totp" not in n.lower() for n in notes)


@pytest.mark.parametrize("col,val", [("totp_secret_encrypted", "attacker-seed"), ("duress_scrypt", "x$y"), ("is_2fa_enabled", 0)])
def test_v03_credential_swap_detected(env, monkeypatch, col, val):
    u = _enrolled_with_duress(monkeypatch)
    raw(env, f"UPDATE users SET {col}=? WHERE id=?", val, u.id)
    assert ledger.verify_chain()["error_type"] == "ROW_TAMPERED"


# ---- V-07: MP4 and PDF
def _b(t, payload=b""):
    return (8 + len(payload)).to_bytes(4, "big") + t + payload

def _mp4(version=0):
    t = (b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" if version == 0 else b"\x01" * 16)
    gps = _b(b"udta", _b(b"\xa9xyz", b"\x00\x08\x15\xc7+37.7749-122.4194/"))
    mvhd = _b(b"mvhd", bytes([version]) + b"\0\0\0" + t + b"\x11" * 80)
    trak = _b(b"trak", _b(b"tkhd", bytes([version]) + b"\0\0\0" + t + b"\x22" * 60) + _b(b"meta", b"\0\0\0\0com.apple.quicktime.location 37.77") + gps)
    return _b(b"ftyp", b"isom\0\0\2\0isom") + _b(b"moov", mvhd + gps + trak) + _b(b"mdat", b"VIDEODATA" * 20)

@pytest.mark.parametrize("version", [0, 1])
def test_v07_mp4_strip(version):
    from backend.scrub import strip_mp4
    src = _mp4(version)
    out = strip_mp4(src)
    assert len(out) == len(src)                                        # same size => every chunk offset stays valid
    assert out.index(b"mdat") == src.index(b"mdat") and out.endswith(b"VIDEODATA" * 20)
    assert b"37.7749" not in out and b"quicktime.location" not in out and b"\xa9xyz" not in out
    assert b"\xde\xad\xbe\xef" not in out and b"\xca\xfe\xba\xbe" not in out and out.count(b"free") == 3 and b"mvhd" in out
    pos, kinds = 0, []                                                  # the result is still a well-formed box sequence
    while pos < len(out):
        size = int.from_bytes(out[pos:pos + 4], "big"); kinds.append(out[pos + 4:pos + 8]); pos += size
    assert pos == len(out) and kinds == [b"ftyp", b"moov", b"mdat"]

def test_v07_mp4_malformed_rejected():
    from backend.scrub import strip_mp4
    bad = _mp4()[:-5]
    with pytest.raises(ValueError): strip_mp4(bad)
    with pytest.raises(ValueError): strip_mp4(b"\0\0\0\x20ftypisom" + b"\0" * 8 + (1 << 31).to_bytes(4, "big") + b"moov")

def test_v07_pdf_strip():
    import io, pikepdf
    from backend.scrub import strip_pdf
    pdf = pikepdf.new(); pdf.add_blank_page()
    pdf.docinfo["/Author"] = "Alice Whistle"; pdf.docinfo["/Creator"] = "iPhone 15 Pro"
    with pdf.open_metadata() as m: m["dc:creator"] = ["Alice Whistle"]
    src = io.BytesIO(); pdf.save(src)
    assert b"Alice Whistle" in src.getvalue()
    out = strip_pdf(src.getvalue())
    assert b"Alice" not in out and b"iPhone" not in out and b"/Metadata" not in out
    with pikepdf.open(io.BytesIO(out)) as p2:
        assert len(p2.pages) == 1 and list(p2.docinfo.keys()) == []
    with pytest.raises(ValueError): strip_pdf(b"%PDF-1.4 not really a pdf")

def test_v07_scrub_dispatch_covers_every_sniffed_type():
    assert set(["image/jpeg", "image/png", "application/pdf", "video/mp4"]) == {sniff(x) for x in (JPG, b"\x89PNG\r\n\x1a\n", b"%PDF-", b"\0\0\0\x18ftypisom")}
    assert scrub(_mp4(), "video/mp4") != _mp4()


# ---- independent review fixes
def test_f2_identity_swap_detected(env):
    a = auth.login_upsert("a", "boss@example.org", True, None, "Boss")
    w = mkuser("w")
    c = sqlite3.connect(f"{env}/t.db")  # copy the admin's encrypted identity onto the whistleblower: decrypts cleanly, so only the hash can catch it
    c.execute("UPDATE users SET encrypted_email=(SELECT encrypted_email FROM users WHERE id=?), encrypted_name=(SELECT encrypted_name FROM users WHERE id=?) WHERE id=?", (a.id, a.id, w.id))
    c.commit(); c.close()
    assert ledger.verify_chain()["error_type"] == "ROW_TAMPERED"


def test_f6_stale_pending_cleaned_and_not_500(env):
    ad = auth.login_upsert("a", "boss@example.org", True, None, "n")
    with pytest.raises(PermissionError): auth.login_upsert("late", "late@gmail.com", True, None, "n")
    with database.ReadSession() as db:
        pid = db.execute(select(PendingSignup.id)).scalar_one()
    monkey = auth.settings.ALLOWED_EMAILS
    auth.settings.ALLOWED_EMAILS = monkey + ["late@gmail.com"]        # the account gets allow-listed later and logs in
    try:
        auth.login_upsert("late", "late@gmail.com", True, None, "n")
    finally:
        auth.settings.ALLOWED_EMAILS = monkey
    with database.ReadSession() as db:
        assert db.execute(select(PendingSignup.id)).first() is None  # login removed the stale queue entry
    # and a stale row that does exist (older code path / race) is cleaned instead of crashing approve
    with database.WriteSession.begin() as db:
        sub = db.execute(select(User.google_sub_hmac).where(User.id == 2)).scalar_one()
        db.add(PendingSignup(google_sub_hmac=sub, encrypted_email="x", encrypted_name="y"))
        pid = db.execute(select(PendingSignup.id)).scalar_one()
    with pytest.raises(ValueError): auth.approve_signup(ad.id, pid)
    with database.ReadSession() as db:
        assert db.execute(select(PendingSignup.id)).first() is None


def test_f7_pending_rows_expire(env, monkeypatch):
    monkeypatch.setattr(auth.settings, "MAX_PENDING_SIGNUPS", 2)
    for i in range(2):
        with pytest.raises(PermissionError): auth.login_upsert(f"o{i}", f"o{i}@gmail.com", True, None, "n")
    with pytest.raises(OverflowError): auth.login_upsert("new", "new@gmail.com", True, None, "n")  # queue full
    raw(env, "UPDATE pending_signups SET created_at='2000-01-01T00:00:00.000000Z'")                  # the two entries are now old
    with pytest.raises(PermissionError): auth.login_upsert("new", "new@gmail.com", True, None, "n")  # expired rows were purged: queued, not 503


def test_anchor_garbage_fails_verification_not_500(env):
    mkuser()
    (env / "objs" / "anchors" / "0000000099.json").write_text("{not json")
    assert ledger.verify_chain()["error_type"] == "ANCHOR_MALFORMED"


def test_f9_part_caps_stop_cpu_bombs(monkeypatch):
    import backend.scrub as sc
    monkeypatch.setattr(sc, "MAX_PARTS", 50)
    jpg = b"\xff\xd8" + b"\xff\xfe\x00\x04ab" * 60 + b"\xff\xd9"
    with pytest.raises(ValueError, match="too many"): sc.strip_jpeg(jpg)
    with pytest.raises(ValueError, match="too many"): sc.strip_png(b"\x89PNG\r\n\x1a\n" + _chunk(b"tEXt", b"x") * 60 + _chunk(b"IEND", b""))
    with pytest.raises(ValueError, match="too many"): sc.strip_mp4(_b(b"ftyp", b"isom\0\0\2\0isom") + _b(b"free") * 60)
    assert sc.strip_jpeg(b"\xff\xd8" + b"\xff\xfe\x00\x04ab" * 3 + b"\xff\xd9") == b"\xff\xd8\xff\xd9"  # normal files are untouched by the cap


def test_f10_jpeg_keeps_only_plain_jfif():
    seg = lambda m, payload: bytes([0xFF, m]) + (len(payload) + 2).to_bytes(2, "big") + payload
    jfif = seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")           # plain 16-byte JFIF header
    junk0 = seg(0xE0, b"SECRET")                                                  # APP0 that is not JFIF
    thumb = seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x02\x02" + b"THUMB")  # JFIF with an embedded thumbnail
    res = seg(0xF5, b"HIDE")                                                      # reserved JPGn segment
    scan = b"\xff\xda\x00\x04\x00\x00\x12\xff\xd9"
    out = strip_jpeg(b"\xff\xd8" + jfif + junk0 + thumb + res + scan)
    assert out == b"\xff\xd8" + jfif + scan                                       # only the plain JFIF header survives


def test_f_short_mvhd_rejected_not_overrun():
    from backend.scrub import strip_mp4
    short = _b(b"mvhd", b"\x01\0\0\0" + b"\x07" * 8)       # version 1 needs 16 bytes of times, only 8 present
    with pytest.raises(ValueError): strip_mp4(_b(b"ftyp", b"isom\0\0\2\0isom") + _b(b"moov", short) + _b(b"mdat", b"x"))
