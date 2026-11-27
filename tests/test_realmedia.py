"""Scrubbers against files made by real tools (ffmpeg, PIL, reportlab, LibreOffice), not hand-built bytes.
Skipped when a tool is missing. These are generated stand-ins for phone footage: real phone files are still untested."""
import hashlib, io, json, shutil, subprocess
import pytest
from backend.scrub import scrub, sniff

GPS = "+37.7749-122.4194/"
need = lambda *tools: pytest.mark.skipif(not all(shutil.which(t) for t in tools), reason=f"needs {tools}")


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True)


def probe_tags(path):
    out = run("ffprobe", "-v", "error", "-show_entries", "format_tags:stream_tags", "-of", "json", str(path)).stdout
    return json.dumps(json.loads(out)).lower()


def frame_md5(path):  # hash of the decoded video and audio: must not change when only metadata is removed
    out = run("ffmpeg", "-v", "error", "-i", str(path), "-map", "0", "-f", "framemd5", "-").stdout.decode()
    return hashlib.sha256(re_lines(out)).hexdigest()


def re_lines(text):
    return "\n".join(l.split(",", 1)[1] if "," in l else l for l in text.splitlines() if not l.startswith("#")).encode()


def make_mp4(path, *flags, audio=True):
    cmd = ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=2:size=320x240:rate=15"]
    if audio:
        cmd += ["-f", "lavfi", "-i", "sine=frequency=440:duration=2"]
    cmd += ["-c:v", "libx264", "-pix_fmt", "yuv420p"] + (["-c:a", "aac"] if audio else [])
    cmd += ["-metadata", f"location={GPS}", "-metadata", "title=Alice phone", "-metadata", "comment=Pixel 8 serial ABC123",
            "-metadata", "com.apple.quicktime.location.ISO6709=" + GPS, *flags, str(path)]
    run(*cmd)


MP4_VARIANTS = {
    "plain": [],
    "faststart_moov_first": ["-movflags", "+faststart"],  # moov before mdat: removing bytes there would break chunk offsets
    "mdta_keys": ["-movflags", "+use_metadata_tags"],     # QuickTime/iTunes style meta box (where iPhone location lives)
    "fragmented": ["-movflags", "frag_keyframe+empty_moov+default_base_moof"],
}


@need("ffmpeg", "ffprobe")
@pytest.mark.parametrize("variant", MP4_VARIANTS)
def test_real_mp4_scrubbed_and_still_plays(tmp_path, variant):
    src, dst = tmp_path / "in.mp4", tmp_path / "out.mp4"
    make_mp4(src, *MP4_VARIANTS[variant])
    raw = src.read_bytes()
    assert sniff(raw) == "video/mp4"
    tags_before = probe_tags(src)
    out = scrub(raw, "video/mp4")
    dst.write_bytes(out)
    assert len(out) == len(raw)                                   # in place: offsets cannot shift
    assert "37.7749" in tags_before or b"37.7749" in raw           # the test file really carried the location
    for secret in (b"37.7749", b"Alice phone", b"ABC123"):
        assert secret not in out, secret
    assert "37.7749" not in probe_tags(dst) and "alice" not in probe_tags(dst)
    assert frame_md5(dst) == frame_md5(src)                       # every audio/video frame decodes to the same bytes


@need("ffmpeg", "ffprobe")
def test_real_mp4_video_only_and_timestamps_zeroed(tmp_path):
    src = tmp_path / "v.mp4"
    make_mp4(src, audio=False)
    out = scrub(src.read_bytes(), "video/mp4")
    (tmp_path / "o.mp4").write_bytes(out)
    assert "creation_time" not in probe_tags(tmp_path / "o.mp4")
    assert frame_md5(tmp_path / "o.mp4") == frame_md5(src)


@need("ffmpeg")
def test_real_mp4_with_gps_track_documents_known_gap(tmp_path):
    """Timed-metadata tracks are NOT removed (documented limit). This test pins that behaviour so nobody assumes otherwise."""
    src, gps, mux = tmp_path / "v.mp4", tmp_path / "gps.srt", tmp_path / "mux.mp4"
    make_mp4(src, audio=False)
    gps.write_text(f"1\n00:00:00,000 --> 00:00:02,000\n{GPS}\n")
    run("ffmpeg", "-y", "-v", "error", "-i", str(src), "-i", str(gps), "-c", "copy", "-c:s", "mov_text", str(mux))
    assert b"37.7749" in scrub(mux.read_bytes(), "video/mp4")


@need("ffmpeg")
def test_real_jpeg_exif_gps_removed_pixels_identical(tmp_path):
    from PIL import Image
    im = Image.effect_noise((200, 150), 40).convert("RGB")
    exif = Image.Exif()
    exif[0x010F], exif[0x0110] = "ACME", "PhoneModel X"
    exif.get_ifd(0x8825).update({1: "N", 2: (37.0, 46.0, 29.64), 3: "W", 4: (122.0, 25.0, 9.84)})
    buf = io.BytesIO(); im.save(buf, "JPEG", exif=exif.tobytes(), quality=90)
    raw = buf.getvalue()
    assert b"PhoneModel" in raw and b"Exif" in raw
    out = scrub(raw, "image/jpeg")
    assert b"PhoneModel" not in out and b"Exif" not in out and len(out) < len(raw)
    a, b = Image.open(io.BytesIO(raw)), Image.open(io.BytesIO(out))
    assert not b.getexif() and a.tobytes() == b.tobytes()           # decodes to exactly the same pixels


@need("ffmpeg")
def test_real_png_text_chunks_removed_pixels_identical(tmp_path):
    from PIL import Image, PngImagePlugin
    im = Image.effect_noise((120, 90), 50).convert("P")
    info = PngImagePlugin.PngInfo(); info.add_text("Author", "Alice Whistle"); info.add_text("GPS", GPS)
    buf = io.BytesIO(); im.save(buf, "PNG", pnginfo=info)
    raw = buf.getvalue()
    assert b"Alice Whistle" in raw
    out = scrub(raw, "image/png")
    assert b"Alice" not in out and b"37.7749" not in out
    a, b = Image.open(io.BytesIO(raw)), Image.open(io.BytesIO(out))
    assert a.getpalette() == b.getpalette() and a.tobytes() == b.tobytes()   # palette and pixels survive (the old Pillow re-encode lost the palette)


def _pdf_text(path):
    return run("pdftotext", str(path), "-").stdout.decode().split()


@need("pdftotext")
def test_real_pdf_reportlab_metadata_removed_text_intact(tmp_path):
    from reportlab.pdfgen import canvas
    src = tmp_path / "r.pdf"
    c = canvas.Canvas(str(src)); c.setAuthor("Alice Whistle"); c.setCreator("PhoneApp 3.1"); c.setTitle("Secret title"); c.setSubject("GPS +37.7749")
    for i in range(3):
        c.drawString(72, 720, f"Evidence page {i} witness statement"); c.showPage()
    c.save()
    raw = src.read_bytes()
    assert b"Alice Whistle" in raw
    out = scrub(raw, "application/pdf")
    (tmp_path / "o.pdf").write_bytes(out)
    for secret in (b"Alice", b"PhoneApp", b"Secret title", b"37.7749"):
        assert secret not in out, secret
    assert _pdf_text(tmp_path / "o.pdf") == _pdf_text(src) and b"%PDF-" == out[:5]


@need("libreoffice", "pdftotext")
def test_real_pdf_libreoffice_with_xmp_removed_text_intact(tmp_path):
    (tmp_path / "doc.txt").write_text("Witness statement line one\nSecond line about the incident\n")
    run("libreoffice", "--headless", "--convert-to", "pdf", "--outdir", str(tmp_path), str(tmp_path / "doc.txt"))
    src = tmp_path / "doc.pdf"
    import pikepdf
    raw = src.read_bytes()
    with pikepdf.open(io.BytesIO(raw)) as before:                    # LibreOffice keeps its metadata in a compressed object stream, so read it properly
        assert {"/Creator", "/Producer", "/CreationDate"} <= set(before.docinfo.keys())
    out = scrub(raw, "application/pdf")
    (tmp_path / "o.pdf").write_bytes(out)
    with pikepdf.open(io.BytesIO(out)) as after:
        assert list(after.docinfo.keys()) == [] and "/Metadata" not in after.Root
    assert _pdf_text(tmp_path / "o.pdf") == _pdf_text(src)


@need("pdftotext", "qpdf")
def test_real_pdf_incremental_update_history_dropped(tmp_path):
    """An edited PDF keeps the old text in earlier revisions; the rewrite must not."""
    from reportlab.pdfgen import canvas
    src = tmp_path / "a.pdf"
    c = canvas.Canvas(str(src)); c.setAuthor("OLD AUTHOR NAME"); c.drawString(72, 720, "hello"); c.save()
    raw = src.read_bytes()
    update = b"\n% incremental update\n" + b"99 0 obj\n<< /Secret (OLD REVISION DATA) >>\nendobj\n"
    out = scrub(raw + update, "application/pdf")
    assert b"OLD REVISION DATA" not in out and b"OLD AUTHOR" not in out
