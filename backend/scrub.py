"""Type sniffing and metadata removal for JPEG, PNG, MP4 and PDF.
JPEG/PNG: we never DECODE untrusted images (no Pillow), so there is no decompression-bomb surface and no re-compression:
pixels are byte-identical, only metadata segments/chunks are dropped.
MP4: user-data boxes are overwritten IN PLACE by same-size `free` boxes, so every offset in the file stays valid; capture timestamps are zeroed.
PDF: rewritten by qpdf (pikepdf), which drops the Info dictionary, XMP and old incremental revisions.
NOT removed (tell users): GPS or other timed-metadata TRACKS inside a video (GoPro gpmd, Android camm, iPhone mebx), the content itself
(faces, text, audio), embedded files and JavaScript inside PDFs, and anything typed into the description field.
"""
import io
import re


class Unsupported(ValueError):
    pass


MAX_PARTS = 100_000  # segments / chunks / boxes per file: real files have far fewer; crafted ones (millions of 4-byte parts) burn CPU
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"acTL", b"fcTL", b"fdAT"}
# next real JPEG marker inside/after entropy-coded data: FF followed by something other than 00 (stuffing), D0-D7 (restart), FF (fill)
_NEXT_MARKER = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")


def sniff(d: bytes) -> str:
    if d[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if d[:8] == PNG_SIG:
        return "image/png"
    if d[:5] == b"%PDF-":
        return "application/pdf"
    if d[4:8] == b"ftyp":
        return "video/mp4"
    raise Unsupported("unsupported file type (allowed: JPEG, PNG, PDF, MP4)")


def _drop_segment(m: int, seg: bytes) -> bool:
    """seg includes its 2-byte length. Keep JFIF, ICC colour profile and Adobe colour flag; drop EXIF/XMP/comments/etc."""
    if m == 0xFE:
        return True
    if m == 0xE0:  # keep only a plain JFIF header (no thumbnail); drop JFXX and any other APP0 payload
        return not (seg[2:7] == b"JFIF\x00" and len(seg) <= 16)
    if m == 0xE2:
        return seg[2:14] != b"ICC_PROFILE\x00"
    if m == 0xEE:
        return seg[2:7] != b"Adobe"
    return 0xE1 <= m <= 0xEF or (0xF0 <= m <= 0xFD and m not in (0xF7, 0xF8))  # APPn, and reserved JPGn segments (F7/F8 are JPEG-LS)


def strip_jpeg(d: bytes) -> bytes:
    if d[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    out, i, n, parts = bytearray(b"\xff\xd8"), 2, len(d), 0
    while i < n:
        parts += 1
        if parts > MAX_PARTS:
            raise ValueError("too many JPEG segments")
        if d[i] != 0xFF:
            raise ValueError("bad JPEG marker structure")
        while i < n and d[i] == 0xFF:
            i += 1
        if i >= n:
            break
        m = d[i]
        i += 1
        if m == 0xD9:  # EOI: anything after it (hidden trailers) is discarded
            out += b"\xff\xd9"
            return bytes(out)
        if m == 0x01 or 0xD0 <= m <= 0xD8:  # markers without payload
            out += bytes([0xFF, m])
            continue
        if i + 2 > n:
            raise ValueError("truncated JPEG")
        ln = int.from_bytes(d[i : i + 2], "big")
        if ln < 2 or i + ln > n:
            raise ValueError("bad JPEG segment length")
        seg = d[i : i + ln]
        if not _drop_segment(m, seg):
            out += bytes([0xFF, m]) + seg
        i += ln
        if m == 0xDA:  # start of scan: copy entropy-coded bytes up to the next real marker
            nxt = _NEXT_MARKER.search(d, i)
            j = nxt.start() if nxt else n
            out += d[i:j]
            i = j
    raise ValueError("JPEG has no end marker")


def strip_png(d: bytes) -> bytes:
    if d[:8] != PNG_SIG:
        raise ValueError("not a PNG")
    out, i, n, parts = bytearray(d[:8]), 8, len(d), 0
    while i + 12 <= n:
        parts += 1
        if parts > MAX_PARTS:
            raise ValueError("too many PNG chunks")
        ln = int.from_bytes(d[i : i + 4], "big")
        typ, end = d[i + 4 : i + 8], i + 12 + ln
        if end > n:
            raise ValueError("truncated PNG chunk")
        if typ in PNG_KEEP:
            out += d[i:end]  # copied verbatim, CRC stays valid
        i = end
        if typ == b"IEND":
            return bytes(out)  # anything after IEND is discarded
    raise ValueError("PNG has no IEND")


def _box(d: bytes, pos: int, end: int) -> tuple[int, int, bytes]:
    """-> (header length, total size, type) of the box at pos; raises on anything inconsistent."""
    if pos + 8 > end:
        raise ValueError("truncated MP4 box")
    size, typ, hdr = int.from_bytes(d[pos : pos + 4], "big"), bytes(d[pos + 4 : pos + 8]), 8
    if size == 1:
        if pos + 16 > end:
            raise ValueError("truncated MP4 box")
        size, hdr = int.from_bytes(d[pos + 8 : pos + 16], "big"), 16
    elif size == 0:  # box runs to the end of its parent
        size = end - pos
    if size < hdr or pos + size > end:
        raise ValueError("bad MP4 box size")
    return hdr, size, typ


MP4_CONTAINERS = {b"moov", b"trak", b"mdia"}
MP4_DROP_TOP = {b"udta", b"meta", b"uuid"}  # user data, iTunes/QuickTime metadata (incl. GPS location), XMP
MP4_TIME_BOXES = {b"mvhd", b"tkhd", b"mdhd"}  # carry creation/modification time (seconds since 1904)


def _mp4_walk(out: bytearray, start: int, end: int, depth: int, count: list) -> None:
    pos = start
    while pos < end:
        count[0] += 1
        if count[0] > MAX_PARTS:
            raise ValueError("too many MP4 boxes")
        hdr, size, typ = _box(out, pos, end)
        if typ in MP4_DROP_TOP:
            out[pos + 4 : pos + 8] = b"free"  # same size: nothing after it moves
            out[pos + hdr : pos + size] = bytes(size - hdr)
        elif typ in MP4_CONTAINERS and depth < 4:
            _mp4_walk(out, pos + hdr, pos + size, depth + 1, count)
        elif typ in MP4_TIME_BOXES:
            if pos + hdr + 4 > pos + size:
                raise ValueError("bad MP4 header box")
            n = 8 if out[pos + hdr] == 1 else 4  # version 1 uses 64-bit times
            if pos + hdr + 4 + 2 * n > pos + size:
                raise ValueError("bad MP4 header box")  # too short to hold its own times: writing would run into the next box
            out[pos + hdr + 4 : pos + hdr + 4 + 2 * n] = bytes(2 * n)
        pos += size


def strip_mp4(d: bytes) -> bytes:
    if d[4:8] != b"ftyp":
        raise ValueError("not an MP4")
    out = bytearray(d)
    _mp4_walk(out, 0, len(out), 0, [0])
    return bytes(out)


def strip_pdf(d: bytes) -> bytes:
    import pikepdf  # qpdf parses untrusted input: keep it patched, and keep MAX_UPLOAD_BYTES small

    try:
        with pikepdf.open(io.BytesIO(d)) as pdf:
            if pdf.is_encrypted:
                raise ValueError("encrypted PDFs are not accepted")
            for k in list(pdf.docinfo.keys()):
                del pdf.docinfo[k]
            for obj in pdf.objects:  # document, page and image-level XMP / private application data
                if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
                    for k in ("/Metadata", "/PieceInfo"):
                        if k in obj:
                            del obj[k]
            out = io.BytesIO()
            pdf.save(out, deterministic_id=True)  # rewrites the file: old revisions and unreferenced objects are gone
            return out.getvalue()
    except pikepdf.PdfError as e:
        raise ValueError("PDF is damaged or unsupported") from e


def scrub(d: bytes, mime: str) -> bytes:
    return {"image/jpeg": strip_jpeg, "image/png": strip_png, "video/mp4": strip_mp4, "application/pdf": strip_pdf}[mime](d)
