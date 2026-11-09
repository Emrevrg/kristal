"""SÄ±kÄ±ÅŸtÄ±r / medya â€” model DIÅI dosyalar (resim, belge, video, metin) iÃ§in dosya-tÃ¼rÃ¼ne gÃ¶re KAYIPSIZ sÄ±kÄ±ÅŸtÄ±rma.

Her dosya iÃ§in adaylar denenir, en kÃ¼Ã§Ã¼ÄŸÃ¼ seÃ§ilir; seÃ§ilen yÃ¶ntem aÃ§Ä±lÄ±p SHA-256 ile orijinal baytlara eÅŸitliÄŸi
doÄŸrulanmadan kabul edilmez (bit-kesin, dosya dÃ¼zeyinde â€” yalnÄ±z piksel deÄŸil, dosyanÄ±n kendisi geri gelir).

YÃ¶ntemler
  jxl-jpeg : JPEG â†’ JPEG XL kayÄ±psÄ±z yeniden kodlama (DCT katsayÄ±larÄ± korunur; djxl orijinal JPEG baytlarÄ±nÄ± geri kurar)
  pc-xz    : deflate akÄ±ÅŸlarÄ±nÄ± (PNG, PDF, ZIP/DOCXâ€¦) bit-kesin geri kurulabilir biÃ§imde aÃ§ar (precomp), sonra xz -9e
  zstd     : zstd -19 --long=27 (hÄ±zlÄ± aÃ§Ä±lÄ±ÅŸ)
  xz       : xz -9e
  store    : sÄ±kÄ±ÅŸtÄ±rÄ±lamÄ±yorsa olduÄŸu gibi
KapsayÄ±cÄ±: NSKM2 | girdi sayÄ±sÄ± | toplu blok boyu | (ad, yÃ¶ntem, boy, sha256, yÃ¼k) â€¦ | toplu xz bloÄŸu
  (tÃ¼re Ã¶zel yÃ¶ntem kazanmayan dosyalar â€” kaynak kod, metin, log â€” tek akÄ±ÅŸta: dosyalar arasÄ± benzerlik yakalanÄ±r)
"""
from __future__ import annotations

import hashlib, os, shutil, struct, subprocess, tempfile

JPEG_EXT = (".jpg", ".jpeg", ".jpe", ".jfif")
DEFLATE_EXT = (".png", ".pdf", ".zip", ".docx", ".xlsx", ".pptx", ".odt", ".epub", ".jar", ".apk", ".gz", ".swf")
TOOLS = {"cjxl": os.environ.get("NSK_CJXL", "cjxl"), "djxl": os.environ.get("NSK_DJXL", "djxl"),
         "precomp": os.environ.get("NSK_PRECOMP", "precomp")}


def _have(t):
    return shutil.which(TOOLS.get(t, t)) is not None


def _run(args, **kw):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def _pipe(args, data: bytes) -> bytes:
    return subprocess.run(args, input=data, check=True, capture_output=True).stdout


def _tmp(d, name, data=None):
    p = os.path.join(d, name)
    if data is not None:
        open(p, "wb").write(data)
    return p


# --- yÃ¶ntemler: enc(bytes, tmpdir) -> bytes, dec(bytes, tmpdir) -> bytes
def _enc_zstd(b, d):
    return _pipe(["zstd", "-19", "--long=27", "-q", "-c"], b)


def _dec_zstd(b, d):
    return _pipe(["zstd", "-d", "--long=27", "-q", "-c"], b)


def _enc_xz(b, d):
    return _pipe(["xz", "-9e", "-T1", "-c"], b)


def _dec_xz(b, d):
    return _pipe(["xz", "-d", "-c"], b)


def _enc_jxl(b, d):
    i, o = _tmp(d, "i.jpg", b), _tmp(d, "o.jxl")
    _run([TOOLS["cjxl"], i, o, "--lossless_jpeg=1", "-e", os.environ.get("NSK_JXL_EFFORT", "9")])
    return open(o, "rb").read()


def _dec_jxl(b, d):
    i, o = _tmp(d, "i.jxl", b), _tmp(d, "o.jpg")
    _run([TOOLS["djxl"], i, o])
    return open(o, "rb").read()


def _enc_pc(b, d):
    i, o = _tmp(d, "i.bin", b), _tmp(d, "o.pcf")
    _run([TOOLS["precomp"], "-cn", "-intense", f"-o{o}", i], cwd=d)
    return _enc_xz(open(o, "rb").read(), d)


def _dec_pc(b, d):
    i, o = _tmp(d, "i.pcf", _dec_xz(b, d)), _tmp(d, "o.bin")
    _run([TOOLS["precomp"], "-r", f"-o{o}", i], cwd=d)
    return open(o, "rb").read()


METHODS = {"store": (lambda b, d: b, lambda b, d: b), "zstd": (_enc_zstd, _dec_zstd), "xz": (_enc_xz, _dec_xz),
           "jxl-jpeg": (_enc_jxl, _dec_jxl), "pc-xz": (_enc_pc, _dec_pc)}
CODE = {m: i for i, m in enumerate(METHODS)}


def candidates(name: str, b: bytes):
    low = name.lower(); c = ["zstd", "xz"]
    if (low.endswith(JPEG_EXT) or b[:3] == b"\xff\xd8\xff") and _have("cjxl"):
        c.append("jxl-jpeg")
    if (low.endswith(DEFLATE_EXT) or b[:4] in (b"\x89PNG", b"%PDF", b"PK\x03\x04")) and _have("precomp"):
        c.append("pc-xz")
    return c


def compress_one(name: str, b: bytes, only=None):
    """â†’ (yÃ¶ntem, yÃ¼k, {yÃ¶ntem: boy veya hata}). Her aday aÃ§Ä±lÄ±p doÄŸrulanÄ±r; doÄŸrulanmayan aday elenir."""
    h = hashlib.sha256(b).digest(); best = ("store", b); tried = {}
    for m in (only or candidates(name, b)):
        with tempfile.TemporaryDirectory() as d:
            try:
                enc, dec = METHODS[m]
                y = enc(b, d)
                ok = hashlib.sha256(dec(y, d)).digest() == h
            except Exception as e:  # noqa: BLE001 â€” araÃ§ bu dosyayÄ± iÅŸleyemedi â†’ aday elenir
                tried[m] = "hata:" + type(e).__name__; continue
        tried[m] = len(y) if ok else "dogrulanmadi"
        if ok and len(y) < len(best[1]):
            best = (m, y)
    return best[0], best[1], tried


def decompress_one(method: str, y: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        return METHODS[method][1](y, d)


SOLID = 255
SPECIAL = ("jxl-jpeg", "pc-xz")


def _plan_one(p):
    """TÃ¼re Ã¶zel yÃ¶ntem (JPEG XL, deflate aÃ§ma) dosyanÄ±n kendi xz'sinden kÃ¼Ã§Ã¼kse dosya ayrÄ± tutulur; deÄŸilse toplu bloÄŸa gider
    (kaynak kod/metin/log: dosyalar arasÄ± benzerlik ancak tek akÄ±ÅŸta yakalanÄ±r). SÄ±kÄ±ÅŸmayan (video) ayrÄ± 'store'."""
    b = open(p, "rb").read(); c = [m for m in candidates(p, b) if m in SPECIAL]
    m, y, _ = compress_one(p, b, only=c + ["xz"])
    return p, (m, y) if m in SPECIAL or m == "store" else (SOLID, None)


def pack(paths, out_path, root=None, workers=4):
    """NSKM2: dosya baÅŸÄ±na tÃ¼re Ã¶zel yÃ¶ntem + kalanlar iÃ§in tek toplu xz bloÄŸu. Her dosyanÄ±n SHA-256'sÄ± saklanÄ±r."""
    from concurrent.futures import ProcessPoolExecutor
    with ProcessPoolExecutor(workers) as ex:
        plan = dict(ex.map(_plan_one, paths))
    solid = sorted((p for p in paths if plan[p][0] == SOLID), key=lambda p: (os.path.splitext(p)[1].lower(), p))
    order = [p for p in paths if plan[p][0] != SOLID] + solid
    blob = _enc_xz(b"".join(open(p, "rb").read() for p in solid), None) if solid else b""
    with open(out_path, "wb") as f:
        f.write(b"NSKM2" + struct.pack("<IQ", len(order), len(blob)))
        for p in order:
            b = open(p, "rb").read(); m, y = plan[p]; y = y or b""
            nm = os.path.relpath(p, root or os.path.dirname(p)).replace("\\", "/").encode()
            code = SOLID if m == SOLID else CODE[m]
            f.write(struct.pack("<HBQQ", len(nm), code, len(b), len(y)) + nm + hashlib.sha256(b).digest() + y)
        f.write(blob)
    return {"files": len(order), "solid_files": len(solid), "solid_bytes": len(blob)}


def unpack(arc, out_dir):
    names = list(METHODS)
    with open(arc, "rb") as f:
        assert f.read(5) == b"NSKM2"
        n, blen = struct.unpack("<IQ", f.read(12))
        ents = []
        for _ in range(n):
            ln, code, size, ylen = struct.unpack("<HBQQ", f.read(19))
            ents.append((f.read(ln).decode(), code, size, f.read(32), f.read(ylen)))
        solid = _dec_xz(f.read(blen), None) if blen else b""
    pos = 0
    for nm, code, size, h, y in ents:
        if code == SOLID:
            b = solid[pos:pos + size]; pos += size
        else:
            b = decompress_one(names[code], y)
        if len(b) != size or hashlib.sha256(b).digest() != h:
            raise ValueError(f"bozuk girdi: {nm}")
        p = os.path.join(out_dir, nm); os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        open(p, "wb").write(b)

