"""SÄ±kÄ±ÅŸtÄ±r / PNG: pikselleri JPEG XL kayÄ±psÄ±zla kodlar, PNG dosyasÄ±nÄ± bayt bayt geri kurmak iÃ§in gerekenleri ayrÄ± saklar.

PNG'nin sÄ±kÄ±ÅŸtÄ±rÄ±lmÄ±ÅŸ kÄ±smÄ± (IDAT) iki adÄ±mla Ã¼retilir: satÄ±r filtreleri + zlib. Filtre tÃ¼rleri ve zlib ayarlarÄ± kaydedilirse aynÄ± baytlar yeniden Ã¼retilebilir.
Ayar aranÄ±r (seviye, bellek, strateji). Tutmazsa ya da biÃ§im desteklenmiyorsa None dÃ¶ner, Ã§aÄŸÄ±ran baÅŸka yÃ¶ntem dener.
Desteklenen: 8 bit, geÃ§iÅŸsiz, gri/RGB/gri+alfa/RGBA.
"""
import io, os, struct, subprocess, tempfile, zlib, lzma
import numpy as np
from PIL import Image

SIG = b"\x89PNG\r\n\x1a\n"
KANAL = {0: 1, 2: 3, 4: 2, 6: 4}
MOD = {0: "L", 2: "RGB", 4: "LA", 6: "RGBA"}
CJXL = lambda: os.environ.get("NSK_CJXL", "cjxl")
DJXL = lambda: os.environ.get("NSK_DJXL", "djxl")


def _parcala(b):
    if b[:8] != SIG:
        return None
    p, c = 8, []
    while p < len(b):
        if p + 12 > len(b):
            return None
        n = struct.unpack(">I", b[p:p + 4])[0]; t = b[p + 4:p + 8]
        if p + 12 + n > len(b):
            return None
        c.append((t, b[p + 8:p + 8 + n], b[p + 8 + n:p + 12 + n])); p += 12 + n
    return c


def _filtrele(px, f, bpp):
    """Filtreleri piksellerden ileri yÃ¶nde uygular; her satÄ±r yalnÄ±z ham piksellere baktÄ±ÄŸÄ± iÃ§in vektÃ¶rle yapÄ±lÄ±r."""
    h, w = px.shape; c = np.zeros((h, w + 1), dtype=np.uint8); c[:, 0] = f
    a = np.zeros_like(px); a[:, bpp:] = px[:, :-bpp]
    b = np.zeros_like(px); b[1:] = px[:-1]
    d = np.zeros_like(px); d[1:, bpp:] = px[:-1, :-bpp]
    x = px.astype(np.int16); A, B, D = a.astype(np.int16), b.astype(np.int16), d.astype(np.int16)
    for t, sat in ((0, x), (1, x - A), (2, x - B), (3, x - (A + B) // 2)):
        m = f == t
        if m.any():
            c[m, 1:] = (sat[m] & 255).astype(np.uint8)
    m = f == 4
    if m.any():
        P = A[m] + B[m] - D[m]; pa = np.abs(P - A[m]); pb = np.abs(P - B[m]); pc = np.abs(P - D[m])
        Q = np.where((pa <= pb) & (pa <= pc), A[m], np.where(pb <= pc, B[m], D[m]))
        c[m, 1:] = ((x[m] - Q) & 255).astype(np.uint8)
    return c


AYARLAR = [(l, m, s) for l in (6, 9, 7, 8, 5, 4, 3, 2, 1) for m in (8, 9, 7) for s in (0, 1, 2, 3)]


def _zlib_bul(ham, hedef):
    wb = 8 + (hedef[0] >> 4)
    for l, m, s in AYARLAR:
        o = zlib.compressobj(l, zlib.DEFLATED, wb, m, s)
        if o.compress(ham) + o.flush() == hedef:
            return l, m, s, wb
    return None


def enc(b):
    c = _parcala(b)
    if not c or c[0][0] != b"IHDR":
        return None
    w, h, bit, tip, _, _, gec = struct.unpack(">IIBBBBB", c[0][1])
    if bit != 8 or gec or tip not in KANAL:
        return None
    id_ = [i for i, x in enumerate(c) if x[0] == b"IDAT"]
    if not id_ or id_ != list(range(id_[0], id_[-1] + 1)):
        return None
    akis = b"".join(c[i][1] for i in id_)
    try:
        ham = zlib.decompress(akis)
    except zlib.error:
        return None
    n = KANAL[tip]; st = w * n + 1
    if len(ham) != st * h:
        return None
    ay = _zlib_bul(ham, akis)
    if not ay:
        return None
    sat = np.frombuffer(ham, dtype=np.uint8).reshape(h, st); f = sat[:, 0].copy()
    if f.max() > 4:
        return None
    px = np.asarray(Image.open(io.BytesIO(b)).convert(MOD[tip]), dtype=np.uint8).reshape(h, w * n)
    if _filtrele(px, f, n).tobytes() != ham:
        return None
    with tempfile.TemporaryDirectory() as d:
        i, o = f"{d}/i.png", f"{d}/o.jxl"
        Image.frombytes(MOD[tip], (w, h), px.tobytes()).save(i, compress_level=1)
        subprocess.run([CJXL(), i, o, "-d", "0", "-e", os.environ.get("NSK_JXL_EFFORT", "9")], check=True, capture_output=True)
        jx = open(o, "rb").read()
    # DiÄŸer parÃ§alar ve IDAT parÃ§a boylarÄ±: dosyayÄ± geri kurmak iÃ§in
    ust = bytearray(struct.pack("<BBBBIIB", ay[0], ay[1], ay[2], ay[3], w, h, tip))
    ust += struct.pack("<I", len(c))
    for t, v, crc in c:
        ust += t + struct.pack("<I", len(v))
        if t != b"IDAT":
            ust += v
        ust += crc
    m = lzma.compress(bytes(ust) + f.tobytes(), preset=9 | lzma.PRESET_EXTREME)
    return b"NPN1" + struct.pack("<II", len(m), len(jx)) + m + jx


def dec(y):
    if y[:4] != b"NPN1":
        raise ValueError("biÃ§im")
    ml, jl = struct.unpack("<II", y[4:12]); m = lzma.decompress(y[12:12 + ml]); jx = y[12 + ml:12 + ml + jl]
    l, mem, s, wb, w, h, tip = struct.unpack("<BBBBIIB", m[:13]); nc = struct.unpack("<I", m[13:17])[0]; p = 17; par = []
    for _ in range(nc):
        t = m[p:p + 4]; n = struct.unpack("<I", m[p + 4:p + 8])[0]; p += 8; v = None
        if t != b"IDAT":
            v = m[p:p + n]; p += n
        crc = m[p:p + 4]; p += 4; par.append((t, n, v, crc))
    f = np.frombuffer(m[p:p + h], dtype=np.uint8); n = KANAL[tip]
    with tempfile.TemporaryDirectory() as d:
        i, o = f"{d}/i.jxl", f"{d}/o.png"; open(i, "wb").write(jx)
        subprocess.run([DJXL(), i, o], check=True, capture_output=True)
        px = np.asarray(Image.open(o).convert(MOD[tip]), dtype=np.uint8).reshape(h, w * n)
    z = zlib.compressobj(l, zlib.DEFLATED, wb, mem, s); akis = z.compress(_filtrele(px, f, n).tobytes()) + z.flush()
    out = bytearray(SIG); q = 0
    for t, n_, v, crc in par:
        if t == b"IDAT":
            v = akis[q:q + n_]; q += n_
        out += struct.pack(">I", n_) + t + v + crc
    return bytes(out)

