"""SIKISTIR v5: NSK4 (CDC + ozel medya yollari) ile KATI mod (deterministik tar + en iyi kodek: xz/zstd/brotli/ppmd) arasindan
kucuk olani secer. Her iki yol da paketlemeden sonra acilip SHA-256 ile dogrulanir; dogrulanamayan yol secilmez.
Kati mod cok sayida kucuk dosyada (metin/kod/ikon) dosya basi hash/tarif yukunu ortadan kaldirir.
Bicim: MAGIC5 + 1 bayt kip (0=NSK4, 1=KATI) + [KATI: 1 bayt kodek uzunlugu + kodek + 32 bayt tar SHA-256] + govde.
Kullanim: python sikistir5.py pack KAYNAK ARSIV | unpack ARSIV HEDEF"""
import hashlib, io, os, shutil, struct, subprocess, sys, tarfile, tempfile
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sikistir4 as S4

MAGIC5 = b"NSK5\r\n\x1a\n"


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.digest()


def _tar(src, out):
    src = Path(src)
    def norm(ti):
        ti.uid = ti.gid = 0; ti.uname = ti.gname = ""; return ti
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as t:
        for p in sorted(src.rglob("*"), key=lambda q: (q.suffix.lower(), q.as_posix())):   # ayni tur dosyalar yan yana
            t.add(p, arcname=p.relative_to(src).as_posix(), recursive=False, filter=norm)


def _agac_hash(root):
    root = Path(root); h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        r = p.relative_to(root).as_posix().encode()
        if p.is_symlink(): h.update(b"L" + r + os.readlink(p).encode())
        elif p.is_file(): h.update(b"F" + r + _sha(p))
        elif p.is_dir(): h.update(b"D" + r)
    return h.digest()


IRIS = os.environ.get("NSK_IRIS", "/mnt/norovox/iris_bp/iris_bp")


def _iris_uygun(p):
    if p.suffix != ".safetensors" or not p.is_file() or p.is_symlink() or p.stat().st_size < (64 << 20): return False
    try:
        import json as _j, struct as _s
        with open(p, "rb") as f: n = _s.unpack("<Q", f.read(8))[0]; h = _j.loads(f.read(n))
        bf = sum(v["data_offsets"][1] - v["data_offsets"][0] for k, v in h.items() if k != "__metadata__" and v.get("dtype") == "BF16")
        return bf > 0.5 * p.stat().st_size
    except Exception: return False


def pack(src, archive):
    """IRIS katmani: bf16 safetensors dosyalari IRIS-BP ile (bit-kesin dogrulanir), geri kalani _pack_genel ile."""
    src = Path(src); archive = Path(archive)
    iris_d = [p for p in sorted(src.rglob("*")) if os.path.exists(IRIS) and _iris_uygun(p)]
    if not iris_d: return _pack_genel(src, archive)
    w = Path(tempfile.mkdtemp(dir=archive.parent))
    try:
        kalan = w / "kalan"; shutil.copytree(src, kalan, symlinks=True, copy_function=shutil.copy2)
        uyeler = []
        for p in iris_d:
            rel = p.relative_to(src).as_posix(); enc = w / f"i{len(uyeler)}.ib"; geri = w / "geri.st"
            subprocess.run([IRIS, "enc", str(p), str(enc), "--seviye", "19"], check=True, capture_output=True)
            subprocess.run([IRIS, "dec", str(enc), str(geri)], check=True, capture_output=True)
            if _sha(geri) != _sha(p): enc.unlink(); continue            # dogrulanamazsa genel yola birak
            geri.unlink(); st = p.stat(); (kalan / rel).unlink()
            uyeler.append((rel, enc, st.st_mode & 0o7777, st.st_mtime_ns))
        alt = w / "alt.nsk5"; r = _pack_genel(kalan, alt)
        with open(archive, "wb") as f:
            f.write(MAGIC5 + bytes([2]) + struct.pack("<I", len(uyeler)))
            for rel, enc, mode, mt in uyeler:
                b = rel.encode(); f.write(struct.pack("<H", len(b)) + b + struct.pack("<IqQ", mode, mt, enc.stat().st_size))
                with open(enc, "rb") as g: shutil.copyfileobj(g, f, 1 << 20)
            with open(alt, "rb") as g: shutil.copyfileobj(g, f, 1 << 20)
        return {"kip": "IRIS+" + r["kip"], "iris_dosya": len(uyeler), "boyut": archive.stat().st_size}
    finally:
        shutil.rmtree(w, ignore_errors=True)


def _pack_genel(src, archive):
    src = Path(src); archive = Path(archive); w = Path(tempfile.mkdtemp(dir=archive.parent))
    try:
        hedef = _agac_hash(src); adaylar = []
        # yol A: NSK4
        try:
            a = w / "a.nsk4"; S4.pack(src, a)
            g = w / "ga"; S4.unpack(a, g)
            if _agac_hash(g) == hedef: adaylar.append((a.stat().st_size, 0, a, b""))
            shutil.rmtree(g, ignore_errors=True)
        except Exception as e:
            print(f"NSK4 yolu atlandi: {e}", file=sys.stderr)
        # yol B: KATI
        tarp = w / "k.tar"; _tar(src, tarp); tsha = _sha(tarp)
        kd = w / "kd"; kd.mkdir()
        codec, data = S4.best_compression(tarp, kd, "kati")
        g = w / "gb"; g.mkdir()
        geri = w / "geri.tar"; S4.decompress(data, geri, codec)
        if _sha(geri) == tsha:
            with tarfile.open(geri) as t: t.extractall(g, filter="tar")
            if _agac_hash(g) == hedef:
                adaylar.append((data.stat().st_size + 2 + len(codec) + 32, 1, data, bytes([len(codec)]) + codec.encode() + tsha))
        if not adaylar: raise RuntimeError("hicbir yol dogrulanamadi")
        _, kip, govde, ek = min(adaylar, key=lambda x: x[0])
        with open(archive, "wb") as f:
            f.write(MAGIC5 + bytes([kip]) + ek)
            with open(govde, "rb") as g2: shutil.copyfileobj(g2, f, 1 << 20)
        return {"kip": "NSK4" if kip == 0 else "KATI", "boyut": archive.stat().st_size, "aday": [(s, k) for s, k, _, _ in adaylar]}
    finally:
        shutil.rmtree(w, ignore_errors=True)


def unpack(archive, dest):
    archive = Path(archive); dest = Path(dest); w = Path(tempfile.mkdtemp(dir=dest.parent if dest.parent.exists() else None))
    try:
        with open(archive, "rb") as f:
            if f.read(8) != MAGIC5: raise ValueError("NSK5 degil")
            kip = f.read(1)[0]
            if kip == 2:                                   # IRIS uyeleri + alt arsiv
                n = struct.unpack("<I", f.read(4))[0]; uyeler = []
                for i in range(n):
                    L = struct.unpack("<H", f.read(2))[0]; rel = f.read(L).decode(); mode, mt, sz = struct.unpack("<IqQ", f.read(20))
                    if rel.startswith("/") or ".." in Path(rel).parts: raise ValueError("guvensiz yol")
                    enc = w / f"i{i}.ib"
                    with open(enc, "wb") as g:
                        kalan_b = sz
                        while kalan_b:
                            b = f.read(min(1 << 20, kalan_b))
                            if not b: raise ValueError("kesik arsiv")
                            g.write(b); kalan_b -= len(b)
                    uyeler.append((rel, enc, mode, mt))
                alt = w / "alt.nsk5"
                with open(alt, "wb") as g: shutil.copyfileobj(f, g, 1 << 20)
                unpack(alt, dest)
                for rel, enc, mode, mt in uyeler:
                    out = dest / rel; out.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.run([IRIS, "dec", str(enc), str(out)], check=True, capture_output=True)
                    os.chmod(out, mode); os.utime(out, ns=(mt, mt))
                return
            if kip == 0:
                body = w / "a.nsk4"
                with open(body, "wb") as g: shutil.copyfileobj(f, g, 1 << 20)
                S4.unpack(body, dest); return
            n = f.read(1)[0]; codec = f.read(n).decode(); tsha = f.read(32)
            if codec not in ("xz", "zstd", "brotli", "ppmd"): raise ValueError("bilinmeyen kodek")
            body = w / "b"
            with open(body, "wb") as g: shutil.copyfileobj(f, g, 1 << 20)
        tarp = w / "k.tar"; S4.decompress(body, tarp, codec)
        if _sha(tarp) != tsha: raise ValueError("KATI: SHA-256 uyusmazligi")
        dest.mkdir(parents=True, exist_ok=False)
        with tarfile.open(tarp) as t: t.extractall(dest, filter="tar")
    finally:
        shutil.rmtree(w, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1] == "pack": print(pack(sys.argv[2], sys.argv[3]))
    elif sys.argv[1] == "unpack": unpack(sys.argv[2], sys.argv[3])
