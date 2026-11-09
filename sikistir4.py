"""NSK4. Linux/x86-64 iÃ§in doÄŸrulamalÄ± tÃ¼r yÃ¶nlendirme + CDC + xz/zstd.

    python sikistir4.py pack kaynak cikti.nsk4 --esik 1
    python sikistir4.py unpack cikti.nsk4 hedef

--esik yÃ¼zde cinsindendir. Ã–zel yÃ¼k, tek dosyanÄ±n min(xz9e, zstd19long)
Ã§Ä±ktÄ±sÄ±ndan bu oranda kÃ¼Ã§Ã¼kse seÃ§ilir. Son olarak tÃ¼mÃ¼-CDC planÄ± da denenir.
BiÃ§im: MAGIC, uint64 LE tablo boyu, 32 bayt tablo SHA256, xz(JSON tablo),
tablodaki sÄ±rayla yÃ¼kler. CDC tarifi mevcut nsk_cdc.c'nin little-endian biÃ§imi.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import lzma
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

MAGIC = b"NSK4\r\n\x1a\n"
HEADER = struct.Struct("<8sQ32s")
BUFFER = 1 << 20
MAX_TABLE = 256 << 20
MAX_TABLE_RAW = 512 << 20
JPEG = {".jpg", ".jpeg", ".jpe", ".jfif"}
DEFLATE = {".pdf", ".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
           ".odp", ".epub", ".jar", ".apk", ".gz", ".swf"}
COMPRESSED = {".mp4", ".mp3", ".webp", ".7z", ".mkv", ".mov", ".avi",
              ".ogg", ".flac", ".aac", ".xz", ".zst", ".bz2", ".rar", ".jxl"}
METHODS = {"cdc", "store", "lepton", "png-nsk", "precomp-xz"}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(BUFFER):
            digest.update(chunk)
    return digest.hexdigest()


def tool(name):
    value = os.environ.get("NSK_" + name.upper(), "nsk_cdc" if name == "cdc" else name)
    found = shutil.which(value)
    if not found:
        raise FileNotFoundError(f"AraÃ§ bulunamadÄ±: {name} ({value})")
    return str(Path(found).resolve())


def run(args, *, output=None, cwd=None):
    # AraÃ§larÄ±n bÃ¼yÃ¼k tanÄ±lama Ã§Ä±ktÄ±larÄ± RAM'de tutulmaz.
    with tempfile.TemporaryFile() as log:
        if output is None:
            result = subprocess.run(list(map(str, args)), stdout=log, stderr=log, cwd=cwd)
        else:
            with open(output, "wb") as target:
                result = subprocess.run(list(map(str, args)), stdout=target, stderr=log, cwd=cwd)
        if result.returncode:
            log.seek(max(0, log.tell() - 4000))
            raise RuntimeError(f"{args[0]} kod {result.returncode}: "
                               + log.read().decode(errors="replace"))


PPMD_SINIR = 400 << 20   # PPMd yavas: bundan buyuk akislarda denenmez


def _akis(source, target, enc):
    with open(source, "rb") as f, open(target, "wb") as g:
        while True:
            b = f.read(BUFFER)
            if not b: break
            g.write(enc(b))


def compress(source, target, codec):
    if codec == "ppmd":
        import pyppmd
        c = pyppmd.Ppmd8Encoder(10, 1 << 30, pyppmd.PPMD8_RESTORE_METHOD_RESTART)
        with open(source, "rb") as f, open(target, "wb") as g:
            g.write(struct.pack("<Q", os.path.getsize(source)))
            while True:
                b = f.read(BUFFER)
                if not b: break
                g.write(c.encode(b))
            g.write(c.flush(endmark=False))
        return
    if codec == "brotli":
        import brotli
        c = brotli.Compressor(quality=11, lgwin=24)
        with open(source, "rb") as f, open(target, "wb") as g:
            while True:
                b = f.read(BUFFER)
                if not b: break
                g.write(c.process(b))
            g.write(c.finish())
        return
    args = ([tool("xz"), "-9e", "-T1", "-c", "--", source] if codec == "xz"
            else [tool("zstd"), "-19", "--long=31", "-T1", "-q", "-c", "--", source])
    run(args, output=target)


def decompress(source, target, codec):
    if codec == "ppmd":
        import pyppmd
        with open(source, "rb") as f, open(target, "wb") as g:
            n = struct.unpack("<Q", f.read(8))[0]
            d = pyppmd.Ppmd8Decoder(10, 1 << 30, pyppmd.PPMD8_RESTORE_METHOD_RESTART)
            data = f.read(); out = d.decode(data, n); g.write(out)
            if len(out) != n: raise ValueError("PPMd uzunluk uyusmazligi")
        return
    if codec == "brotli":
        import brotli
        d = brotli.Decompressor()
        with open(source, "rb") as f, open(target, "wb") as g:
            while True:
                b = f.read(BUFFER)
                if not b: break
                g.write(d.process(b))
        return
    args = ([tool("xz"), "-d", "-c", "--", source] if codec == "xz"
            else [tool("zstd"), "-d", "--long=31", "-q", "-c", "--", source])
    run(args, output=target)


def best_compression(source, directory, stem):
    """Ä°ki aday da Ã§alÄ±ÅŸmalÄ± ve SHA ile doÄŸrulanmalÄ±. Eksik genel araÃ§ hatadÄ±r."""
    digest = sha256(source)
    candidates = []
    restored = directory / (stem + ".check")
    adaylar = ["xz", "zstd", "brotli"] + (["ppmd"] if os.path.getsize(source) <= PPMD_SINIR else [])
    for codec in adaylar:
        output = directory / (stem + "." + codec)
        try:
            compress(source, output, codec)
            decompress(output, restored, codec)
            gecerli = sha256(restored) == digest
        except Exception:
            gecerli = False
        if not gecerli:                      # dogrulanamayan aday asla secilmez
            if codec in ("xz", "zstd"):
                raise ValueError(f"Genel sikistirma dogrulanamadi: {codec}")
            output.unlink(missing_ok=True); continue
        candidates.append((output.stat().st_size, codec, output))
    restored.unlink()
    size, codec, output = min(candidates)
    for _, _, other in candidates:
        if other != output:
            other.unlink()
    return codec, output


def safe_name(name):
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise ValueError(f"GÃ¼vensiz arÅŸiv yolu: {name!r}")
    parts = name.split("/")
    if (any(part in ("", ".", "..") for part in parts)
            or PurePosixPath(name).is_absolute() or PureWindowsPath(name).drive
            or any(":" in part for part in parts)):
        raise ValueError(f"GÃ¼vensiz arÅŸiv yolu: {name!r}")
    return name


def snapshot(root, stage):
    entries = []
    for parent, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(directories + files):
            path = Path(parent) / name
            info = path.lstat()
            rel = safe_name(path.relative_to(root).as_posix())
            entry = {"name": rel, "mode": stat.S_IMODE(info.st_mode),
                     "mtime_ns": info.st_mtime_ns}
            if stat.S_ISDIR(info.st_mode):
                entry["kind"] = "dir"
            elif stat.S_ISREG(info.st_mode):
                ident = f"{len(entries):012d}"
                dest = stage / ident
                shutil.copyfile(path, dest)
                after = path.stat()
                if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError(f"Kaynak kopyalanÄ±rken deÄŸiÅŸti: {path}")
                entry.update(kind="file", id=ident, size=dest.stat().st_size,
                             sha256=sha256(dest), method="cdc")
            else:
                raise ValueError(f"Symlink/Ã¶zel dosya desteklenmiyor: {path}")
            entries.append(entry)
    return entries


def special_encode(method, source, output, directory):
    if method == "lepton":
        run([tool("lepton"), source, output], cwd=directory)
    elif method == "png-nsk":
        import png_nsk
        payload = png_nsk.enc(source.read_bytes())
        if payload is None:
            return False
        output.write_bytes(payload)
    elif method == "precomp-xz":
        preprocessed = directory / "encoded.pcf"
        run([tool("precomp"), "-cn", "-intense", f"-o{preprocessed}", source], cwd=directory)
        compress(preprocessed, output, "xz")
    return True


def special_decode(method, source, output, directory):
    if method == "store":
        shutil.copyfile(source, output)
    elif method == "lepton":
        run([tool("lepton"), source, output], cwd=directory)
    elif method == "png-nsk":
        import png_nsk
        output.write_bytes(png_nsk.dec(source.read_bytes()))
    elif method == "precomp-xz":
        preprocessed = directory / "decoded.pcf"
        decompress(source, preprocessed, "xz")
        run([tool("precomp"), "-r", f"-o{output}", preprocessed], cwd=directory)
    else:
        raise ValueError(f"Bilinmeyen Ã¶zel yÃ¶ntem: {method}")


def plan_special(entry, source, directory, threshold, diagnostics):
    with source.open("rb") as stream:
        signature = stream.read(8)
    suffix = Path(entry["name"]).suffix.lower()
    candidates = []
    if suffix in JPEG or signature.startswith(b"\xff\xd8\xff"):
        candidates = ["lepton"]
    elif suffix == ".png" or signature.startswith(b"\x89PNG\r\n\x1a\n"):
        candidates = ["png-nsk", "precomp-xz"]
    elif suffix in DEFLATE or signature.startswith((b"%PDF", b"PK\x03\x04", b"\x1f\x8b")):
        candidates = ["precomp-xz"]
    if not candidates and suffix not in COMPRESSED:
        return None
    _, baseline = best_compression(source, directory, "baseline")
    baseline_size = baseline.stat().st_size
    baseline.unlink()
    for method in candidates:
        output = directory / ("candidate." + method)
        check = directory / "candidate.restored"
        try:
            if not special_encode(method, source, output, directory):
                continue
            special_decode(method, output, check, directory)
            if check.stat().st_size != entry["size"] or sha256(check) != entry["sha256"]:
                raise ValueError("SHA-256 uyuÅŸmazlÄ±ÄŸÄ±")
        except Exception as error:  # Ã–zel kodlayÄ±cÄ±nÄ±n her dosya hatasÄ± genel yola dÃ¼ÅŸer.
            diagnostics.append({"name": entry["name"], "method": method, "error": str(error)})
            continue
        finally:
            check.unlink(missing_ok=True)
        if output.stat().st_size <= baseline_size * (1 - threshold / 100):
            return method, output
        # PNG kapsam iÃ§indeyse eÅŸik elenmesi doÄŸrudan genel yola gider.
        return None
    if suffix in COMPRESSED and entry["size"] <= baseline_size:
        return "store", source
    return None


def build_general(entries, stage, directory):
    directory.mkdir()
    files = sorted((e for e in entries if e.get("method") == "cdc"),
                   key=lambda e: (Path(e["name"]).suffix.lower(), e["name"]))
    if not files:
        return []
    listing = directory / "files.txt"
    listing.write_text("".join(str(stage / e["id"]) + "\n" for e in files), encoding="utf-8")
    unique, recipe = directory / "unique", directory / "recipe"
    run([tool("cdc"), "pack", listing, stage, unique, recipe])
    # Tarifin bÃ¼tÃ¼nlÃ¼ÄŸÃ¼nÃ¼ ve parÃ§a sÄ±nÄ±rlarÄ±nÄ± native unpack'a gÃ¼venmeden denetle.
    consume_recipe(unique, recipe, {e["id"]: e for e in files})
    codec, data = best_compression(unique, directory, "unique-packed")
    recipe_packed = directory / "recipe.xz"
    compress(recipe, recipe_packed, "xz")
    unique.unlink()
    recipe.unlink()
    return [("unique", codec, data), ("recipe", "xz", recipe_packed)]


def exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("KesilmiÅŸ arÅŸiv/tarif")
    return data


def consume_recipe(unique, recipe, expected, destinations=None):
    """CDC dosya tarifini doÄŸrula, SHA hesapla, isteÄŸe baÄŸlÄ± dosyalarÄ± oluÅŸtur."""
    seen = set()
    unique_size = unique.stat().st_size
    with unique.open("rb") as data, recipe.open("rb") as stream:
        while marker := stream.read(1):
            if marker != b"F":
                raise ValueError("Bozuk CDC tarif iÅŸareti")
            length, = struct.unpack("<I", exact(stream, 4))
            if length != 12:
                raise ValueError("Bozuk CDC kimlik uzunluÄŸu")
            ident = exact(stream, length).decode("ascii")
            _, _, size = struct.unpack("<IqQ", exact(stream, 20))
            exact(stream, 32)  # Native BLAKE3 yerine tabloda saklÄ± SHA-256 denetlenir.
            if ident not in expected or ident in seen or size != expected[ident]["size"]:
                raise ValueError("CDC tarifi dosya tablosuyla uyuÅŸmuyor")
            seen.add(ident)
            digest = hashlib.sha256()
            target = open(destinations[ident], "xb") if destinations is not None else None
            try:
                remaining = size
                while remaining:
                    offset, count = struct.unpack("<QI", exact(stream, 12))
                    if not 0 < count <= min(remaining, 256 << 10) or offset + count > unique_size:
                        raise ValueError("GeÃ§ersiz CDC parÃ§a sÄ±nÄ±rÄ±")
                    data.seek(offset)
                    chunk = exact(data, count)
                    digest.update(chunk)
                    if target is not None:
                        target.write(chunk)
                    remaining -= count
                if digest.hexdigest() != expected[ident]["sha256"]:
                    raise ValueError(f"CDC SHA-256 uyuÅŸmazlÄ±ÄŸÄ±: {ident}")
            finally:
                if target is not None:
                    target.close()
    if seen != set(expected):
        raise ValueError("CDC tarifinde eksik dosya")


def make_table(entries, blobs, root_info):
    descriptors = [{"key": key, "codec": codec, "size": path.stat().st_size,
                    "sha256": sha256(path)} for key, codec, path in blobs]
    table = {"version": 1, "root": root_info, "entries": entries, "blobs": descriptors}
    raw = json.dumps(table, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_TABLE_RAW:
        raise ValueError("Dosya tablosu Ã§ok bÃ¼yÃ¼k")
    encoded = lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME)
    if len(encoded) > MAX_TABLE:
        raise ValueError("SÄ±kÄ±ÅŸtÄ±rÄ±lmÄ±ÅŸ dosya tablosu Ã§ok bÃ¼yÃ¼k")
    return encoded


def pack(source, output, esik=1.0):
    if not math.isfinite(esik) or not 0 <= esik < 100:
        raise ValueError("--esik 0 dahil, 100 hariÃ§ bir yÃ¼zde olmalÄ±")
    if sys.byteorder != "little":
        raise ValueError("nsk_cdc little-endian makine gerektirir")
    root, output = Path(source).resolve(), Path(output).resolve()
    if not root.is_dir() or output.is_relative_to(root):
        raise ValueError("Kaynak dizin olmalÄ±, arÅŸiv kaynak dizinin dÄ±ÅŸÄ±nda olmalÄ±")
    # Genel araÃ§larÄ±n eksikliÄŸi iki yÃ¶ntemden birini sessizce elemez.
    for name in ("xz", "zstd", "cdc"):
        tool(name)
    root_stat = root.stat()
    root_info = {"mode": stat.S_IMODE(root_stat.st_mode), "mtime_ns": root_stat.st_mtime_ns}
    diagnostics = []
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nsk4-", dir=output.parent) as temporary:
        work = Path(temporary)
        stage = work / "stage"
        stage.mkdir()
        entries = snapshot(root, stage)
        special_blobs = []
        special_directory = work / "special-payloads"
        special_directory.mkdir()
        for entry in entries:
            if entry["kind"] != "file":
                continue
            with tempfile.TemporaryDirectory(prefix="candidate-", dir=work) as candidate_dir:
                result = plan_special(entry, stage / entry["id"], Path(candidate_dir), esik, diagnostics)
                if result:
                    method, payload = result
                    entry["method"] = method
                    if method != "store":
                        saved = special_directory / entry["id"]
                        shutil.copyfile(payload, saved)
                        payload = saved
                    special_blobs.append((entry["id"], method, payload))
            print(f"{entry['name']!r} -> {entry['method']}", file=sys.stderr, flush=True)
        blobs = special_blobs + build_general(entries, stage, work / "hybrid")
        table = make_table(entries, blobs, root_info)
        strategy = "hybrid"
        if special_blobs:
            all_entries = [dict(e, method="cdc") if e["kind"] == "file" else dict(e) for e in entries]
            all_blobs = build_general(all_entries, stage, work / "all-general")
            all_table = make_table(all_entries, all_blobs, root_info)
            if len(all_table) + sum(p.stat().st_size for _, _, p in all_blobs) <= (
                    len(table) + sum(p.stat().st_size for _, _, p in blobs)):
                entries, blobs, table = all_entries, all_blobs, all_table
                strategy = "all-cdc"
        archive = work / "complete.nsk4"
        with archive.open("wb") as stream:
            stream.write(HEADER.pack(MAGIC, len(table), hashlib.sha256(table).digest()))
            stream.write(table)
            for _, _, payload in blobs:
                with payload.open("rb") as data:
                    shutil.copyfileobj(data, stream, BUFFER)
        # GerÃ§ek okuyucuyla tÃ¼m kapsayÄ±cÄ± yeniden aÃ§Ä±lmadan sonuÃ§ yayÄ±mlanmaz.
        unpack(archive, work / "verify")
        os.replace(archive, output)
    return {"files": sum(e["kind"] == "file" for e in entries), "bytes": output.stat().st_size,
            "strategy": strategy, "methods": dict(Counter(e["method"] for e in entries if e["kind"] == "file")),
            "fallbacks": diagnostics, "verified": True}


def valid_int(value, minimum=0):
    return type(value) is int and value >= minimum


def validate_table(table):
    if not isinstance(table, dict) or table.get("version") != 1:
        raise ValueError("Desteklenmeyen NSK4 sÃ¼rÃ¼mÃ¼")
    entries, blobs = table["entries"], table["blobs"]
    if not isinstance(entries, list) or not isinstance(blobs, list):
        raise ValueError("Bozuk dosya tablosu")
    names, ids, blob_map = {}, set(), {}
    for entry in entries:
        name = safe_name(entry["name"])
        if name in names or entry["kind"] not in ("dir", "file"):
            raise ValueError("Yinelenen ad/geÃ§ersiz girdi")
        names[name] = entry["kind"]
        if not valid_int(entry["mode"]) or entry["mode"] > 0o7777 or type(entry["mtime_ns"]) is not int:
            raise ValueError("GeÃ§ersiz dosya kip/zamanÄ±")
        if entry["kind"] == "file":
            ident = entry["id"]
            if not isinstance(ident, str) or len(ident) != 12 or not ident.isascii() or not ident.isdigit() or ident in ids:
                raise ValueError("GeÃ§ersiz dosya kimliÄŸi")
            ids.add(ident)
            if entry["method"] not in METHODS or not valid_int(entry["size"]):
                raise ValueError("GeÃ§ersiz yÃ¶ntem/boyut")
            bytes.fromhex(entry["sha256"])
            if len(entry["sha256"]) != 64:
                raise ValueError("GeÃ§ersiz SHA-256")
    for name in names:
        for parent in PurePosixPath(name).parents:
            if str(parent) != "." and names.get(str(parent)) != "dir":
                raise ValueError("Eksik/Ã§akÄ±ÅŸan Ã¼st dizin")
    expected = {e["id"]: e["method"] for e in entries if e.get("method") in METHODS - {"cdc"}}
    if any(e.get("method") == "cdc" for e in entries):
        expected.update(unique=None, recipe="xz")
    for blob in blobs:
        key = blob["key"]
        if key not in expected or key in blob_map or not valid_int(blob["size"]):
            raise ValueError("GeÃ§ersiz/yinelenen yÃ¼k")
        allowed = {"xz", "zstd", "ppmd", "brotli"} if key == "unique" else {expected[key]}
        if blob["codec"] not in allowed or len(bytes.fromhex(blob["sha256"])) != 32:
            raise ValueError("GeÃ§ersiz yÃ¼k kodlayÄ±cÄ±sÄ±/Ã¶zeti")
        blob_map[key] = blob
    if set(blob_map) != set(expected):
        raise ValueError("Eksik yÃ¼k")
    root = table["root"]
    if not valid_int(root["mode"]) or root["mode"] > 0o7777 or type(root["mtime_ns"]) is not int:
        raise ValueError("GeÃ§ersiz kÃ¶k kip/zamanÄ±")


def metadata(path, entry):
    os.chmod(path, entry["mode"])
    os.utime(path, ns=(entry["mtime_ns"], entry["mtime_ns"]))


def unpack(archive, destination):
    # Yeni hedef + Ã¶zel geÃ§ici kÃ¶k, mevcut symlink/Ã¼zerine yazma yarÄ±ÅŸÄ±nÄ± engeller.
    destination = Path(os.path.abspath(destination))
    if os.path.lexists(destination):
        raise FileExistsError(f"Hedef mevcut, yeni dizin kullanÄ±n: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nsk4-unpack-", dir=destination.parent) as temporary:
        work = Path(temporary)
        restored = work / "restored"
        restored.mkdir()
        with open(archive, "rb") as stream:
            magic, length, digest = HEADER.unpack(exact(stream, HEADER.size))
            if magic != MAGIC or length > MAX_TABLE:
                raise ValueError("GeÃ§ersiz NSK4 baÅŸlÄ±ÄŸÄ±")
            encoded = exact(stream, length)
            if hashlib.sha256(encoded).digest() != digest:
                raise ValueError("Tablo SHA-256 uyuÅŸmazlÄ±ÄŸÄ±")
            decoder = lzma.LZMADecompressor(memlimit=1 << 30)
            raw = decoder.decompress(encoded, max_length=MAX_TABLE_RAW + 1)
            if len(raw) > MAX_TABLE_RAW or not decoder.eof or decoder.unused_data:
                raise ValueError("GeÃ§ersiz/Ã§ok bÃ¼yÃ¼k tablo")
            table = json.loads(raw)
            validate_table(table)
            paths = {}
            for index, blob in enumerate(table["blobs"]):
                path = work / f"blob-{index}"
                remaining = blob["size"]
                digest = hashlib.sha256()
                with path.open("wb") as output:
                    while remaining:
                        chunk = exact(stream, min(remaining, BUFFER))
                        output.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                if digest.hexdigest() != blob["sha256"]:
                    raise ValueError("YÃ¼k SHA-256 uyuÅŸmazlÄ±ÄŸÄ±")
                paths[blob["key"]] = path
            if stream.read(1):
                raise ValueError("ArÅŸiv sonunda fazladan veri")
        entries = table["entries"]
        for entry in sorted(entries, key=lambda e: e["name"].count("/")):
            if entry["kind"] == "dir":
                (restored / entry["name"]).mkdir()
        general = {e["id"]: e for e in entries if e.get("method") == "cdc"}
        if general:
            codecs = {b["key"]: b["codec"] for b in table["blobs"]}
            unique, recipe = work / "unique", work / "recipe"
            decompress(paths["unique"], unique, codecs["unique"])
            decompress(paths["recipe"], recipe, "xz")
            consume_recipe(unique, recipe, general,
                           {ident: restored / e["name"] for ident, e in general.items()})
        for entry in entries:
            if entry["kind"] != "file":
                continue
            path = restored / entry["name"]
            if entry["method"] != "cdc":
                directory = work / ("decode-" + entry["id"])
                directory.mkdir()
                special_decode(entry["method"], paths[entry["id"]], path, directory)
            if path.stat().st_size != entry["size"] or sha256(path) != entry["sha256"]:
                raise ValueError(f"Dosya SHA-256 uyuÅŸmazlÄ±ÄŸÄ±: {entry['name']}")
        # Dosyalar doÄŸrulandÄ±ktan sonra en derin dizinden kÃ¶ke doÄŸru metaveri.
        for entry in sorted(entries, key=lambda e: e["name"].count("/"), reverse=True):
            metadata(restored / entry["name"], entry)
        metadata(restored, table["root"])
        if os.path.lexists(destination):
            raise FileExistsError(f"Hedef iÅŸlem sÄ±rasÄ±nda oluÅŸtu: {destination}")
        os.rename(restored, destination)
    return {"files": sum(e["kind"] == "file" for e in entries), "verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    packing = commands.add_parser("pack")
    packing.add_argument("source")
    packing.add_argument("archive")
    packing.add_argument("--esik", type=float, default=1.0, help="Ã–zel yÃ¶ntem iÃ§in asgari kazanÃ§ yÃ¼zdesi (1)")
    unpacking = commands.add_parser("unpack")
    unpacking.add_argument("archive")
    unpacking.add_argument("destination")
    args = parser.parse_args()
    try:
        result = (pack(args.source, args.archive, args.esik) if args.command == "pack"
                  else unpack(args.archive, args.destination))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, struct.error, lzma.LZMAError) as error:
        parser.exit(1, f"HATA: {error}\n")
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()

