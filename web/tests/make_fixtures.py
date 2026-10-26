"""Reference encoder for the web receiver tests.

Builds small .dropack archives (ZIP32 and ZIP64, stored and deflated) and
encrypts them with an independent Python implementation of the format in
Dropack/Core/EncryptedPackage.swift. Usage: python3 make_fixtures.py OUTDIR
"""
import hashlib
import json
import os
import struct
import sys
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"DROPACKE"
APPLE_EPOCH = 978307200


def zip_archive(entries, zip64=False):
    local, central = bytearray(), bytearray()
    for name, payload, deflate in entries:
        raw_name = name.encode()
        crc = zlib.crc32(payload)
        if deflate:
            c = zlib.compressobj(6, zlib.DEFLATED, -15)
            data = c.compress(payload) + c.flush()
        else:
            data = payload
        method = 8 if deflate else 0
        offset = len(local)
        if zip64:
            lextra = struct.pack("<HHQQ", 1, 16, len(payload), len(data))
            cextra = struct.pack("<HHQQQ", 1, 24, len(payload), len(data), offset)
            psize = usize = 0xFFFFFFFF
            coff = 0xFFFFFFFF
        else:
            lextra = cextra = b""
            psize, usize, coff = len(data), len(payload), offset
        local += struct.pack("<IHHHHHIIIHH", 0x04034B50, 45, 0x0800, method, 0, 0x5021, crc, psize, usize, len(raw_name), len(lextra))
        local += raw_name + lextra + data
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 0x0300 | 45, 45, 0x0800, method, 0, 0x5021, crc, psize, usize,
                               len(raw_name), len(cextra), 0, 0, 0, 0o100644 << 16, coff)
        central += raw_name + cextra
    out = local + central
    if zip64:
        z64 = len(out)
        out += struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, len(entries), len(entries), len(central), len(local))
        out += struct.pack("<IIQI", 0x07064B50, 0, z64, 1)
        out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    else:
        out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), len(local), 0)
    return bytes(out)


def encrypt(plain, password, iterations=10000, chunk=4096, salt=None, prefix=None):
    salt = salt or os.urandom(16)
    prefix = prefix or os.urandom(4)
    header = MAGIC + bytes([1, 1]) + struct.pack(">I", iterations) + salt + struct.pack(">I", chunk) + prefix
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, 32)
    aes = AESGCM(key)
    out = bytearray(header)
    chunks = [plain[i:i + chunk] for i in range(0, len(plain), chunk)] or [b""]
    for index, part in enumerate(chunks):
        nonce = prefix + struct.pack(">Q", index)
        aad = header + bytes([1 if index == len(chunks) - 1 else 0])
        out += aes.encrypt(nonce, part, aad)
    return bytes(out)


def sample_album(zip64=False):
    photo = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 40 + b"\xff\xd9"
    video = b"\x00\x00\x00\x18ftypqt  " + bytes((i * 7919 + 13) % 251 for i in range(9000))
    paired = b"\x00\x00\x00\x18ftypqt  " + b"live" * 700
    preview = b"\xff\xd8\xff\xe0preview\xff\xd9"
    ids = ["5B0C5E1E-3A7B-4E36-9C10-2A1F0F6A0001", "5B0C5E1E-3A7B-4E36-9C10-2A1F0F6A0002"]
    sha = lambda b: hashlib.sha256(b).hexdigest()
    manifest = {
        "version": 1,
        "album": {"id": "8D2B6C1A-0000-4000-8000-000000000001", "snapshotID": "8D2B6C1A-0000-4000-8000-000000000002",
                  "revision": 2, "title": "京都 · 2026 秋", "senderName": "PRO.X",
                  "createdAt": 1793000000 - APPLE_EPOCH, "updatedAt": 1793000000 - APPLE_EPOCH},
        "items": [
            {"id": ids[0], "photoPath": f"media/{ids[0]}/original.jpg", "videoPath": f"media/{ids[0]}/paired.mov",
             "isLivePhoto": True, "photoSHA256": sha(photo), "videoSHA256": sha(paired),
             "creationDate": 1792000000 - APPLE_EPOCH, "previewPath": f"__dropack_previews/{ids[0]}.preview"},
            {"id": ids[1], "videoPath": f"media/{ids[1]}/original.mov", "isLivePhoto": False,
             "videoSHA256": sha(video), "creationDate": 1792000100 - APPLE_EPOCH},
        ],
    }
    entries = [
        (f"media/{ids[0]}/original.jpg", photo, False),
        (f"media/{ids[0]}/paired.mov", paired, False),
        (f"__dropack_previews/{ids[0]}.preview", preview, False),
        (f"media/{ids[1]}/original.mov", video, False),
        ("dropack-manifest.json", json.dumps(manifest, ensure_ascii=False).encode(), False),
    ]
    return zip_archive(entries, zip64=zip64), manifest


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    album, manifest = sample_album()
    (out / "album.dropack").write_bytes(album)
    (out / "album64.dropack").write_bytes(sample_album(zip64=True)[0])
    (out / "album.json").write_text(json.dumps(manifest, ensure_ascii=False))
    (out / "album-locked.dropack").write_bytes(encrypt(album, "dropack-test"))
    plain = zip_archive([("photos/a.jpg", b"\xff\xd8" + b"A" * 3000, True), ("clips/b.mp4", b"B" * 5000, False),
                         ("__MACOSX/._a.jpg", b"x", False), ("notes.txt", b"hi", True)])
    (out / "plain.zip").write_bytes(plain)


if __name__ == "__main__":
    main(sys.argv[1])
