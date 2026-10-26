# Dropack web receiver

`receive/` is a static page that opens `.dropack` packages, password-protected
Dropack packages and ordinary ZIPs in any modern browser (Android, Windows,
Linux, macOS). Files are read with random access and decrypted locally with
WebCrypto; nothing is uploaded, so the page can be hosted anywhere static.

- `receive/dropack.js` – ZIP/ZIP64 reader, manifest parsing, and random-access
  decryption of the format specified in `Dropack/Core/EncryptedPackage.swift`.
- `receive/index.html` – the page (Chinese/English by browser language).
- `tests/make_fixtures.py` – independent Python encoder for fixtures.

```sh
python3 web/tests/make_fixtures.py /tmp/dropack-fixtures
DROPACK_FIXTURES=/tmp/dropack-fixtures node --test web/tests/
python3 -m http.server -d web/receive 8000   # then open http://localhost:8000
```

The `Web receiver` workflow tests every push and deploys `receive/` to GitHub
Pages from `main` once Pages is enabled with source "GitHub Actions".
