# AGENTS.md

## Project

Python 3.10+ hybrid RSA-AES API security prototype. AES-GCM encrypts payloads; RSA-OAEP SHA-256 encrypts the AES key.

## Layout

- `src/security_engine.py` — `HybridSecurityEngine` (all crypto: keygen, encrypt, decrypt)
- `src/app.py` — Flask app with `create_app(private_key_path)` factory and endpoint `POST /api/v1/secure-data`
- `src/generate_keys.py` — RSA key pair generator (writes to `keys/`)
- `src/test_pages.py` — Blueprint `test_bp` with demo endpoints `/test/success`, `/test/error-400`, `/test/error-500`
- `tests/test_security_engine.py` — unit tests for crypto round-trips
- `tests/test_app.py` — Flask endpoint tests using `tmp_path` and `app.test_client()`
- `tests/test_test_pages.py` — tests for the `test_bp` blueprint endpoints

`keys/` is the canonical key directory. `src/keys/` is stale — do not rely on it.

## Verified commands

```powershell
python -m venv .venv; .venv\Scripts\activate; pip install -r requirements.txt
python -m src.generate_keys      # generate RSA-2048 keys to keys/
flask --app src.app run --debug  # start dev server
python -m pytest                 # run all tests
```

Run everything from repo root so imports resolve.

## Import quirks

- `src/app.py` and `src/generate_keys.py` wrap imports in `try/except ModuleNotFoundError` to handle both `python src/app.py` and `flask --app` invocation styles. Keep this pattern if adding new modules.
- `src/app.py` imports `test_bp` from `src/test_pages.py` **inside** `create_app()`, not at module top level, to avoid circular imports (test routes import `create_app` to call the real endpoint).
- `src/test_pages.py` route functions lazily import `create_app` with the same `try/except` pattern.

## Test conventions

- Tests use `pytest` (listed in `requirements.txt`, already configured).
- `test_app.py` uses `tmp_path` fixture + `create_app(key_path)` to avoid filesystem coupling.
- `test_security_engine.py` generates ephemeral RSA key pairs in-memory — no keys/ needed.

## .gitignore

- `keys/*.pem` — do not commit generated keys.
- `AGENTS.md` — this file is intentionally gitignored.

## Unused dependency

`pycryptodome` in `requirements.txt` is not imported anywhere. Only `cryptography` is used for all crypto operations.

## Style

PEP 8, 4-space indent, no comments unless requested. `snake_case` for functions/vars, `PascalCase` for classes.
