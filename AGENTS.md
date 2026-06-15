# Repository Guidelines

## Project Structure & Module Organization

This repository is a small Python project for a hybrid RSA-AES API security prototype. Keep source code in `src/`. The current core module is `src/security_engine.py`, which contains `HybridSecurityEngine` for AES-GCM payload encryption and RSA-OAEP AES-key encryption.

Use `.codex/PLAN.md` as the local implementation roadmap. Add future Flask routes, request handlers, or API glue under `src/` rather than at the repository root. Put tests in a top-level `tests/` directory when they are added, using names such as `tests/test_security_engine.py`.

## Build, Test, and Development Commands

Create and activate a virtual environment before installing dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

For a quick dependency install matching the current plan:

```bash
pip install flask cryptography pycryptodome
```

Run modules or scripts from the repository root so imports resolve consistently. When a Flask entry point is added, prefer a documented command such as:

```bash
flask --app src.app run --debug
```

## Coding Style & Naming Conventions

Use Python 3.10+ and follow PEP 8 with 4-space indentation. Prefer clear, small functions and explicit names. Use `snake_case` for functions and variables, `PascalCase` for classes, and uppercase names for constants. Keep cryptographic behavior direct and readable; avoid broad refactors unless they simplify the current architecture.

Do not add comments unless requested. If documentation is needed, prefer short docstrings for public classes or functions.

## Testing Guidelines

No test framework is currently configured. When adding tests, use `pytest` and keep test files under `tests/`. Name tests after expected behavior, for example `test_encrypt_payload_returns_base64_nonce_and_ciphertext`.

Recommended command after tests are added:

```bash
pytest
```

Prioritize tests for encryption/decryption round trips, invalid keys, malformed Base64 payloads, and Flask endpoint request validation.

## Commit & Pull Request Guidelines

This repository currently has no commit history, so there is no established commit convention. Use concise imperative messages such as `Add hybrid security engine tests` or `Implement secure data endpoint`.

Pull requests should include a short summary, changed files, test results, and any security-sensitive behavior changes. Include sample request/response JSON when API behavior changes.

## Security & Configuration Tips

Never commit private keys, API keys, generated secrets, or local virtual environments. Store runtime secrets in environment variables or ignored local files. Use AES-GCM with unique nonces and RSA-OAEP with SHA-256 as described in the project plan.
