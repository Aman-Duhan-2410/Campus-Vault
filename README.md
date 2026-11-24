# CampusVault

A Flask student resource-sharing platform for notes, assignments, lab manuals and previous-year papers.

## Features
- Registration/login with Werkzeug password hashing
- Browse, search and filter academic resources
- Upload/download resources with randomized storage filenames
- Bookmarks, ratings, comments and reports
- Per-user upload management
- CSRF validation for POST forms
- Basic login-attempt throttling
- Upload size and extension restrictions plus basic file-signature checks

## Run locally
1. Install Python 3.10+
2. Create and activate a virtual environment
3. Install dependencies: `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and set `SECRET_KEY` (export variables in your shell; the app does not automatically load .env files).
5. Run: `python app.py`
6. Visit `http://127.0.0.1:5000`

For development, the app uses a temporary fallback secret if `SECRET_KEY` is not set. Set a stable secret before deployment.

## Run tests

Install development dependencies with `pip install -r requirements-dev.txt`, then run `pytest`.

## Production checklist
- Set `FLASK_ENV=production` and a long random `SECRET_KEY`
- Use HTTPS so secure session cookies are enabled
- Run with a production WSGI server (e.g. Gunicorn; install it separately) rather than `python app.py`
- Put uploads on persistent storage and back them up
- Restrict upload types further if your use case permits; signature checks are basic and are not malware scanning
- Configure reverse proxy limits and trusted proxy settings carefully
- Add a privacy policy, terms, copyright/takedown process and moderation workflow before opening to the public
- This MVP login throttling is SQLite-backed and not a substitute for a dedicated distributed rate limiter on multi-instance deployments

## Important
CampusVault is a learning project. Do not treat it as production-secure without a security review, tests, malware scanning, operational monitoring and deployment-specific configuration.

## Phase 2: Admin moderation
- User accounts have `student` / `admin` roles and `active` / `disabled` status.
- Configure an initial administrator by setting `ADMIN_EMAIL` to the email address of an already registered account before starting the app. The app promotes that account on startup.
- Visit `/admin` while logged in as an administrator to review pending reports, dismiss reports or remove reported resources, disable/enable accounts, and grant/revoke admin roles.
- Admin actions are POST-only and protected by login, role checks, and CSRF validation. Admins cannot disable themselves or change their own role.
- Existing databases are migrated automatically by adding role/status columns without deleting records.

## Phase 3 — Testing and quality checks

A pytest suite is included in `tests/test_security.py` covering CSRF enforcement, registration/logout, duplicate registration, upload signature checks, admin authorization and moderation, protection of the last administrator, missing-resource responses, and rating validation.

Run the tests after installing dependencies:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The source can be syntax-checked without installing Flask:

```bash
python -m py_compile app.py tests/test_security.py
```

**Environment note:** automated tests have been added, but were not executed successfully in the current build environment because Flask is not installed. Install the project requirements before treating the test suite as verified.

## Phase 4 — Deployment files
- `render.yaml`: Render Blueprint using a persistent disk for SQLite and uploads (single instance).
- `Procfile`: production Gunicorn command.
- `Dockerfile`: container image with `/data` persistence support.
- `DEPLOYMENT.md`: deployment instructions and persistence/scaling caveats.
- `UPLOAD_FOLDER` and `DATABASE_PATH` can be configured through environment variables.

For deployment, do not commit `.env`, secrets, database files, or uploads. This SQLite deployment is for a single instance; PostgreSQL and object storage are recommended before scaling.


## Phase 5: PDF Study Tools (local NLP)

Logged-in users can open **AI Study Tools** from PDF resource details. The feature extracts text (up to 80 pages), ranks a short sentence summary, lists frequent terms, and creates fill-in-the-blank practice prompts. It is implemented with local text heuristics and PyMuPDF; it does not call a hosted AI API, so describe it accurately as NLP-assisted study tooling rather than a generative AI model. Scanned PDFs require OCR (not included).
