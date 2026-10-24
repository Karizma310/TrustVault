# TrustVault — Secure Document Sharing with Audit Trail

## Overview
TrustVault is a secure document-sharing application designed to manage document access using user roles and permissions. It aims to protect private files and maintain an audit trail of important activities.

## Key Features
- User authentication and account access
- Admin role plus per-document Owner and read-only Viewer access
- Document upload and download
- Permission-based document sharing
- Grant and revoke document access
- Audit logging for important activities
- Notifications for supported user actions
- Admin APIs for user and login activity management

## Technology Stack
- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS, JavaScript
- **API Documentation:** Swagger UI
- **Database:** SQLite for local development; PostgreSQL with psycopg for Docker Compose deployment
- **Testing:** pytest

## Project Structure
- `app/` — Application source code
- `scripts/` — Utility and setup scripts
- `tests/` — Automated tests
- `.env.example` — Example environment configuration
- `THREATS.md` — Security threat analysis
- `PROMPTS.md` — AI assistance and development log

## Setup Instructions
1. Use Python 3.13 (the Docker image is based on Python 3.13).
2. Create and activate a virtual environment, then install dependencies:

   ```powershell
   py -3.13 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env`. Set a unique `TRUSTVAULT_SECRET_KEY` with at least 32 characters. Do not use the example placeholder or commit `.env`.
4. Initialize the local database:

   ```powershell
   python .\scripts\setup_db.py
   ```

5. Start the API and frontend:

   ```powershell
   python -m uvicorn app.main:app --reload --port 8000
   ```

6. Open `http://127.0.0.1:8000/`. FastAPI serves the frontend; API documentation is at `http://127.0.0.1:8000/docs`.

## Safe demo-data setup

The demo seed script creates two synthetic `.txt` documents in the configured private upload directory: one owned-only document and one document shared read-only with the Viewer. It also records the fixture creation and permission grant in the audit log. It does not create accounts, set or change passwords, or assign administrator roles.

1. Register three separate accounts from the website. Use unique demo email addresses and choose strong passwords yourself; registration requires at least 12 characters. Do not reuse real account passwords.
2. From a trusted local shell using the same project `.env` and database as the application, promote only the account you intend to use as Admin:

   ```powershell
   python .\scripts\set_admin_role.py admin@example.com
   ```

   The script changes the role of the named registered account; it does not accept or set a password. Do not use `--only-admin` unless you explicitly intend to demote any other administrators.
3. Seed the sample documents and read-only Viewer access:

   ```powershell
   python .\scripts\seed_data.py `
     --admin-email admin@example.com `
     --owner-email owner@example.com `
     --viewer-email viewer@example.com
   ```

   The seed command verifies that the selected account already has the Admin role and that Owner and Viewer are regular User accounts. It refuses account-role mismatches, uses no default credentials, and can be rerun without duplicating the sample data. Admin is not given implicit access to the Owner's documents.
4. Sign in to the app with the passwords you selected during registration. Follow [the five-minute demo](./docs/FIVE_MINUTE_DEMO.md) to demonstrate upload, access denial, grant, download, revocation, and audit events.

For the precise authorization boundary and denial behavior of each API endpoint, see the [endpoint authorization guide](./docs/API_AUTHORIZATION.md). The [challenge write-up](./docs/CHALLENGE_WRITEUP.md) summarizes the permission model, audit controls, AI use, limitations, and work still needed.

## Testing
Run the automated tests using:

`python -m pytest`

## Security
- Keep private configuration and secrets in `.env`.
- Never commit passwords, API keys, access tokens, or private documents.
- Verify user permissions before allowing document access.
- Review `THREATS.md` for security risks and mitigations.

## Deployment preparation (not deployed)

The implemented deployment path uses the Dockerfile and Docker Compose: the API runs with PostgreSQL and named persistent volumes for database data and private uploads. A practical single-host setup is a Linux VPS running Docker Compose behind a TLS reverse proxy such as Caddy. Keep the application and PostgreSQL ports private; expose only HTTPS through the proxy. Compose binds the API to `127.0.0.1:8000`, which is suitable for a reverse proxy on the same host.

### Beginner deployment steps

1. Create a Linux host with Docker Engine and the Docker Compose plugin. Point a DNS name to the host.
2. Copy the project to the host using a private deployment method. Do not copy `.env`, `.venv`, `trustvault.db`, `private_uploads`, or the local Google OAuth export.
3. Create `.env` from `.env.example`. Set these environment variable names in the deployment secret store or the untracked `.env`: `TRUSTVAULT_SECRET_KEY`, `POSTGRES_PASSWORD`, `TRUSTVAULT_FRONTEND_LOGIN_URL`, `TRUSTVAULT_GOOGLE_CLIENT_ID`, `TRUSTVAULT_GOOGLE_CLIENT_SECRET`, `TRUSTVAULT_GOOGLE_REDIRECT_URI`, `TRUSTVAULT_SMTP_HOST`, `TRUSTVAULT_SMTP_PORT`, `TRUSTVAULT_SMTP_USERNAME`, `TRUSTVAULT_SMTP_PASSWORD`, `TRUSTVAULT_SMTP_FROM_EMAIL`. Use a strong generated application key and database password. SMTP authentication requires both SMTP username and password.
   For Render, set `TRUSTVAULT_DATABASE_URL` to the PostgreSQL connection URL provided by Render. The application accepts Render's standard `postgresql://` URL and normalizes its dialect to `postgresql+psycopg://` for the installed psycopg 3 driver. Do not paste database URLs or passwords into source files or support logs.
4. Set `TRUSTVAULT_FRONTEND_LOGIN_URL` to `https://your-domain.example/app/templates/login.html`. Set `TRUSTVAULT_GOOGLE_REDIRECT_URI` to `https://your-domain.example/api/auth/google/callback` and register the same callback with Google. Do not use localhost URLs in production. Same-origin frontend and API hosting avoids browser CORS configuration; for a separately hosted frontend, set `TRUSTVAULT_CORS_ORIGINS` to its exact HTTPS origin and configure its `trustvault-api-base` metadata.
5. Configure Caddy or another reverse proxy to terminate HTTPS and proxy requests to `127.0.0.1:8000`. Do not expose PostgreSQL port 5432 publicly.
6. Start the stack from the project directory:

   ```sh
   docker compose up --build -d
   docker compose ps
   ```

   Compose sets `TRUSTVAULT_DATABASE_URL` to the PostgreSQL service and mounts named persistent volumes for PostgreSQL and `/app/private_uploads`. Verify `https://your-domain.example/health` returns `{"status":"ok"}`.
7. Register the intended administrator through the website, then use trusted host access to assign only that account:

   ```sh
   docker compose exec app python scripts/set_admin_role.py admin@example.com --only-admin
   ```

   Replace the example with the registered Admin’s email. `--only-admin` makes that account the sole Admin; do not run it for ordinary users.
8. Test registration, login, logout, upload/download, share/revoke access, Admin APIs, and password reset over HTTPS. Mocked SMTP tests do not prove provider delivery; send a real reset email and confirm receipt before relying on recovery in production.

### Deployment limitations

- Database initialization uses SQLAlchemy `create_all` plus custom additive migrations, not Alembic or another versioned migration tool. Plan and test a schema migration process before future production schema changes.
- The file backend is local to one application instance. Compose’s named volume persists files on one host but does not share them across app replicas or hosts. Use private object storage or a shared filesystem before horizontal scaling.
- SQLite audit immutability triggers are installed only for SQLite. PostgreSQL audit rows are protected by application access controls, not a database append-only trigger.
- Logout records an event and clears the browser token, but a copied stateless bearer token remains usable until expiry. Add server-side revocation if immediate invalidation is required.
- Real Google OAuth and SMTP delivery need provider testing; automated tests mock these external services.

No deployment has been performed.

## Author
[Your Name]
