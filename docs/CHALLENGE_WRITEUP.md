# TrustVault challenge write-up

## Project summary

TrustVault is a Python/FastAPI application with an HTML, CSS, and JavaScript frontend. It uses SQLAlchemy with SQLite for local development and includes a PostgreSQL option in Docker Compose. Its core workflow is private document upload, owner-controlled read-only sharing, access revocation, and audit review.

## Permission model

Global account roles are `admin` and `user`. New registrations are regular users; assigning Admin is a separate trusted local operation through `scripts/set_admin_role.py`. Admin authorization is enforced by the API dependency, not just by the frontend. Admin can access administrative user, login activity, and system audit endpoints, but Admin does not bypass document ownership or grants.

Owner and Viewer are document-specific relationships, not separate global account roles. A document owner can list, download, edit, delete, and grant/revoke access to their documents. A Viewer is a regular user with an active `read` permission and can list/download shared documents only. There is no Edit-level share permission. Revocation is checked again on later requests. Authenticated attempts to access an unavailable or unauthorized document receive `404` to avoid disclosing whether it exists.

## Audit protection

The application records account login outcomes, logout, document operations, permission changes, and selected denied document/permission operations. Audit endpoints are user-scoped or Admin-only; CSV export is available. On SQLite, initialization creates triggers that reject ordinary audit-row updates and deletes.

This is not tamper-proof audit storage. The SQLite database owner can alter the database outside the application. PostgreSQL does not receive equivalent append-only triggers in the current implementation. There is no externally replicated or cryptographically chained log. Audit immutability must not be claimed for PostgreSQL or against a database administrator.

## Demo and automated verification

The safe demo workflow requires three accounts to be registered through the application. The Admin account is promoted explicitly from a trusted shell. `scripts/seed_data.py` validates the selected roles and creates only synthetic private documents, a read-only Viewer grant, a notification, and matching audit events. It does not create users, embed credentials, or set passwords.

The exact endpoint access boundaries and a timed walkthrough are documented in [the authorization guide](./API_AUTHORIZATION.md) and [the five-minute demo](./FIVE_MINUTE_DEMO.md). The local full-suite command `.\.venv\Scripts\python.exe -m pytest` completed with **56 passed, 0 failed**, and one Starlette/httpx deprecation warning. The suite includes mocked Google and SMTP integrations; it does not establish live provider delivery or deployed-system behavior.

## AI use

AI assistance was used during development to inspect the existing implementation, help debug and implement changes, suggest regression tests, and draft/review project documentation. The prompt log in [PROMPTS.md](../PROMPTS.md) records representative project requests. AI assistance is not an independent security certification: the human project owner must review generated changes, run the tests, and verify behavior in the target environment.

## Limitations and unfinished work

- Sharing is read-only; Edit permission is not implemented.
- Login and password-reset rate limiting was not found.
- Logout clears the browser session and records an event, but a copied stateless bearer token remains usable until expiry.
- SQLite audit append-only triggers are not implemented for PostgreSQL.
- The file-storage implementation is local to one application instance. A named volume persists files on one host but does not provide shared storage for replicas.
- Database setup uses `create_all` and hand-written additive changes, not a versioned migration framework.
- Real SMTP delivery, live Google OAuth, PostgreSQL runtime behavior, container restart/recovery, backup restoration, and production hosting have not been verified by this project write-up.
- Production readiness still requires rate limiting, reviewed secret handling, HTTPS and proxy configuration, backups, provider verification, deployment-specific testing, and a documented schema migration process.

## Submission statement

This write-up describes the implementation and evidence available in the repository; it does not claim that the project has been deployed or independently penetration-tested. Attach the exact test output from the final local test run when submitting.
