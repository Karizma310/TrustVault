# TrustVault threat model

## Scope and assets

TrustVault stores account records, password hashes, bearer tokens held by clients, private uploaded files, document permissions, user preferences, notifications, and audit records. The trust boundaries are the browser/API, authenticated users, the database, private file storage, and external OAuth/SMTP providers.

## Verified controls in the current implementation

| Threat | Current control | Evidence boundary |
|---|---|---|
| Unauthorized private-document access | Every download checks ownership or an active `read` permission. Missing/revoked permission returns `404` and is audited. | Exercised by `tests/test_revocation.py` and `tests/test_security.py`; test evidence is local and does not cover a deployed host. |
| Unauthorized Admin actions | Admin APIs use a backend dependency that checks the database-backed global role and returns `403` to regular users. | Exercised by `tests/test_admin.py`; frontend hiding is not relied on. |
| Unsafe uploads and public exposure | The upload path restricts extensions/content, size, and filenames; storage names are generated and files must be outside the public static directory. | Exercised by `tests/test_security.py`; there is no antivirus scanner or cloud object-storage integration. |
| Permission revocation | Active permission is checked at request time; revocation prevents later downloads. | Exercised by `tests/test_revocation.py`. |
| Unauthorized API access | Protected routes require a valid bearer token. Document ownership and notification recipient checks are performed server-side. | Covered by authentication, document, notification, and Admin tests. |
| Sensitive reset-token storage | Reset tokens are stored as hashes, expire, and are single-use. The public reset-request response is generic. | Covered by `tests/test_password_reset.py`; SMTP delivery tests are mocked. |
| Audit access and ordinary SQLite mutation | Audit API results are user-scoped or Admin-only. SQLite initialization installs triggers that reject audit-row updates/deletes through ordinary SQL operations. | SQLite behavior is tested in `tests/test_audit.py`; PostgreSQL does not install equivalent triggers. |

## Residual risks

- No login or password-reset rate limiter was found. Repeated guesses and reset-email abuse require additional controls.
- Logout does not revoke a copied stateless JWT before its expiry.
- The PostgreSQL deployment option has no matching append-only audit triggers; a database administrator can alter records.
- The local file backend is single-instance storage. The Compose named volume persists files on one host but is not shared storage for multiple replicas.
- SQLite/database and upload backups, restore procedures, and host/container restart recovery have not been exercised here.
- Google OAuth and SMTP automated coverage uses mocks. Live provider behavior is not verified.
- The project does not use a versioned migration framework; schema evolution needs an explicit migration and rollback process.
- No antivirus or content-disarm scanning is present.
- The root OAuth export's exclusion rules do not establish whether it was previously committed or shared. Verify repository history independently and rotate the provider secret if exposure is possible.
- Production deployment, HTTPS/proxy hardening, secret-store configuration, and operational monitoring require environment-specific validation.

## Security verification

Run the automated tests from the project virtual environment with `python -m pytest`. A passing suite demonstrates the tested local behaviors only; it is not a penetration test, provider-delivery check, or production certification. See [the endpoint authorization guide](./docs/API_AUTHORIZATION.md) for the intended endpoint-level access and denial behavior.
