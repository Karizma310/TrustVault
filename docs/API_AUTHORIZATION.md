# TrustVault API authorization guide

All paths below are relative to the FastAPI origin. “Authenticated” means a valid bearer access token for an existing account. The API checks authorization on every request; hiding a link or page in the frontend is not an access-control boundary.

## Account roles and document access

- Registration and Google sign-in create accounts with the global `user` role. The trusted local `scripts/set_admin_role.py` utility can assign the global `admin` role to a named registered account.
- **Admin** is a global role for the `/api/admin/*` endpoints. It does not override document ownership or sharing permissions.
- **Owner** means the user ID in a document's `owner_id`. Owners can read, download, update, delete, and manage permissions for their own documents.
- **Viewer** means a regular user with an active document permission whose access level is `read`. Viewers can list and download that shared document. They cannot edit, delete, or share it.
- Revoked permissions are checked on subsequent requests. An authenticated user who is neither the document owner nor an active Viewer receives `404 Document not found` for protected document operations; this avoids confirming that another user's document exists.

## Authentication and account endpoints

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `POST /api/auth/register` | Public | Creates a regular User account. Invalid input returns `422`; an existing email returns `409`. The request cannot select an Admin role. |
| `POST /api/auth/login` | Public | Invalid email/password returns the same `401` message for both cases. |
| `POST /api/auth/logout` | Authenticated | Records logout and returns `204`. Missing, invalid, or expired bearer token returns `401`. Logout does not revoke a copied stateless token; it remains valid until expiration. |
| `GET /api/auth/me` | Authenticated | Returns only the caller's account and role. Missing, invalid, or expired token returns `401`. |
| `PATCH /api/auth/me` | Authenticated | Updates only the caller's profile. Missing, invalid, or expired token returns `401`. |
| `GET /api/auth/preferences` | Authenticated | Reads only the caller's preferences. Missing, invalid, or expired token returns `401`. |
| `PATCH /api/auth/preferences` | Authenticated | Updates only the caller's preferences. Missing, invalid, or expired token returns `401`; an empty or invalid update returns `422`. |
| `POST /api/auth/password-reset/request` | Public | Returns the same `202` response for unknown accounts and known accounts. Delivery failures are not disclosed to the caller. |
| `POST /api/auth/password-reset/confirm` | Public, with a valid reset token | Invalid, expired, or previously used token returns `400` with a generic invalid-or-expired message. |

## Google OAuth endpoints

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `GET /api/auth/google/start` | Public | Begins OAuth when configured. If configuration is missing, redirects to the login page with a generic configuration error. |
| `GET /api/auth/google/callback` | Public, with a matching short-lived OAuth state cookie and provider response | Invalid state, provider rejection, or invalid identity redirects to login and records the failed attempt. No bearer token is required. |
| `POST /api/auth/google/exchange` | Public, with an unexpired one-time exchange code | Invalid, expired, or reused code returns `400`. A successful exchange consumes the code. |

## Document endpoints

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `POST /api/documents` | Any authenticated user | Uploads a document owned by the caller. Invalid type/content returns `415`; oversize returns `413`; unsafe filename, empty file, or invalid title returns `422`. |
| `GET /api/documents` | Any authenticated user | Lists only documents owned by the caller (including Admin callers). Invalid filters or date ranges return `422`. |
| `GET /api/documents/shared-with-me` | Any authenticated user | Lists only documents for which the caller has an active read permission. |
| `GET /api/documents/{document_id}/download` | Owner or active read Viewer | Owner and active Viewer receive the private file. Other authenticated users receive `404`, and an access-denial audit event is recorded. Missing private file also returns `404` and is logged as a failed download. |
| `PATCH /api/documents/{document_id}` | Owner only | Non-owner or missing document returns `404` and records a denial event. An empty update or blank title returns `422`. A Viewer cannot edit. |
| `DELETE /api/documents/{document_id}` | Owner only | Non-owner or missing document returns `404` and records a denial event. A Viewer cannot delete. |

## Permission endpoints

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `GET /api/documents/{document_id}/permissions` | Owner only | Lists active permissions for the owner's document. Non-owner or missing document returns `404` and records a denial event. |
| `POST /api/documents/{document_id}/permissions` | Owner only | Grants **read-only** access to one existing account selected by email or user ID. Non-owner/missing document and unknown recipient return `404`; self-grant returns `422`; duplicate active grant returns `409`. Denied owner/recipient and duplicate-grant attempts are audited. |
| `DELETE /api/documents/{document_id}/permissions/{permission_id}` | Owner only | Revokes an active permission. Non-owner/missing document or inactive/missing permission returns `404`; denied attempts are audited. The revoked Viewer is denied on the next document request. |

## Notifications

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `GET /api/notifications` | Authenticated | Returns only notifications addressed to the caller. |
| `POST /api/notifications/{notification_id}/read` | Recipient only | Marks only the caller's notification read. A different user's or missing notification returns `404`. |
| `DELETE /api/notifications/{notification_id}` | Recipient only | Dismisses only the caller's notification. A different user's or missing notification returns `404`. |

## Audit and administration

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `GET /api/audit` | Authenticated | Returns only audit entries attributed to the caller; supports action/date filters and a bounded limit. |
| `GET /api/audit/export.csv` | Authenticated | Exports only the caller's audit entries. |
| `GET /api/admin/audit` | Admin only | Returns system-wide audit entries with filters and a bounded limit. A regular user receives `403`. |
| `GET /api/admin/audit/export.csv` | Admin only | Exports system-wide audit entries. A regular user receives `403`. |
| `GET /api/admin/users` | Admin only | Lists registered accounts with optional search and pagination. A regular user receives `403`. |
| `GET /api/admin/login-activity` | Admin only | Lists login/logout activity with pagination. A regular user receives `403`. |

## Health and frontend routes

| Method and path | Who may call it | Authorization and expected denials |
|---|---|---|
| `GET /health` | Public | Returns service/database health status; database connection failures are errors, not a success-shaped fallback. |
| `GET /` and `/app/templates/*`, `/app/static/*` | Public | Serves/redirects to frontend files. Pages are not authorization boundaries; protected API requests still require the bearer token and appropriate ownership/permission. |

The API returns `401` when a protected request has no valid bearer token and `403` for a regular user calling an Admin-only endpoint. Document/permission resources use `404` where revealing their existence would be inappropriate. Validation failures generally return `422`.
