# TrustVault five-minute demo

This is a local demonstration plan, not a claim of production deployment or third-party service verification.

## Before the timer

1. Start TrustVault using the local setup in the README and open the frontend and `/docs` on the same API origin.
2. Register three separate accounts from the website. Choose your own strong, temporary demo passwords; do not reuse personal credentials or place passwords in commands, recordings, or source files.
3. Assign the Admin role to the chosen registered account from a trusted project shell:

   ```powershell
   python .\scripts\set_admin_role.py admin@example.com
   ```

4. Create the synthetic private sample files and read-only Viewer permission:

   ```powershell
   python .\scripts\seed_data.py `
     --admin-email admin@example.com `
     --owner-email owner@example.com `
     --viewer-email viewer@example.com
   ```

5. Use Swagger UI or the website for the API steps below. Authorize each account separately. Keep bearer tokens private; do not paste them into the demo recording or share them.

## Five-minute walkthrough

| Time | Action |
|---|---|
| **0:00–0:40** | Sign in as **Owner**. Open My Documents and show that the Owner sees their own private documents. Upload a small synthetic `.txt` or `.pdf` that contains no real personal or confidential information. |
| **0:40–1:25** | In Swagger UI, as Owner, call `GET /api/documents` and note the new document ID. Switch authorization to **Admin** and call `GET /api/documents/{document_id}/download`. Show the expected `404`. Admin is privileged for Admin APIs, not implicitly authorized for this document. |
| **1:25–2:10** | Sign back in as Owner and grant the Viewer read access from the Permissions screen (or call `POST /api/documents/{document_id}/permissions` with the Viewer account). Show that the permission is `read`. |
| **2:10–2:55** | Sign in as **Viewer**. Open Shared With Me and download the granted document. Optionally show that `GET /api/documents` remains empty for this Viewer and that the document is in `/api/documents/shared-with-me`. |
| **2:55–3:40** | Return to Owner and revoke the Viewer permission from Permissions (or call the matching `DELETE /api/documents/{document_id}/permissions/{permission_id}`). |
| **3:40–4:25** | As Viewer, retry the same download request. Show the expected `404` after revocation, demonstrating that access is checked on each request. |
| **4:25–5:00** | Sign in as Admin and open Audit Logs or call `GET /api/admin/audit`. Point out the upload, access grant, successful download, denied access, and revocation events. Confirm a regular User gets `403` from `/api/admin/audit` or `/api/admin/users`. |

## Expected outcomes and caveats

- The Owner can upload and manage owned documents.
- A Viewer can download only while a read permission is active; the Viewer cannot edit or delete.
- Admin status does not grant access to private documents.
- Unauthorized document requests return `404`; regular users receive `403` on Admin-only APIs.
- The local seed script produces two synthetic files in private storage and one read-only Viewer grant. It does not create or change accounts or passwords.
- This walkthrough exercises the local application. It does not verify real SMTP, live Google OAuth, PostgreSQL, production backups, or a deployed service.
