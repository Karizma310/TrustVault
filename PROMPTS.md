# TrustVault – AI-Assisted Development Prompts

## 1. Authentication and Role-Based Access Control

Design and implement a secure authentication and authorization system for TrustVault using FastAPI. Support Admin, Owner, and Viewer roles, enforce role-based access restrictions, and ensure protected API endpoints validate the authenticated user's permissions.

## 2. Secure Document Management

Implement document upload, storage, retrieval, and sharing functionality. Ensure uploaded files remain private, validate incoming files, and restrict document access to authorized users.

## 3. Permission Management

Develop document-level permission management that allows owners to grant and revoke access. Ensure permission changes take effect immediately and unauthorized users cannot access documents after their permissions are revoked.

## 4. Audit Logging

Implement an audit trail for security-sensitive operations, including document uploads, downloads, and permission changes. Record relevant event details while avoiding sensitive information in logs.

## 5. Notification Management

Implement persistent notifications with read and dismiss functionality. Ensure notification states are stored correctly and remain consistent across page refreshes and subsequent requests.

## 6. Administrative Monitoring

Develop administrator-only APIs and dashboard functionality for viewing user information and login activity. Enforce server-side authorization and prevent non-administrator users from accessing administrative resources.

## 7. Automated Testing and Debugging

Create and execute automated tests for authentication, authorization, document operations, permission management, and unauthorized access. Investigate failures, implement appropriate fixes, and verify the resulting behavior through regression testing.

## 8. Security Assessment

Review TrustVault for potential vulnerabilities involving authentication, privilege escalation, insecure file handling, exposed secrets, and access-control failures. Recommend mitigations and validate security-critical behavior through testing.

## 9. Project Documentation and Configuration

Prepare project documentation covering architecture, installation, environment configuration, database setup, API usage, testing, and deployment requirements. Ensure the documentation accurately reflects the implemented application.

## 10. Final Validation and Challenge Readiness

Evaluate TrustVault against the hiring challenge requirements. Review feature completeness, authorization boundaries, audit logging, automated test results, documentation, and deployment readiness. Identify unresolved issues and prioritize corrective actions before submission.

## Dated Prompt Log

These entries summarize actual project requests from this conversation; they do not claim that live third-party services were tested.

1. **2026-10-24 08:21** — Inspect the password-reset path across backend, frontend, configuration, and tests; identify SMTP and token/link issues without exposing secrets.
2. **2026-10-24 08:32** — Report the exact SMTP environment variable names and Gmail App Password setup supported by the current implementation.
3. **2026-10-24 13:14** — Diagnose why the intended account receives 403 from Admin APIs; verify the role assignment script and preserve normal-user denial.
4. **2026-10-24 13:17** — Compare the running FastAPI instance and role-assignment script database, verify the intended account, and avoid granting Admin to all users.
5. **2026-10-24 13:28** — Audit authentication, roles, document security, audit trail, settings, tests, repository requirements, and deployment readiness.
6. **2026-10-24 14:21** — Add safe synthetic demo data, endpoint authorization documentation, a five-minute walkthrough, and an honest challenge write-up without embedding credentials.
