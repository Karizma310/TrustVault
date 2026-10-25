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

## Day-wise Development Progress (October 19–24, 2026)

October 19, 2026 — Project Setup

Planned the application structure and configured the initial FastAPI project.

Worked on authentication flow, user roles, and API access restrictions.

October 20, 2026 — Document Sharing

Developed the initial document upload, listing, and download workflows.

Worked on owner-controlled sharing and document permission handling.

October 21, 2026 — Security and Tracking

Worked on recording document-related activities through audit logs.

Reviewed notification handling and user-facing document status updates.

October 22, 2026 — Admin and Access Control

Reviewed administrator access and protected API endpoints.

Tested user permissions and checked for unauthorized document access.

October 23, 2026 — Testing and Debugging

Added and updated automated tests for configuration and application behavior.

Investigated errors and reviewed security-sensitive functionality.

October 24, 2026 — Deployment

Debugged PostgreSQL URL validation and added configuration regression tests.

Deployed the application on Render and verified 61 passing automated tests.
