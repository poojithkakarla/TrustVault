
# TrustVault - Threat Model

## 1. Unauthorized Document Access
Threat: A viewer may try to open a document without permission.
Mitigation: Check document permissions before serving each document.

## 2. Revoked Access
Threat: A user may try to access a document after access is revoked.
Mitigation: Remove the user's permission from the database and check access on every request.

## 3. Unauthorized Login
Threat: An attacker may try to log in with incorrect credentials.
Mitigation: Verify passwords using secure password hashes.

## 4. Unauthorized Sharing
Threat: A viewer may try to share a document with another user.
Mitigation: Only administrators and document owners should manage sharing.

## 5. Audit Log Integrity
Threat: Important document activities may not be recorded.
Mitigation: Record document access, sharing, and revocation events in audit logs.

## 6. Unsafe File Uploads
Threat: An attacker may upload an unsupported or oversized file.
Mitigation: Validate file extensions and enforce a file size limit.

## Testing Checklist
- Test access with different user roles.
- Test access after revoking permission.
- Test login with incorrect credentials.
- Test whether viewers can manage sharing.
- Verify audit logs after document activities.
