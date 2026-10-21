
# TrustVault - Threat Model

## 1. Unauthorized Document Access
Threat: A viewer may try to open a document without permission.
Mitigation: Check document access permissions on every document request.

## 2. Revoked Access
Threat: A user may try to access a document after permission is revoked.
Mitigation: Remove the user's permission from the database and verify access before serving the file.

## 3. Unauthorized Login
Threat: An attacker may try to log in using incorrect credentials.
Mitigation: Verify passwords securely using password hashes.

## 4. Unauthorized Sharing
Threat: A viewer may try to grant document access to another user.
Mitigation: Only administrators and document owners should manage sharing.

## 5. Audit Log Integrity
Threat: Important document activities may not be recorded.
Mitigation: Record document access, sharing, and revocation events in audit logs.

## 6. File Upload Risks
Threat: An attacker may upload an unsafe or oversized file.
Mitigation: Validate file extensions and enforce the upload size limit.

## Testing
- Test document access with different user roles.
- Test access after revoking permission.
- Test login with incorrect credentials.
- Test whether viewers can manage sharing.
- Verify audit logs after document activities.
