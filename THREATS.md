# TrustVault – Threat Model

## 1. Overview
TrustVault is a secure document-sharing application that uses user roles and document-level permissions to protect confidential files.

## 2. Assets to Protect
- Confidential uploaded documents
- User credentials
- Document access permissions
- Audit logs
- User and document metadata

## 3. Potential Threats and Mitigations

### Threat 1: Unauthorized Document Access
**Risk:** A user may try to access a document without permission.  
**Mitigation:** Verify document permissions before allowing access or download.

### Threat 2: Unauthorized Permission Changes
**Risk:** A user may try to grant or revoke permissions without authorization.  
**Mitigation:** Restrict permission-management actions to authorized users.

### Threat 3: Malicious File Upload
**Risk:** An attacker may upload an unexpected or harmful file.  
**Mitigation:** Validate allowed file types and enforce a maximum upload size. File-type checks alone do not guarantee that a file is safe.

### Threat 4: Password Attacks
**Risk:** An attacker may try to guess user passwords.  
**Mitigation:** Store password hashes rather than plaintext passwords. Use strong passwords and add login rate limiting before production deployment.

### Threat 5: Cross-Site Request Forgery (CSRF)
**Risk:** A malicious website may attempt to trigger actions using an authenticated session.  
**Mitigation:** Validate CSRF tokens on state-changing requests.

### Threat 6: Audit Log Tampering
**Risk:** An attacker may attempt to alter or erase security events.  
**Mitigation:** Restrict audit-log access and consider tamper-resistant centralized logging for production.

## 4. Security Testing
- Test valid and invalid login attempts.
- Verify document access permissions.
- Confirm revoked users cannot access protected documents.
- Test file upload validation and size limits.
- Verify unauthorized actions are rejected and logged.

## 5. Limitations
TrustVault is a hackathon prototype. Production deployment requires additional security review, secure secret management, HTTPS, rate limiting, protected storage, and deployment hardening.