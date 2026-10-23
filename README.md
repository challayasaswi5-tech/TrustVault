# TrustVault – Secure Document Sharing with a Real Audit Trail

## Overview
TrustVault is a secure document management platform designed to help authorised users store, manage, and share confidential documents with controlled access.

## User Roles
- **Admin:** Manages users and reviews audit logs.
- **Document Owner:** Uploads and manages documents and controls access permissions.
- **Viewer:** Accesses documents only when permission is granted.

## Key Features
- User authentication and role-based access control.
- Secure document upload and management.
- Document-level read and edit permissions.
- Permission granting and revocation.
- Audit logging for security-related actions.
- Automated security tests.

## Technologies
- Python
- Flask
- SQLite
- HTML and CSS
- Git and GitHub

## Run Locally
1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install the required dependencies.
4. Run `python TrustVault_app_updated.py` or follow the application's configured entry point.
5. Open `http://127.0.0.1:5000` in your browser.

## Security
This project is intended as a hackathon prototype. Review the configuration, credentials, file validation, and access controls before public deployment. Never use demo credentials in production.