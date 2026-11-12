# TMERP — Trustless Multi-Party Evidence Release Protocol

A runnable Flask prototype for sealed evidence submission, multipart integrity, reviewer threshold approvals, disputes, and conditional downloads.

## What is implemented

- Flask authentication and role-based access (`admin`, `reviewer`, `submitter`)
- Multipart file processing in 1 MiB chunks
- Per-part SHA-256 hashes and a Merkle root
- Fernet authenticated encryption before writing evidence parts to disk
- Independent reviewer decisions and configurable approval threshold
- Open disputes suspend release; admin resolution re-evaluates release
- Audit trail for submission, review, disputes, integrity checks, and downloads
- SQLite database and Bootstrap dashboard

## Quick start (Windows PowerShell)

```powershell
py -3 -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Generate a Fernet key:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Edit `.env` and set:
- `SECRET_KEY` to a long random secret
- `EVIDENCE_MASTER_KEY` to the generated Fernet key

Then run:

```powershell
python app.py
```

Open http://127.0.0.1:5000

## First login and reviewer setup

Default local admin:
- Email: `admin@tmerp.local`
- Password: `Admin@12345`

Immediately change this password before any shared deployment. Create normal user accounts using Register. In Admin → Users, promote selected accounts to `reviewer`. Submitter accounts can then select reviewers when creating evidence.

## How the multipart commitment works

The upload stream is read in 1 MiB parts. For each plaintext part, the app computes SHA-256, encrypts the part with Fernet, and stores only the encrypted bytes. The Merkle root is built from the ordered part hashes. The integrity page decrypts each part in memory and checks the part hashes and root.

## Important prototype/security limitations

This project is a local Flask implementation, not yet a fully trustless distributed protocol:
- The audit log and approval database are stored in the same SQLite database and can be altered by a privileged host operator.
- The default admin account is seeded for local evaluation; change it and add proper admin password management before deployment.
- The master encryption key is supplied through `.env`; back it up securely. Losing it makes evidence unrecoverable. Do not commit `.env`.
- The app uses a single master encryption key for simplicity. A production design should use per-evidence data-encryption keys wrapped by a KMS/HSM and implement key rotation.
- The Flask app's local role assignment is administrative, not decentralized identity.
- No Ethereum contract is deployed by this starter. The `blockchain/` folder contains an integration design note. To make approvals genuinely independently verifiable, deploy a smart contract and anchor event hashes/roots on-chain. A database-only audit trail must not be described as immutable or trustless.
- Add CSRF protection, rate limiting, secure session/cookie settings, malware scanning, backups, and HTTPS before production use.
- Avoid deploying this prototype with debug mode enabled.

## Suggested production architecture

Keep evidence encrypted off-chain. Put only evidence IDs, Merkle roots, approval events, challenge events, and release state on-chain. Never put raw evidence or encryption keys on a public blockchain.
