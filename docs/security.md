# NETSENTRY Security & Privacy Model

> [!CAUTION]
> ### ⚠️ STRICT PROHIBITION ON MALICIOUS USE, HACKING & SCAMS
> **THIS PROJECT IS ABSOLUTELY NOT FOR HACKERS, SCAMMERS, OR FRAUDSTERS.**
> NETSENTRY is designed solely for authorized network defense, educational research, and transparent laboratory environments. Any deployment for unauthorized surveillance, extortion, phishing, tech-support scams, or hacking is strictly prohibited, terminates all licenses, and is criminally punishable under international cybercrime laws.

## Principles & Invariants

### 1. Zero Stealth Access
NETSENTRY rejects all covert surveillance patterns:
- **No Background Video Capture**: The camera engine can only be triggered after the local user clicks `ALLOW` on a visible, top-level Tkinter modal window.
- **No Hidden Processes**: The client GUI cannot minimize to the tray or conceal its active status during a session.
- **Active Streaming Indicator**: A prominent red `CAMERA ACTIVE` banner with a live countdown is displayed continuously on the target endpoint.

### 2. Administrator Authentication & Rate Limiting
- Passwords are encrypted using salted `bcrypt` with a cost factor of 12.
- Session authorization uses signed JSON Web Tokens (JWT) using `HS256`.
- Account Lockout Protection: After 5 consecutive failed login attempts, the target administrator account is automatically locked for 15 minutes.

### 3. Ephemeral Enrollment Handshake
- Permanent pre-shared credentials are never used.
- Administrators generate single-use registration codes (`NET-XXXX-XXX`) valid for exactly 15 minutes.
- When an endpoint registers, a cryptographically secure 256-bit token is generated, hashed with SHA-256 in the database, and issued to the client.

### 4. Bounded Session Lifetimes
- All camera monitoring sessions are bound to a configurable maximum duration (default: 10 minutes, max: 30 minutes).
- Server-side asynchronous background timers terminate the session automatically when the limit expires.
- Unilateral revocation: either party can click `STOP CAMERA` / `END SESSION` to instantly terminate access.

### 5. Immutable Audit Trail
- Critical security and administrative events are written to the `audit_logs` table.
- Normal administrative operations cannot modify or delete audit log entries.
- Audit records include timestamp, actor, event type, target device, IP address, and status.
