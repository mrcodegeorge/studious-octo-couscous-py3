# NETSENTRY: Local Wi-Fi Network Monitoring & Consent-Based Remote Camera System
**Final Year Project Academic Specification & Engineering Report**

- **Author & Principal Investigator**: **George Asiedu Annan**
- **Organization**: **Neolifeporium**
- **Subsidiary**: **Gazomapay**
- **Collaborating Assets**: **Neodata** &bull; **Nexa Kreatives** &bull; **Nexa Kreatives Academy**

---

## 1. Project Background & Context
In institutional, laboratory, and domestic computing environments, network administrators and research supervisors frequently require automated situational awareness over connected endpoint devices. Traditional network inventory tools (such as Nmap or standard SNMP managers) provide passive layer-2/layer-3 discovery, but lack contextual verification of endpoint hardware and operational environment.

Concurrently, remote camera access mechanisms have historically been plagued by ethical and architectural vulnerabilities: remote administration tools (RATs) and covert surveillance software activate video sensors silently, bypass operating-system permission frameworks, and persist surreptitiously. Such behaviors undermine privacy rights and violate computer misuse legislation.

**NETSENTRY** addresses this dual challenge by architecting a unified, authorized local-network monitoring system paired with a **strictly consent-driven remote optical verification subsystem**. It demonstrates how network visibility and administrative verification can be achieved while maintaining strict ethical boundaries and verifiable user consent.

---

## 2. Problem Statement
1. **Network Blindness**: Unauthorized or unclassified devices joining a local subnet can introduce vulnerabilities, consume bandwidth, or disrupt experimental testbeds without immediate administrator detection.
2. **Covert Surveillance Risks**: Conventional remote assistance and camera utilities often lack transparent, user-facing consent controls, creating significant privacy risks and legal liabilities.
3. **Session Overstay & Hijacking**: Long-lived or perpetual remote access permissions enable credential harvesting and persistent unauthorized monitoring.

---

## 3. Aim & Objectives

### Aim
To design, implement, and validate a secure local-network monitoring platform that continuously discovers endpoints on authorized subnets and enables temporary, mutually authenticated, and revocable camera monitoring governed strictly by user consent.

### Core Objectives
1. **Authorized Network Discovery**: Automatically identify active local network devices using native Address Resolution Protocol (ARP) tables and targeted socket sweeps strictly bound to authorized CIDR subnets (e.g. `192.168.1.0/24`).
2. **Device Classification & Trust Management**: Correlate MAC addresses against Organizationally Unique Identifier (OUI) registries, classify devices (Online, Offline, New, Trusted), and emit real-time alerts.
3. **Cryptographic Enrollment Handshake**: Implement ephemeral single-use registration codes (`NET-XXXX-XXX`) to enroll consenting client devices without permanent pre-shared secrets.
4. **Consent-Driven Camera Subsystem**: Guarantee that remote camera activation is technically impossible without an active, explicit human acceptance (`ALLOW`) on the target device's visible graphical interface.
5. **Real-Time Revocation & Bounded Lifecycles**: Enforce strict session duration limits (default 10 minutes) and provide instant unilateral termination (`STOP CAMERA`) to both administrator and device user.
6. **Immutable Audit Trail**: Log all authentication events, device transitions, and camera session handshakes into a non-editable relational audit ledger with ReportLab PDF and CSV export capabilities.

---

## 4. Research Questions
- **RQ1**: How can local network device discovery be performed efficiently without saturating network bandwidth or triggering intrusive port-scanning IDS alarms?
- **RQ2**: What state-machine architecture ensures that camera hardware activation is strictly contingent upon human interaction and cannot be forced remotely or bypassed?
- **RQ3**: How can real-time video frames and administrative telemetry be relayed with minimal latency using lightweight WebSocket transports in local network environments?

---

## 5. Scope & Boundary Definition
- **In-Scope**:
  - Local IPv4 network discovery within authorized subnets.
  - Device inventory management and MAC vendor classification.
  - Ephemeral client enrollment via administrative pairing codes.
  - Tkinter-based user client with visible permission modals and live streaming controls.
  - Real-time video frame relay over authenticated WebSockets.
  - Comprehensive immutable audit logging, alerts, and PDF/CSV reporting.
  - Evaluation Demonstration Mode (`DEMO MODE`) for simulated network and camera workflows.
- **Out-of-Scope**:
  - Internet-wide or multi-hop WAN scanning (strictly prohibited).
  - Bypassing host operating system security controls or webcam indicator LEDs.
  - Covert background installation, stealth persistence, or keylogging.
  - Indefinite video footage recording without explicit additional consent.

---

## 6. System Architecture

```
                    ADMINISTRATIVE DOMAIN
   +------------------------------------------------------+
   |                  Web Browser UI                      |
   |   (Cybersecurity Dashboard, Camera Viewer, Reports)  |
   +--------------------------+---------------------------+
                              | HTTP REST / WebSockets
                              v
   +------------------------------------------------------+
   |             NETSENTRY Backend (FastAPI)              |
   |                                                      |
   |  +----------------+  +---------------+  +----------+ |
   |  | Network Engine |  | CameraManager |  | Auth /   | |
   |  | (ARP & Sweeps) |  | (Consent SM)  |  | Security | |
   |  +-------+--------+  +-------+-------+  +----+-----+ |
   |          |                   |               |       |
   |          v                   v               v       |
   |  +-------------------------------------------------+ |
   |  |         SQLite Database (WAL Mode)              | |
   |  | (Users, Devices, Sessions, Alerts, Audit Logs)  | |
   |  +-------------------------------------------------+ |
   +--------------------------+---------------------------+
                              | Local Network (Signaling & Frame Relay)
                              v
   +------------------------------------------------------+
   |             NETSENTRY Client (Python)                |
   |                                                      |
   |   +-------------------+      +--------------------+  |
   |   |   Tkinter GUI     |      |  OpenCV Streaming  |  |
   |   | (Consent Prompt)  |      |   (Camera Engine)  |  |
   |   +---------+---------+      +---------+----------+  |
   |             |                          |             |
   |             v                          v             |
   |    [ALLOW] / [DENY] Button    Hardware Optical Cam   |
   +------------------------------------------------------+
                     CLIENT DOMAIN
```

---

## 7. Database Entity Relationship (ER) Model

1. **`users`**: Administrative accounts with bcrypt salted password hashes, failed login counters, lockout timestamps, and roles.
2. **`devices`**: Discovered network hardware records (IP address, MAC address, hostname, OUI vendor, status, trust flag, client registration state).
3. **`registration_codes`**: Ephemeral single-use pairing codes (`NET-XXXX-XXX`) with strict expiration timestamps.
4. **`device_tokens`**: SHA-256 hashed cryptographic bearer tokens issued to enrolled client endpoints.
5. **`camera_sessions`**: Complete session metadata (UUID, device ID, admin ID, state machine transitions, requested timestamp, approved timestamp, termination reason).
6. **`alerts`**: Real-time notifications categorized by severity (INFO, WARNING, CRITICAL).
7. **`audit_logs`**: Immutable, append-only security ledger recording actor, event, IP, and metadata JSON.
8. **`network_scans`**: Historical scan telemetry (duration, subnet, devices discovered).

---

## 8. Security & Consent Model

### Invariant 1: No Silent Activation
Under no circumstance can a camera stream be initiated via a single administrative action. The administrative request creates a session in the `REQUESTED` state and pushes a message to the target client. The client UI raises an unmissable modal dialog. If the user clicks `DENY` or closes the dialog, the session is marked `DENIED`, and no frame capture thread is initialized.

### Invariant 2: Visible Active State
When active, the client GUI displays a prominent `CAMERA ACTIVE` banner, an active elapsed countdown, and a red `[STOP CAMERA]` button. The client process cannot hide its window or minimize to the notification area during an active streaming session.

### Invariant 3: Unilateral Instant Termination
Either the client user (clicking `STOP CAMERA`), the administrator (clicking `END SESSION`), or the automated server expiration timer (reaching 10 minutes) can terminate the session instantly, immediately powering down the webcam and writing an audit entry.

---

## 9. Testing & Verification Summary

| Test Suite | Total Tests | Status | Verification Focus |
|---|---|---|---|
| `test_auth.py` | 4 | PASSED | Bcrypt hashing, JWT generation, admin authentication, account lockout after 5 failed attempts. |
| `test_network.py` | 4 | PASSED | MAC normalization, OUI vendor lookup, authorized subnet boundary checks, demo mode generator. |
| `test_devices.py` | 2 | PASSED | Device CRUD, trust status toggling, audit timeline synthesis. |
| `test_camera_permissions.py` | 4 | PASSED | Code expiration, **request does NOT start camera**, explicit denial keeps camera off, explicit allow starts session. |
| `test_audit.py` | 1 | PASSED | Immutable audit log generation and querying. |
| `test_client.py` | 2 | PASSED | Local network telemetry detection, synthetic frame fallback encoding. |
| `test_web_filter.py` | 6 | PASSED | Domain wildcard pattern matching, web activity ingestion, hosts surgical null-routing, anti-VPN policy management. |
| `test_e2e_workflow.py` | 1 | PASSED | End-to-end full consent lifecycle verification (enrollment, allow, deny). |
| **Total** | **24** | **100% PASSED** | All critical security, privacy, and consent invariants mathematically and functionally verified. |

---

## 10. Conclusion & Future Work
NETSENTRY proves that local network observability, web safety enforcement, and remote visual verification can be harmoniously integrated without sacrificing endpoint privacy or administrative rigor. Future research will explore WebRTC peer-to-peer data channels for multi-camera classroom synchronization, TPM-backed hardware attestation for enrolled endpoints, and zero-knowledge consent verification.

---

## 11. Authorship & Intellectual Property

- **Lead Engineer & Author**: George Asiedu Annan
- **Corporate Entity**: Neolifeporium
- **Subsidiary**: Gazomapay
- **Technology Assets**:
  - Neodata (Analytics & Security Intelligence)
  - Nexa Kreatives (Product Design & Interaction Architecture)
  - Nexa Kreatives Academy (Curriculum & Technical Research)
- **License**: NETSENTRY Non-Commercial & Anti-Resale Source License (Copyright &copy; 2026 George Asiedu Annan / Neolifeporium). All commercial resale, leasing, sublicensing, and paid distribution are strictly prohibited. All rights reserved.
