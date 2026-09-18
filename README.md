# NETSENTRY
### Local Wi-Fi Network Monitoring & Consent-Based Remote Camera System

NETSENTRY is an authorized local-network monitoring platform paired with a **strictly consent-driven remote optical verification subsystem**. Built for computer laboratories, educational environments, research facilities, and controlled demonstrations, it provides comprehensive real-time situational awareness over connected devices while strictly upholding endpoint privacy.

---

## Key Features

- **Authorized Local Discovery**: Multi-threaded ICMP sweep combined with native ARP cache extraction (`arp -a` and PowerShell `Get-NetNeighbor`) strictly bounded to administrator-authorized subnets (e.g., `192.168.1.0/24`).
- **Hardware & Vendor Classification**: Real-time MAC normalization and OUI manufacturer matching across Apple, Raspberry Pi, Cisco, Intel, TP-Link, Samsung, Dell, and hundreds of hardware vendors.
- **Cybersecurity Dark Dashboard**: Professional slate-and-cyan interface with real-time KPI metrics, network activity charts (Chart.js), searchable device inventory, and WebSocket live updates.
- **Strictly Consent-Driven Camera Access**:
  - Camera access CANNOT be silent, hidden, forced, or covert.
  - Requires active client enrollment via ephemeral registration codes (`NET-XXXX-XXX`).
  - Remote request triggers an unmissable modal dialog on the client device.
  - If user clicks **DENY**, the camera stays completely OFF and an audit log is recorded.
  - If user clicks **ALLOW**, a prominent `CAMERA ACTIVE` banner appears with countdown and an instant `[STOP CAMERA]` button.
- **Web Activity Monitoring & Anti-VPN Content Filtering**:
  - Endpoint-level browsing activity inspection capturing requested domains and processes across modern browsers.
  - VPN-resistant domain restriction via surgical OS-level hosts null-routing (`0.0.0.0`) and local DNS cache synchronization that cannot be evaded via standard VPN tunnels.
  - Strict Anti-VPN Mode that disarms WireGuard, OpenVPN, Wintun, and TAP virtual tunnel adapters during monitored lab/work sessions.
  - Dedicated administrative dashboard with live telemetry feed, category filters, and real-time violation alerts.
- **Bounded Session Lifecycles**: Default 10-minute maximum session with automated server-side expiration guards and unilateral termination by either party.
- **Immutable Security Audit Trail**: Append-only relational audit ledger recording all administrative, device, camera, and web filtering operations.
- **Executive PDF & CSV Reports**: One-click branded PDF reports generated with ReportLab and comprehensive CSV data exports.
- **Demonstration Mode (`DEMO MODE`)**: Built-in simulation generator clearly labeled `[DEMO MODE]` for academic defenses and evaluations when external physical hardware is unavailable.

---

## Technology Stack

- **Backend**: Python 3.12+, FastAPI, Uvicorn, SQLAlchemy, SQLite (WAL mode), Pydantic, WebSockets
- **Networking**: Native ARP table parsing, ICMP socket probe sweep, DNS cache inspection, adapter detection
- **Camera & Video**: OpenCV (`cv2`), Pillow (PIL), authenticated binary WebSocket JPEG streaming relay
- **Frontend**: Vanilla HTML5/CSS3 (Cybersecurity Design System), Vanilla JS API client, Chart.js
- **Security & Cryptography**: Bcrypt (cost 12), PyJWT (HS256), SHA-256 token hashing, account lockout, hosts null-routing
- **Reporting**: ReportLab PDF generator, CSV streaming
- **Testing**: Pytest test suite (24 automated unit, integration, and E2E workflow tests)

---

## Project Structure

```
netsentry/
├── app/
│   ├── main.py               # FastAPI application setup, static files, and lifespan
│   ├── config.py             # Environment configuration (Pydantic settings)
│   ├── api/                  # REST & WebSocket API endpoints
│   │   ├── auth.py           # Admin login, initial setup, logout, password change
│   │   ├── devices.py        # Device inventory, detail view, trust controls
│   │   ├── network.py        # Subnet settings, manual scans, monitor controls
│   │   ├── camera.py         # Permission requests, session history, termination
│   │   ├── alerts.py         # Notification feed and badge counter
│   │   ├── audit.py          # Immutable audit trail queries
│   │   ├── reports.py        # PDF & CSV exports
│   │   ├── client_api.py     # Client enrollment, heartbeat, consent responses
│   │   └── websocket_endpoints.py # WebSocket channels (/ws/dashboard, /ws/camera/stream)
│   ├── models/               # SQLAlchemy relational entities
│   ├── services/             # Core engines (network_scanner, camera_manager, audit_service)
│   ├── database/             # SQLite connection, WAL pragmas, migrations
│   └── websocket/            # ConnectionManager and typed event definitions
├── client/                   # Standalone Python client node
│   ├── main.py               # Client orchestrator & signaling listener
│   ├── ui.py                 # Sleek dark Tkinter GUI with consent modal dialog
│   ├── camera.py             # OpenCV webcam capture & WebSocket streamer
│   ├── network.py            # Local identity discovery & HTTP/WS client
│   └── config.py             # Client token persistence
├── frontend/                 # Web dashboard static assets & pages
├── tests/                    # Pytest automated test suite
├── docs/                     # Architectural, security, and academic report documentation
├── requirements.txt          # Python dependencies
├── .env.example              # Configuration template
└── run.py                    # Root server runner and administrative CLI
```

---

## Quick Start Guide

### 1. Install Dependencies
```bash
py -m pip install -r requirements.txt
```

### 2. Configure Environment
```bash
copy .env.example .env
```

### 3. Initialize Administrator Credentials
Either configure via the first-time web setup wizard at `http://localhost:8000/login.html` or run the CLI helper:
```bash
py run.py --setup-admin admin SuperSecretPassword2026!
```

### 4. Start NETSENTRY Server
```bash
py run.py
```
Access the dashboard at: **`http://localhost:8000`**

### 5. Start the NETSENTRY Client Node
On the client workstation/laptop:
```bash
py client/main.py
```
1. Open the dashboard under **Settings** &rarr; **Enroll New NETSENTRY Client Device**.
2. Click **Generate New Enrollment Code** to obtain an active code (e.g., `NET-8F4K-29P`).
3. Enter the Server URL and code into the client GUI, then click **Register & Connect**.
4. The client will connect, report heartbeat, and await authorized administrative requests.

### 6. Run the Test Suite
```bash
py -m pytest tests/ -v
```
All 17 tests verify authentication, rate limiting, ARP parsing, device classification, and **the critical invariant that camera requests do NOT auto-start the camera without explicit consent**.

---

## Evaluation Demonstration Mode

For controlled demonstrations or academic defenses:
```bash
py run.py --demo
```
This enables simulated discovery and dynamic network events clearly labeled with `[DEMO MODE]`.

---

## License & Author
NETSENTRY is designed and developed as an authorized cybersecurity and computer engineering academic project. Strictly intended for authorized research and educational environments.
