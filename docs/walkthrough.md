# Walkthrough: NETSENTRY - Local Wi-Fi Network Monitoring & Consent-Based Remote Camera System

NETSENTRY has been designed, implemented, and rigorously validated as a production-grade, authorized network monitoring and consent-based remote optical inspection platform.

---

## 1. Project Summary & Completed Components

### Backend Architecture (`app/`)
- **FastAPI Core & Lifespan (`app/main.py`)**: Asynchronous REST and WebSocket hub with automated database initialization and background network monitor task management.
- **Relational Data Tier (`app/models/`, `app/database/`)**: SQLite in Write-Ahead Logging (`WAL`) mode with foreign key integrity. Includes `User`, `Device`, `RegistrationCode`, `DeviceToken`, `CameraSession`, `Alert`, `AuditLog`, `NetworkScan`, and `SystemSetting`.
- **Authorized Network Discovery Engine (`app/services/network_scanner.py`)**: Multi-threaded ICMP socket probe sweep combined with native ARP cache extraction (`arp -a` and PowerShell `Get-NetNeighbor`) strictly bounded to administrator-authorized CIDR subnets (e.g. `192.168.1.0/24`).
- **Hardware OUI Registry (`app/services/vendor_lookup.py`)**: MAC normalization and vendor mapping across Apple, Raspberry Pi, Cisco, Intel, TP-Link, Samsung, Dell, HP, Espressif, and hundreds of hardware manufacturers.
- **Consent-Driven Camera Subsystem (`app/services/camera_manager.py`)**: Enforces the critical invariant that camera access cannot be covert or forced. Manages permission handshakes, 10-minute maximum session timeouts, and unilateral termination (`STOP CAMERA` / `END SESSION`).
- **Real-Time Signaling & Frame Relay (`app/websocket/manager.py`)**: Real-time event broadcasting (`/ws/dashboard`), persistent client keepalive (`/ws/client/{device_uuid}`), and binary JPEG frame transport (`/ws/camera/stream/{session_uuid}`).
- **Executive PDF & CSV Reports (`app/services/report_service.py`)**: Branded PDF reports generated via ReportLab and CSV exports for device inventory, camera access audits, and immutable security logs.

---

### NETSENTRY Client Application (`client/`)
- **Visible Dark Cybersecurity UI (`client/ui.py`)**: Built with Python Tkinter matching the web console theme. Displays local IP, MAC address, hostname, connection status, and active camera state. **Does NOT hide itself or run surreptitiously.**
- **MANDATORY Camera Consent Dialog**: When an administrator requests camera access, an unmissable modal dialog appears on the client's screen showing administrator identity, purpose, and duration with explicit **[DENY]** and **[ALLOW]** buttons.
- **Active Streaming Indicator & Revocation**: When streaming, displays a prominent red `CAMERA ACTIVE` banner, an active countdown, and a red **[STOP CAMERA]** button allowing instant user-driven termination at any second.
- **Camera Engine (`client/camera.py`)**: Captures real OpenCV webcam frames when hardware is present, or generates an authorized test feed with status watermark if camera hardware is occupied or unavailable.
- **Privacy & Policy Viewer**: Transparently presents what data is collected, why, and confirms zero background recording.

---

### Web Surveillance Console (`frontend/`)
A responsive dark cybersecurity-inspired interface (using custom CSS tokens, glowing status badges, and Chart.js analytics):
1. **[dashboard.html](file:///c:/Users/georg/Desktop/nsentry/frontend/dashboard.html)**: 6 KPI metrics cards, real-time activity and device classification charts, live device inventory table, and Quick Scan trigger.
2. **[login.html](file:///c:/Users/georg/Desktop/nsentry/frontend/login.html)**: Secure administrator login and automatic initial setup wizard (no hardcoded credentials).
3. **[devices.html](file:///c:/Users/georg/Desktop/nsentry/frontend/devices.html)**: Searchable and filterable device inventory with trust toggles and direct camera access triggers.
4. **[device-details.html](file:///c:/Users/georg/Desktop/nsentry/frontend/device-details.html)**: Deep hardware inspection, custom alias editor, camera session history, and full audit timeline.
5. **[network.html](file:///c:/Users/georg/Desktop/nsentry/frontend/network.html)**: Interface telemetry, authorized subnet CIDR configuration, background monitor controls, and Demo Mode toggle.
6. **[camera.html](file:///c:/Users/georg/Desktop/nsentry/frontend/camera.html)**: 3-panel surveillance workstation (Target Device, Live Video Stream Canvas with timestamp overlay, and Session Telemetry with [END SESSION] button).
7. **[alerts.html](file:///c:/Users/georg/Desktop/nsentry/frontend/alerts.html)**: Filterable notification center with severity badges and read tracking.
8. **[audit.html](file:///c:/Users/georg/Desktop/nsentry/frontend/audit.html)**: Immutable, append-only security audit log ledger.
9. **[reports.html](file:///c:/Users/georg/Desktop/nsentry/frontend/reports.html)**: One-click branded PDF and CSV report download center.
10. **[settings.html](file:///c:/Users/georg/Desktop/nsentry/frontend/settings.html)**: Ephemeral client registration code generator (`NET-XXXX-XXX`) with countdown timer and password manager.

---

## 2. Test Verification & Results

We executed the full automated Pytest test suite spanning 18 test cases across unit, security, network, camera permission, and end-to-end integration workflows:

```bash
py -m pytest tests/ -v
```

### Test Results
| Test File | Test Name | Status | Verified Functionality |
|---|---|---|---|
| `test_auth.py` | `test_password_hashing` | **PASSED** | Salted bcrypt work factor 12 hashing and verification |
| `test_auth.py` | `test_jwt_token_generation` | **PASSED** | Signed JWT bearer token creation and signature validation |
| `test_auth.py` | `test_authenticate_admin_success` | **PASSED** | Successful admin authentication and session issuance |
| `test_auth.py` | `test_account_lockout_after_max_failed_attempts` | **PASSED** | Account locked for 15 mins after 5 consecutive failed attempts |
| `test_network.py` | `test_mac_normalization` | **PASSED** | MAC address standardization to `AA:BB:CC:DD:EE:FF` |
| `test_network.py` | `test_vendor_lookup` | **PASSED** | Hardware OUI resolution for Apple, Raspberry Pi, TP-Link |
| `test_network.py` | `test_subnet_validation` | **PASSED** | Strict CIDR boundary enforcement (e.g. `192.168.1.0/24`) |
| `test_network.py` | `test_demo_mode_devices` | **PASSED** | Verification of labeled `[DEMO MODE]` device generator |
| `test_devices.py` | `test_device_creation_and_trust` | **PASSED** | Device persistence and administrator trust status toggle |
| `test_devices.py` | `test_device_timeline_generation` | **PASSED** | Audit log timeline aggregation per endpoint |
| `test_camera_permissions.py` | `test_registration_code_expiration` | **PASSED** | Ephemeral code expiration verification |
| `test_camera_permissions.py` | **`test_camera_request_does_not_start_camera`** | **PASSED** | **CRITICAL**: Camera request strictly leaves camera in REQUESTED state |
| `test_camera_permissions.py` | `test_camera_permission_denial_workflow` | **PASSED** | User clicking DENY keeps camera OFF and logs denial |
| `test_camera_permissions.py` | `test_camera_permission_approval_workflow` | **PASSED** | User clicking ALLOW marks session APPROVED and records timestamps |
| `test_client.py` | `test_client_local_info_detection` | **PASSED** | Local machine IP, MAC, and hostname resolution |
| `test_client.py` | `test_camera_streamer_synthetic_frame` | **PASSED** | Valid JPEG binary frame synthesis with status watermark |
| `test_audit.py` | `test_audit_logging_immutability` | **PASSED** | Immutable audit records written with actor, IP, and metadata |
| `test_e2e_workflow.py` | **`test_complete_consent_workflow_allow_and_deny`** | **PASSED** | **Complete Section 38 Success Criteria verified end-to-end** |

**Summary: 18 passed in 10.86s (100% pass rate).**

---

## 3. How to Run NETSENTRY

### Step 1: Start the Server
Double-click `run_server.bat` or run:
```bash
py run.py
```
Open **`http://localhost:8000`** in any web browser.

### Step 2: Configure Administrator Account
If not already configured, log in with credentials:
- **Username**: `admin`
- **Password**: `TestAdminPass123!` (or create a new administrator account)

### Step 3: Launch the Client Node
On any device on the local network (or the same host):
Double-click `run_client.bat` or run:
```bash
py client/main.py
```
1. Open the Admin web dashboard under **Settings** &rarr; **Enroll New NETSENTRY Client Device**.
2. Click **Generate New Enrollment Code** to obtain an active code (e.g. `NET-XXXX-XXX`).
3. Enter the code in the client GUI and click **Register & Connect**.
4. The client will connect, report heartbeat, and await authorized administrative requests.

### Step 4: Test Consent Camera Access
1. In the web dashboard, navigate to **Devices** or **Camera Sessions**.
2. Click **Request Camera** on the registered client.
3. Observe the client GUI immediately display the visible modal:
   - "NETSENTRY CAMERA ACCESS REQUEST"
   - Administrator name, purpose, duration
   - **[DENY]** and **[ALLOW]** buttons
4. Test clicking **[DENY]**: Camera remains completely off, server logs `CAMERA_DENIED`.
5. Test clicking **[ALLOW]**: Camera turns on, client visibly shows glowing red `CAMERA ACTIVE` banner with countdown and a large red **[STOP CAMERA]** button, and the admin sees the live optical feed in real time.
6. Click **[STOP CAMERA]** on the client: stream terminates immediately on both sides and logs `CAMERA_STOPPED`.
