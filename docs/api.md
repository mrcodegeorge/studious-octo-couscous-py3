# NETSENTRY API Reference

## Authentication
- `POST /api/auth/setup`: Create the initial primary administrator account (only allowed when no admin exists).
- `GET /api/auth/setup-status`: Check if the platform requires initial setup.
- `POST /api/auth/login`: Authenticate admin with credentials; returns JWT bearer token.
- `POST /api/auth/logout`: Invalidate current session and log audit event.
- `GET /api/auth/me`: Get current authenticated administrator profile.
- `POST /api/auth/change-password`: Update administrator password.

## Network Discovery & Scanning
- `GET /api/network/status`: Fetch current interface, IP, authorized subnet, and scanner status.
- `POST /api/network/scan`: Trigger an immediate authorized network scan.
- `POST /api/network/monitor/start`: Enable background periodic network discovery.
- `POST /api/network/monitor/stop`: Halt background monitoring loop.
- `POST /api/network/subnet`: Update authorized CIDR subnet boundary.
- `POST /api/network/demo-mode`: Toggle Demonstration Simulation Mode.

## Device Inventory
- `GET /api/devices`: List all discovered devices with search, status, and trust filtering.
- `GET /api/devices/summary`: KPI summary counts for the dashboard.
- `GET /api/devices/{id}`: Detailed view including device specs and security audit timeline.
- `POST /api/devices/{id}/trust`: Mark a device as trusted.
- `DELETE /api/devices/{id}/trust`: Remove trusted status.
- `POST /api/devices/{id}/label`: Set human-friendly custom alias for a device.
- `POST /api/devices/{id}/revoke-client`: Revoke client enrollment.

## Consent Camera Management
- `POST /api/camera/request/{device_id}`: Initiate consent-driven camera access request.
- `POST /api/camera/{session_uuid}/terminate`: Terminate active/pending camera session.
- `GET /api/camera/sessions`: List camera session history.
- `GET /api/camera/sessions/{session_uuid}`: Fetch details of a single session.

## Client Communication
- `POST /api/client/generate-code`: Administrator generates ephemeral enrollment code (`NET-XXXX-XXX`).
- `POST /api/client/register`: Client enrolls with code, receives device token.
- `POST /api/client/heartbeat`: Periodic client keepalive ping.
- `POST /api/client/camera/permission`: Client reports user consent decision (`allowed: true/false`).
- `POST /api/client/camera/stop`: Client reports user-initiated stream termination.

## WebSockets
- `GET /ws/dashboard`: Real-time dashboard system events feed.
- `GET /ws/client/{device_uuid}`: Persistent client signaling and prompt delivery.
- `GET /ws/camera/stream/{session_uuid}`: Binary JPEG frame streaming relay (roles: `producer`, `viewer`).

## Reports & Exports
- `GET /api/reports/devices?format={pdf|csv}`: Network device inventory report.
- `GET /api/reports/camera?format={pdf|csv}`: Consent-based camera access audit report.
- `GET /api/reports/audit?format=csv`: Full immutable security audit log export.
