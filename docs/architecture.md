# NETSENTRY Architecture Document

## Overview
NETSENTRY is structured into two autonomous, mutually communicating components:
1. **The Server & Administrative Dashboard (`app/`)**: A high-performance FastAPI service managing network discovery, client enrollment, session state machines, audit trails, and the surveillance dashboard.
2. **The Endpoint Client (`client/`)**: A standalone client node executed on consenting endpoints providing a visible user interface, cryptographic pairing, explicit permission modal dialogs, and hardware camera capture.

## Component Breakdown

```
[ Local LAN Subnet ] <== ARP Table / ICMP Sweep ==> [ Network Scanner Engine ]
                                                             |
                                                             v
[ Admin Browser ] <== WebSocket / REST ==> [ FastAPI Web Core ] <== WebSocket ==> [ Client Node ]
                                                 |                                      |
                                                 v                                      v
                                       [ SQLite Database ]                     [ Hardware Camera ]
```

### 1. Network Discovery Engine (`app/services/network_scanner.py`)
- Automatically resolves local interface IP and calculates the CIDR network boundary.
- Employs a multi-threaded non-blocking ICMP ping sweep across active subnet addresses to trigger OS-level ARP cache resolution.
- Reads the native ARP cache using platform-optimized utilities (`arp -a` and PowerShell `Get-NetNeighbor`).
- Correlates MAC addresses with an extensive OUI dictionary (`app/services/vendor_lookup.py`).
- Filters out broadcast/multicast addresses and strictly adheres to the administrator's authorized subnet boundary.

### 2. Camera Consent State Machine (`app/services/camera_manager.py`)
States:
- `REQUESTED`: Initiated by administrator. The client receives a signaling message and renders the visible modal. Camera is powered OFF.
- `APPROVED`: Remote user clicked `ALLOW`. Client activates camera thread and pushes JPEG frames over WebSocket.
- `DENIED`: Remote user clicked `DENY`. Camera never starts; session transitions to terminal state.
- `ACTIVE`: Streaming is currently underway. Countdown timer is active.
- `TERMINATED`: Stream stopped either by user (`STOP CAMERA`), admin (`END SESSION`), or disconnect.
- `EXPIRED`: Maximum duration limit reached (default: 10 minutes).

### 3. WebSocket Signaling & Streaming Relay (`app/websocket/manager.py`)
- `/ws/dashboard`: Broadcasts real-time events (`DEVICE_DISCOVERED`, `DEVICE_ONLINE`, `DEVICE_OFFLINE`, `CAMERA_APPROVED`, `ALERT_NEW`) to connected administrator consoles.
- `/ws/client/{device_uuid}`: Persistent bidirectional signaling channel between client and server.
- `/ws/camera/stream/{session_uuid}`: Low-latency binary JPEG stream relay transferring video frames from client producer to authorized admin viewers.
