# NETSENTRY Deployment & Operation Guide

## Prerequisites
- Python 3.12+ (tested and verified on Python 3.14 on Windows)
- Local network access (Wi-Fi or Ethernet adapter)
- Optional: Physical USB or integrated webcam (if unavailable, NETSENTRY activates verified synthetic optical feed with status watermark)

## Installation Steps

1. Clone or extract the project workspace:
```bash
cd nsentry
```

2. Install dependencies:
```bash
py -m pip install -r requirements.txt
```

3. Initialize configuration:
```bash
copy .env.example .env
```

4. Create the initial administrator account:
```bash
py run.py --setup-admin admin SuperSecretPassword2026!
```

5. Launch the NETSENTRY server:
```bash
py run.py
```
The server will bind to `http://0.0.0.0:8000`.

6. Open the Administrator Dashboard:
Navigate to: `http://localhost:8000`

---

## Client Deployment

1. On a client device within the same authorized local Wi-Fi/LAN:
```bash
py client/main.py
```

2. Generate an enrollment code from the administrator dashboard under **Settings** &rarr; **Enroll New NETSENTRY Client Device** (e.g. `NET-8F4K-29P`).

3. In the client GUI:
- Enter Server URL: `http://<SERVER_IP>:8000`
- Enter Registration Code: `NET-XXXX-XXX`
- Click **Register & Connect**

---

## Demonstration Mode (For Project Defense & Evaluations)

To evaluate NETSENTRY when multiple physical computers or webcams are unavailable:
```bash
py run.py --demo
```
In Demonstration Mode, simulated devices are generated with `[DEMO MODE]` tags, enabling complete end-to-end evaluation of the discovery, classification, consent prompt, and streaming flows.
