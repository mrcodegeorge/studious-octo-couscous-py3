# NETSENTRY Database Schema

NETSENTRY uses SQLAlchemy ORM with SQLite in Write-Ahead Logging (`WAL`) mode for high concurrency and zero database lock contention.

## Tables

### 1. `users`
- `id` (INTEGER, PK)
- `uuid` (VARCHAR(36), UNIQUE)
- `username` (VARCHAR(64), UNIQUE, INDEX)
- `email` (VARCHAR(128), UNIQUE)
- `hashed_password` (VARCHAR(255))
- `role` (VARCHAR(32)) - `admin`, `auditor`, `viewer`
- `is_active` (BOOLEAN)
- `failed_logins` (INTEGER)
- `locked_until` (DATETIME)
- `last_login` (DATETIME)
- `created_at`, `updated_at` (DATETIME)

### 2. `devices`
- `id` (INTEGER, PK)
- `device_uuid` (VARCHAR(36), UNIQUE, INDEX)
- `ip_address` (VARCHAR(45), INDEX)
- `mac_address` (VARCHAR(17), UNIQUE, INDEX)
- `hostname` (VARCHAR(128))
- `vendor` (VARCHAR(128))
- `first_seen`, `last_seen` (DATETIME)
- `status` (VARCHAR(32)) - `ONLINE`, `OFFLINE`, `NEW`, `UNKNOWN`
- `trusted` (BOOLEAN)
- `trusted_at` (DATETIME)
- `trusted_by` (VARCHAR(64))
- `client_registered` (BOOLEAN)
- `client_version` (VARCHAR(32))
- `response_time_ms` (FLOAT)
- `custom_label` (VARCHAR(128))
- `created_at`, `updated_at` (DATETIME)

### 3. `registration_codes`
- `id` (INTEGER, PK)
- `code` (VARCHAR(32), UNIQUE, INDEX)
- `created_by` (VARCHAR(64))
- `expires_at` (DATETIME)
- `is_used` (BOOLEAN)
- `used_at` (DATETIME)
- `used_by_device_id` (INTEGER, FK -> `devices.id`)
- `created_at` (DATETIME)

### 4. `device_tokens`
- `id` (INTEGER, PK)
- `device_id` (INTEGER, FK -> `devices.id`)
- `token_hash` (VARCHAR(255), UNIQUE, INDEX)
- `issued_at`, `expires_at`, `last_used_at` (DATETIME)
- `is_revoked` (BOOLEAN)

### 5. `camera_sessions`
- `id` (INTEGER, PK)
- `session_uuid` (VARCHAR(36), UNIQUE, INDEX)
- `device_id` (INTEGER, FK -> `devices.id`)
- `admin_id` (INTEGER, FK -> `users.id`)
- `admin_username` (VARCHAR(64))
- `permission_status` (VARCHAR(32)) - `REQUESTED`, `APPROVED`, `DENIED`, `ACTIVE`, `TERMINATED`, `EXPIRED`
- `purpose` (VARCHAR(255))
- `max_duration_seconds` (INTEGER)
- `requested_at`, `approved_at`, `denied_at`, `started_at`, `ended_at` (DATETIME)
- `session_duration_seconds` (FLOAT)
- `termination_reason` (VARCHAR(64))
- `client_ip`, `admin_ip` (VARCHAR(45))
- `created_at`, `updated_at` (DATETIME)

### 6. `alerts`
- `id` (INTEGER, PK)
- `alert_type` (VARCHAR(64), INDEX)
- `severity` (VARCHAR(16)) - `INFO`, `WARNING`, `CRITICAL`
- `title` (VARCHAR(128))
- `message` (TEXT)
- `device_id` (INTEGER, FK -> `devices.id`)
- `is_read` (BOOLEAN)
- `created_at` (DATETIME)

### 7. `audit_logs`
- `id` (INTEGER, PK)
- `timestamp` (DATETIME, INDEX)
- `actor` (VARCHAR(64), INDEX)
- `actor_type` (VARCHAR(32)) - `ADMIN`, `CLIENT`, `SYSTEM`
- `event` (VARCHAR(64), INDEX)
- `device_id` (INTEGER, FK -> `devices.id`)
- `device_name` (VARCHAR(128))
- `ip_address` (VARCHAR(45))
- `status` (VARCHAR(32))
- `metadata_json` (TEXT)

### 8. `network_scans`
- `id` (INTEGER, PK)
- `started_at`, `completed_at` (DATETIME)
- `duration_seconds` (FLOAT)
- `interface` (VARCHAR(64))
- `subnet` (VARCHAR(64))
- `devices_found`, `new_devices` (INTEGER)
- `scan_type` (VARCHAR(32)) - `ARP`, `ICMP`, `DEMO`
- `status` (VARCHAR(32)) - `RUNNING`, `COMPLETED`, `FAILED`
- `error_message` (TEXT)
