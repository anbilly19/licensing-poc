# API & CLI Reference

---

## Activation server endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/activate` | None | First-time machine activation |
| `POST` | `/heartbeat` | None | Periodic license renewal |
| `POST` | `/admin/create-key` | `Bearer ADMIN_TOKEN` | Create an activation key for a customer |
| `GET` | `/health` | None | Server uptime check |
| `GET` | `/docs` | None | Swagger UI (dev only) |

### POST /activate

```json
// Request
{ "activation_key": "DEMO-KEY", "machine_fingerprint": "<64-char hex>" }

// Response 200
{ "license": { "payload": { ... }, "signature": "<base64>" } }

// Error 422
{ "detail": "E1001" }
```

### POST /heartbeat

```json
// Request
{ "license_id": "L-0001", "machine_fingerprint": "<64-char hex>", "activation_key": "DEMO-KEY" }

// Response 200 — valid
{ "valid": true, "license": { ... } }

// Response 200 — invalid
{ "valid": false, "code": "E2003" }
```

### POST /admin/create-key

```bash
curl -s -X POST http://localhost:8000/admin/create-key \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "activation_key":    "ACME-2026-XXXX-YYYY",
    "customer_id":       "cust-001",
    "customer_name":     "Acme Corp",
    "max_seats":         3,
    "features":          ["rag_chat","transcriber"],
    "license_minutes":   10080,
    "subscription_days": 365
  }' | python -m json.tool
```

---

## CLI reference

| Command | Role | Description |
|---|---|---|
| `keygen` | Vendor | Generate Ed25519 keypair — writes `private_key.pem` + `public_key.pem` |
| `create-key` | Vendor | Register an activation key in `seats.db` |
| `issue` | Vendor (dev) | Manually sign and write a license file (no server) |
| `fingerprint` | Client | Print this machine's fingerprint |
| `activate` | Client | Online activation — writes `license.json` |
| `heartbeat` | Client | Force a renewal check now |
| `install` | Client (legacy) | Install a license bundle |
| `demo` | Client | Run the feature-gated demo REPL |

---

## Error codes

### Client-side (`license_core.py`)

| Code | Meaning | Recovery |
|---|---|---|
| E0001 | Public key not found | Embed key in binary (see `build.md`) or ensure `public_key.pem` is present |
| E0002 | Nuitka onefile extraction context detected — verification refused | Not a user error; stub is running instead of extracted app |
| E0010 | System clock deviates from NTP by > 90 s | Sync system clock |
| E0011 | System clock deviates from boot-time estimate by > 90 s | Sync system clock |
| E0020 | `last_seen.json` unreadable or malformed | Run uninstall script → re-activate |
| E0021 | `last_seen.json` HMAC invalid (tampered) | Run uninstall script → re-activate |
| E0030 | Both chain files missing but registry/keychain anchor exists (re-install attack) | Run uninstall script → re-activate |
| E0031 | Primary `last_seen.json` missing but mirror exists (asymmetric delete) | Run uninstall script → re-activate |
| E0032 | Mirror missing but primary exists (asymmetric delete) | Run uninstall script → re-activate |
| E0033 | Primary and mirror chain hashes diverge (tamper) | Run uninstall script → re-activate |
| E0034 | Registry/keychain anchor signature mismatch | Run uninstall script → re-activate |
| E0035 | Registry/keychain anchor MAC mismatch | Run uninstall script → re-activate |
| E0036 | Clock rolled back (now < last_seen timestamp) | Sync system clock |
| E0040 | `license.json` not found | Run `activate` |
| E0041 | License signature invalid | Obtain a valid license from vendor |
| E0042 | Machine fingerprint mismatch | License was issued for a different machine |
| E0043 | License not yet valid (`not_before` in future) | Check system clock |
| E0044 | License expired | Run `heartbeat` or contact vendor |

### Server-side (`activation_server.py`)

| Code | Meaning |
|---|---|
| E1001 | Activation key not found or invalid |
| E1002 | Seat cap reached |
| E1003 | Internal activation error |
| E2001 | Machine not recognised during heartbeat |
| E2002 | Activation key not found during heartbeat |
| E2003 | Subscription expired |
| E2004 | Internal heartbeat error |
| E3001 | Admin bearer token missing or malformed |
| E3002 | Admin bearer token invalid |
