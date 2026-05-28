# OneMachine Licensing POC

Minimal proof-of-concept for **offline-capable, node-locked, time-bound, feature-gated** software licensing — with an optional activation server for seat management and renewal.

---

## What it does

- Issues Ed25519-signed `license.json` files locked to a specific machine
- Validates licenses fully offline after first activation
- Enforces feature flags, seat caps, and time bounds
- Detects clock rollback via chained HMAC + NTP + boot-time anchor
- Supports online heartbeat renewal and server-side revocation

---

## Quick start

```bash
uv sync
uv pip install fastapi uvicorn

# Terminal 1 — vendor server
uv run uvicorn src.activation_server:app --reload --port 8000

# Terminal 2 — create key + activate
uv run onemachine-license keygen
uv run onemachine-license create-key --activation-key "DEMO-KEY" --customer-id "cust-001" --customer-name "Acme"
uv run onemachine-license activate --activation-key "DEMO-KEY"
uv run onemachine-license demo
```

See [`docs/runbook.md`](docs/runbook.md) for the full step-by-step walkthrough.

---

## Documentation

| Doc | Contents |
|---|---|
| [`docs/runbook.md`](docs/runbook.md) | Local dev setup, activation flow, demo scenarios, release process |
| [`docs/design.md`](docs/design.md) | Architecture, threat model, security hardening history |
| [`docs/api.md`](docs/api.md) | Activation server endpoints, CLI reference, error codes |
| [`docs/build.md`](docs/build.md) | Nuitka compilation, public key embedding, CI release |
| [`docs/integration.md`](docs/integration.md) | Tauri + Rust integration notes |

---

## Roles at a glance

| Role | Who | Typical commands |
|---|---|---|
| Vendor | You (server side) | `keygen`, `create-key`, `issue` |
| Client | Customer machine | `activate`, `heartbeat`, `demo` |

---

## Test suite

```bash
uv run pytest -v
```
