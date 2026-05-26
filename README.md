# OneMachine Licensing POC

Minimal proof-of-concept for **offline, node-locked, time-bound, feature-gated** software licensing.

## Architecture

- **Ed25519 signatures** — license tamper-proof without network calls
- **Machine fingerprint** — SHA-256 of hostname + MAC address
- **Time bounds** — `not_before` / `not_after` UTC timestamps
- **Feature flags** — per-license module gating
- **Seat cap** — SQLite-backed limit on concurrent machines (vendor side)
- **Clock rollback detection** — local `last_seen.json` guard
- **Fully offline** — client never needs internet after initial setup

---

## Roles

| Role | Machine | Commands |
|---|---|---|
| Vendor | Laptop A | `keygen`, `issue` |
| Client | Laptop B / C | `fingerprint`, `demo` |

---

## Quick Start (dev)

```bash
# Install uv: https://docs.astral.sh/uv/
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install deps
uv sync

# Run tests
uv run pytest -v
```

---

## Full Demo Flow (3 Laptops)

### Step 1 — Vendor: generate keypair (once)

```bash
uv run onemachine-license keygen
# Outputs: private_key.pem, public_key.pem
# Copy public_key.pem to Laptops B and C
```

### Step 2 — Client: get machine fingerprint

```bash
# On Laptop B or C:
uv run onemachine-license fingerprint
# Prints 64-char hex, saves fingerprint.txt
# Send fingerprint.txt (or paste the hex) to the vendor
```

### Step 3 — Vendor: issue a license

```bash
# On Laptop A:
uv run onemachine-license issue \
  --fingerprint <hex from client> \
  --features rag_chat,transcriber \
  --minutes 60
# Outputs: license_<fp8>.json
# Send this file to the client as license.json
```

### Step 4 — Client: run the demo

```bash
# On Laptop B or C:
# Place license.json and public_key.pem in the same directory
uv run onemachine-license demo
```

---

## Standalone Executables (no Python needed)

### Download from GitHub Releases

Go to [Releases](../../releases) and download the binary for your platform:

| Platform | File |
|---|---|
| Linux | `onemachine-license-linux` |
| Windows | `onemachine-license-win.exe` |
| macOS | `onemachine-license-mac` |

```bash
# Linux / macOS
chmod +x onemachine-license-linux
./onemachine-license-linux fingerprint
./onemachine-license-linux demo

# Windows
onemachine-license-win.exe fingerprint
onemachine-license-win.exe demo
```

### Build locally

```bash
uv sync --group dev
uv run python scripts/build_executables.py
# Output: dist/onemachine-license
```

---

## Release a new version

```bash
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions builds Linux/Windows/macOS executables
# and publishes them to the GitHub Release automatically
```

---

## Demo points to showcase

| Scenario | How to demo |
|---|---|
| Node-locking | Copy license from B to C → DENIED (wrong fingerprint) |
| Expiry | Issue a 2-min license → wait → re-run demo → EXPIRED |
| Feature gating | Laptop C gets only `rag_chat` → `transcribe` is DENIED |
| Seat cap | Try issuing a 3rd license on Laptop A → SEAT CAP error |
| Offline | Disconnect all network on Laptop B → demo still works |
| Clock rollback | Roll back system clock → ROLLBACK DETECTED error |
