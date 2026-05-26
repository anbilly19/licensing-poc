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

## Option A — Standalone executable (no Python needed)

Download the binary for your platform from [Releases](../../releases).

| Platform | Binary |
|---|---|
| Windows | `onemachine-license-win.exe` |
| Linux | `onemachine-license-linux` |
| macOS | `onemachine-license-mac` |

### Vendor (Laptop A)

**Windows**
```
onemachine-license-win.exe keygen
onemachine-license-win.exe fingerprint
onemachine-license-win.exe issue --fingerprint <hex> --features rag_chat,transcriber --minutes 60
```

**Linux/macOS**
```bash
chmod +x onemachine-license-linux
./onemachine-license-linux keygen
./onemachine-license-linux issue --fingerprint <hex> --features rag_chat,transcriber --minutes 60
```

### Client (Laptops B & C)

1. Download the binary for your platform
2. **Windows:** open PowerShell or CMD in the download folder
   **Linux/macOS:** `chmod +x onemachine-license-linux`
3. Get your fingerprint and send it to the vendor:
   ```
   onemachine-license-win.exe fingerprint
   ```
4. Place the two files from the vendor in the **same folder** as the binary:
   ```
   onemachine-license-win.exe   <- binary
   license.json                 <- rename from license_<fp8>.json
   public_key.pem               <- from vendor
   ```
5. Run the demo:
   ```
   onemachine-license-win.exe demo
   ```

---

## Option B — Dev setup with uv

```bash
# Install uv: https://docs.astral.sh/uv/
curl -LsSf https://astral.sh/uv/install.sh | sh   # Linux/macOS
# Windows: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

git clone https://github.com/anbilly19/onemachine-licensing-poc.git
cd onemachine-licensing-poc
uv sync

# Vendor
uv run onemachine-license keygen
uv run onemachine-license issue --fingerprint <hex> --features rag_chat,transcriber --minutes 60

# Client
uv run onemachine-license fingerprint
uv run onemachine-license demo

# Tests
uv run pytest -v
```

---

## Release a new version

```bash
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions builds Linux/Windows/macOS executables and publishes the Release
```

---

## Demo scenarios to showcase

| Scenario | How to demo |
|---|---|
| Node-locking | Copy `license.json` from B to C → DENIED (wrong fingerprint) |
| Expiry | Issue a 2-min license → wait → re-run demo → EXPIRED |
| Feature gating | Laptop C gets only `rag_chat` → `transcribe` is DENIED |
| Seat cap | Try issuing a 3rd license on Laptop A → SEAT CAP error |
| Offline | Disconnect all network on Laptop B → demo still works |
| Clock rollback | Roll back system clock → ROLLBACK DETECTED error |

---

## Files the vendor must keep

| File | Purpose | Share? |
|---|---|---|
| `private_key.pem` | Signs licenses | ❌ Never |
| `public_key.pem` | Verifies licenses | ✅ Send to all clients |
| `seats.db` | Tracks issued seats | ❌ Keep locally |
