# OneMachine Licensing POC

Minimal proof-of-concept for **offline/online, node-locked, time-bound, feature-gated**
software licensing with an optional activation server for seat management and license
renewal.

## Architecture

- **Ed25519 signatures** — license tamper-proof without network calls
- **Machine fingerprint** — derived from OS hardware identifiers (see [Fingerprinting](#fingerprinting))
- **Time bounds** — `not_before` / `not_after` UTC timestamps
- **Feature flags** — per-license module gating
- **Seat cap** — SQLite-backed limit, tracked per activation key
- **Clock rollback detection** — chained `last_seen.json` guard + NTP + boot-time anchor
- **Online activation** — client calls `/activate` with an activation key; server signs and returns `license.json`
- **Heartbeat / renewal** — client calls `/heartbeat` every 7 days; server re-signs if subscription still valid
- **Fully offline after activation** — client works air-gapped; heartbeat degrades gracefully on network failure

---

## Roles

| Role | Who | Commands |
|---|---|---|
| Vendor | You (server) | `keygen`, `create-key`, `issue` (dev/manual) |
| Client | Customer machine | `activate`, `heartbeat`, `demo` |

---

## Local Development Quickstart

The full flow can be tested on a single machine with two terminal windows.

### 1. Install

```bash
# Install uv: https://docs.astral.sh/uv/
curl -LsSf https://astral.sh/uv/install.sh | sh   # Linux/macOS
# Windows: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

git clone https://github.com/anbilly19/onemachine-licensing-poc.git
cd onemachine-licensing-poc
uv sync
```

Install FastAPI + uvicorn for the activation server:

```bash
uv pip install fastapi uvicorn
```

### 2. Generate keypair (vendor)

```bash
uv run onemachine-license keygen
# Writes: private_key.pem, public_key.pem
```

### 3. Start the activation server (Terminal 1)

```bash
uv run uvicorn src.activation_server:app --reload --port 8000
# → http://localhost:8000
# → http://localhost:8000/docs  (Swagger UI)
```

> **Environment variables** (optional overrides):
> ```bash
> export PRIVATE_KEY_PATH=private_key.pem
> export DB_PATH=seats.db
> export ADMIN_TOKEN=my-secret-admin-token
> ```

### 4. Create an activation key for a customer (Terminal 2, vendor)

```bash
uv run onemachine-license create-key \
  --activation-key  "DEMO-2026-ABCD-EFGH" \
  --customer-id     "cust-de-0042" \
  --customer-name   "Müller GmbH" \
  --max-seats       2 \
  --features        "rag_chat,transcriber" \
  --days            365
```

This writes the key into `seats.db` on the server.

### 5. Activate a machine (Terminal 2, client)

```bash
uv run onemachine-license activate \
  --activation-key "DEMO-2026-ABCD-EFGH"
# Detects machine fingerprint automatically
# Calls http://localhost:8000/activate
# Writes: license.json
```

### 6. Run the demo app

```bash
uv run onemachine-license demo
# Feature-gated REPL — reads license.json and verifies the Ed25519 signature
```

### 7. Force a heartbeat / renewal

```bash
uv run onemachine-license heartbeat
# Calls http://localhost:8000/heartbeat
# Re-signs license.json with a fresh validity window
```

### 8. Run the test suite

```bash
uv run pytest -v
```

---

## Online Activation Flow (detailed)

```
Client                        Activation Server               seats.db
  │                                 │                            │
  │── POST /activate ──────────────►│                            │
  │   {activation_key, fingerprint} │                            │
  │                                 │── lookup activation_key ──►│
  │                                 │◄─ customer, max_seats ─────│
  │                                 │── seat count check ────────│
  │                                 │── sign license (Ed25519)   │
  │                                 │── upsert issued_licenses ─►│
  │◄── {license: {payload, sig}} ───│                            │
  │                                 │                            │
  │  (7 days later)                 │                            │
  │── POST /heartbeat ─────────────►│                            │
  │   {license_id, fingerprint,     │                            │
  │    activation_key}              │── check key still valid ──►│
  │                                 │── re-sign                  │
  │◄── {valid: true, license: ...} ─│                            │
```

**Revocation:** delete or expire the activation key on the server. The next
heartbeat returns `{valid: false}`. The client prints a warning; the cached
license expires naturally at `not_after` — no hard kill.

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/activate` | None | First-time machine activation |
| `POST` | `/heartbeat` | None | Periodic license renewal |
| `POST` | `/admin/create-key` | `Bearer ADMIN_TOKEN` | Create activation key for a customer |
| `GET` | `/health` | None | Server uptime check |
| `GET` | `/docs` | None | Swagger UI (dev only) |

### Example: create a key via curl

```bash
curl -s -X POST http://localhost:8000/admin/create-key \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer change-me-in-production" \
  -d '{
    "activation_key": "ACME-2026-XXXX-YYYY",
    "customer_id":    "cust-001",
    "customer_name":  "Acme Corp",
    "max_seats":      3,
    "features":       ["rag_chat","transcriber"],
    "days_valid":     365
  }' | python -m json.tool
```

### Example: activate via curl (simulates client)

```bash
FP=$(uv run onemachine-license fingerprint | head -1)
curl -s -X POST http://localhost:8000/activate \
  -H "Content-Type: application/json" \
  -d "{\"activation_key\": \"ACME-2026-XXXX-YYYY\", \"machine_fingerprint\": \"$FP\"}" \
  | python -m json.tool
```

---

## CLI Reference

| Command | Role | Description |
|---|---|---|
| `keygen` | Vendor | Generate Ed25519 keypair |
| `create-key` | Vendor | Register an activation key for a customer in `seats.db` |
| `issue` | Vendor (dev) | Manually sign and write a license file (no server needed) |
| `fingerprint` | Client | Print + save this machine's fingerprint |
| `activate` | Client | Activate against the online server, write `license.json` |
| `heartbeat` | Client | Force a renewal check now |
| `install` | Client (legacy) | Install a license bundle (extracts `public_key.pem` + `license.json`) |
| `demo` | Client | Run the feature-gated demo REPL |

---

## Demo Scenarios

| Scenario | How to demo |
|---|---|
| **Online activation** | Run steps 3–6 above on two terminals |
| **Node-locking** | Copy `license.json` to a second machine → DENIED (wrong fingerprint) |
| **Expiry** | Issue a 2-min license → wait → re-run demo → EXPIRED |
| **Feature gating** | Create key with only `rag_chat` → `transcribe` is DENIED |
| **Seat cap** | Activate a 3rd machine with `--max-seats 2` key → SEAT CAP error |
| **Revocation** | Delete key row from `seats.db` → next heartbeat returns `valid: false` |
| **Offline mode** | Stop the server → `heartbeat` warns but cached license still works until expiry |
| **Clock rollback** | Roll back system clock → ROLLBACK DETECTED |

---

## Option A — Standalone executable (no Python needed)

Download the binary for your platform from [Releases](../../releases).

| Platform | Binary |
|---|---|
| Windows | `onemachine-license-win.exe` |
| Linux | `onemachine-license-linux` |
| macOS | `onemachine-license-mac` |

### Client setup

1. Download the binary for your platform.
2. **Place `public_key.pem` in the same folder as the EXE** (see [Public key distribution](#public-key-distribution) below).
3. Run activation (requires network access to the activation server):
   ```
   onemachine-license-win.exe activate --activation-key YOUR-KEY-HERE
   ```
4. Run the demo:
   ```
   onemachine-license-win.exe demo
   ```

> The activation server URL is baked into the binary at build time via the
> `_ACTIVATION_SERVER_URL` constant in `src/activation_client.py`. For dev builds,
> set `ACTIVATION_SERVER_URL=http://<vendor-ip>:8000` in the environment.

---

## Public key distribution

> ⚠️ **This is a critical step.** Skipping it causes **E0001** on the client machine.

The binary needs the vendor Ed25519 public key to verify `license.json`. There are two
ways to provide it — **embedding (correct for production)** and **file copy (acceptable
for testing)**.

---

### ✅ Correct method — embed the key at build time (production)

Before running Nuitka, bake `public_key.pem` directly into the binary so it is never
a separate file that can be substituted or missed:

**Step 1 — Print the key bytes after keygen:**

```bash
python scripts/print_pubkey_bytes.py
# Output looks like: b'-----BEGIN PUBLIC KEY-----\n...'
```

**Step 2 — Paste into `src/license_core.py`:**

```python
# src/license_core.py  — replace the None with your actual key bytes
_VENDOR_PUBLIC_KEY_PEM: Optional[bytes] = b'-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n'
```

**Step 3 — Build the binary:**

```bash
python -m nuitka \
  --onefile \
  --output-filename=onemachine-license-win.exe \
  --include-package=src \
  src/cli.py
```

The resulting EXE carries the public key internally. `public_key.pem` does **not** need
to exist on the client machine. Do **not** ship `public_key.pem` as a separate file in
production — an attacker who can replace it can forge licenses.

---

### 🔧 Workaround — copy the file (dev/testing only)

For local LAN testing with a pre-built dev EXE where the key was not embedded:

1. Copy `public_key.pem` from the vendor machine to the **same folder** as the EXE on the client.
2. Expected folder layout on the client:
   ```
   onemachine-license-win.exe
   public_key.pem          ← copied from vendor
   license.json            ← written by activate
   ```
3. Run `activate` then `demo` as normal.

> ⚠️ Never ship this layout to real customers. A customer who replaces `public_key.pem`
> with their own key can sign arbitrary licenses. Always use the embedded method for
> distributed builds.

---

## Option B — Dev setup with uv

See [Local Development Quickstart](#local-development-quickstart) above.

---

## Release a new version

```bash
git tag v0.2.0
git push origin v0.2.0
# GitHub Actions builds Linux/Windows/macOS executables and publishes the Release
```

---

## Fingerprinting

The machine fingerprint is derived from OS-level hardware identifiers — **not** from
`gethostname()` or `uuid.getnode()`, which are interceptable via `LD_PRELOAD`.

| Platform | Source |
|---|---|
| Linux | `/etc/machine-id` (fallback: `/sys/class/dmi/id/product_uuid`) |
| macOS | `IOPlatformUUID` via `ioreg` |
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |

All sources are read directly from the OS (sysfs, registry, ioreg) — no libc indirection.

---

## Files the vendor must keep

| File | Purpose | Share? |
|---|---|---|
| `private_key.pem` | Signs licenses | ❌ Never |
| `public_key.pem` | Embedded in binary at build time | ❌ Do not distribute as a standalone file |
| `seats.db` | Tracks issued seats + activation keys | ❌ Keep on server |

> **One key pair for all customers.** Each customer receives a unique `license.json`
> signed with the vendor private key and locked to their machine fingerprint. The same
> binary (with the same embedded public key) is shipped to every customer. A new key
> pair is only needed if the private key is compromised.

---

## Security Notes

### What was hardened (6-commit history + post-audit fixes)

The following protections were applied incrementally. Each entry references the relevant
commit and the threat it closes.

#### 1. HMAC salt — `40fd3acc`

A hardcoded `_HMAC_SALT` is mixed into the HMAC key derivation for `last_seen.json`.
Without this, anyone holding `public_key.pem` could recompute the key and forge the
timestamp chain.

#### 2. Linux xattr anchor — `d9d82a95` · Dotfile anchor — `231d6a2c`

The last HMAC signature is stored redundantly in a filesystem xattr on the primary file
and in a separate `~/.config/.onemachine/anchor` dotfile. Deleting `last_seen.json`
alone is caught because the anchor survives.

#### 3. Windows registry anchor — `f29d6e2e`

Writes to `HKLM` (admin-protected) first, with `HKCU` fallback. Same deletion-detection
logic as Linux but using the registry as the out-of-band store.

#### 4. NTP + boot-time offline clock sanity — `f725fb6a`

- **Online:** raw UDP NTP against Cloudflare → pool.ntp.org → Google (no external deps)
- **Offline:** boot-time anchor — stores a `(wall_clock, uptime)` pair HMAC-signed; on
  next run reconstructs expected wall clock from elapsed uptime
- **Arbitration:** both must agree when both are available; one alone is accepted;
  neither → graceful degrade (no false rejections for air-gapped machines)

#### 5. Cross-platform boot anchor — `5de53e16`

Extended the offline boot anchor to all three OSes:

| Platform | Uptime source |
|---|---|
| Linux | `/proc/uptime` |
| macOS | `sysctl kern.boottime` |
| Windows | `GetTickCount64()` via ctypes |

#### 6. Post-audit security hardening — `54b6bf04`

A full security audit (Claude Code automated reverse engineering) discovered 6
vulnerabilities. All were addressed in this commit:

| # | Severity | Vulnerability | Fix applied |
|---|---|---|---|
| 1 | Critical | `public_key.pem` was user-controlled; attacker could substitute their own key and forge any license | Vendor public key embedded as a compiled constant (`_VENDOR_PUBLIC_KEY_PEM`) — `public_key.pem` no longer read from disk at runtime |
| 2 | High | All three mirrors (`last_seen.json`, mirror, anchor dotfile) could be deleted simultaneously, triggering a cold-start with no rollback check | **Linux:** anchor now written to GNOME Keyring via `secretstorage` (cannot be `rm`-ed by user); cold-start **refused** if any anchor exists |
| 3 | Medium | Anchor file stored an identical copy of `last_seen.json`'s `sig` — forging one automatically satisfied the other | Two independent HMAC keys: `_HMAC_SALT_PRIMARY` (signs entries) and `_HMAC_SALT_ANCHOR` (signs the anchor MAC separately) |
| 4 | High | Machine fingerprint used `socket.gethostname()` + `uuid.getnode()` — both interceptable via `LD_PRELOAD` | Fingerprint now derived from `/etc/machine-id` (Linux), `IOPlatformUUID` (macOS), `MachineGuid` registry (Windows) — no libc indirection |
| 5 | Medium | `NUITKA_ONEFILE_DIRECTORY` env var allowed redirect of extracted `.so` files, enabling full cryptography layer replacement | Guard added inside `load_and_verify_license` — aborts with E0002 if the env var is set at verification time |
| 6 | Medium | HMAC key constants (`_HMAC_SALT`, `_last_seen_hmac_key`) extractable from Nuitka bytecode | Dual-key split reduces blast radius; full mitigation requires a server-side heartbeat or TPM-sealed key (future work) |

#### 7. Online activation + heartbeat — `2f8ae2e`

Added server-side activation flow that directly addresses VULN-6 (HMAC key extraction)
and adds revocation capability:

- `activation_keys` table in `seats.db` — per-customer seat cap, expiry, and features
- Seat cap now enforced **per activation key** (not globally)
- `customer_id` and `activation_key` embedded in every signed license payload
- `/heartbeat` allows the server to invalidate a license at renewal time
- Client degrades gracefully on network failure — cached license still works until `not_after`

### Threat coverage summary

| Attack | Mitigated by |
|---|---|
| Forge `license.json` from `public_key.pem` | Embedded vendor key (VULN-1 fix) |
| Substitute own public key to sign arbitrary license | Embedded vendor key (VULN-1 fix) |
| Delete all mirrors + roll back clock | libsecret keychain anchor; cold-start refused (VULN-2 fix) |
| Forge anchor by copying `last_seen.json` sig | Dual HMAC keys — anchor uses independent salt (VULN-3 fix) |
| Spoof machine fingerprint via `LD_PRELOAD` | sysfs / registry / ioreg fingerprint sources (VULN-4 fix) |
| `.so` redirect via `NUITKA_ONEFILE_DIRECTORY` | Env var blocked inside `load_and_verify_license` (VULN-5 fix) |
| Roll back clock while files intact | NTP check |
| Roll back clock while offline | Boot-time uptime anchor |
| VM snapshot restore with mismatched clock | Boot-time anchor (uptime goes backward → ignored; NTP catches online) |
| Primary ↔ mirror file swap | Cross-check of chained entry hashes |
| License used after subscription cancelled | Heartbeat revocation — next renewal returns `valid: false` |
| Seat count exceeded by concurrent activations | Per-activation-key seat cap in `seats.db` |

### Remaining limitations (known, accepted for PoC)

- **HMAC key extraction (VULN-6):** Any secret embedded in a client binary can
  eventually be extracted by a sufficiently motivated attacker. The only fully robust
  solution is a **server-side timestamp authority** that issues signed time attestations.
  The heartbeat endpoint partially addresses this — a revoked machine cannot renew.
- **Binary protection (open-source constraint):** Nuitka alone is reversible with FLIRT
  signatures. Stronger options (PyArmor + Nuitka, ChaosProtector, VMProtect) exist but
  require commercial or non-open-source tooling, which is out of scope for this PoC.
- **`secretstorage` dependency (Linux):** If `libsecret` / GNOME Keyring is unavailable
  (headless servers, minimal distros), the anchor falls back to the user-writable dotfile,
  reducing VULN-2 protection to pre-fix level. A root-owned `/etc/onemachine/.anchor`
  written via a setuid helper would close this gap.
- **Activation server HTTPS:** The server must run behind HTTPS (nginx/caddy) in
  production. Plaintext HTTP exposes the activation key in transit.
- **`ADMIN_TOKEN` strength:** Default `change-me-in-production` must be replaced with a
  strong random secret (`openssl rand -hex 32`) before deployment.

---

## Tauri + React + Python — Integration Notes

The licensing logic is designed to integrate cleanly into a Tauri desktop app:

| POC component | Tauri equivalent |
|---|---|
| `license_core.py` | Python sidecar spawned by Tauri via sidecar API |
| `activation_client.py` | Python sidecar calls `/activate` and `/heartbeat` |
| `public_key.pem` embedding | Embedded in **Rust binary** via `include_bytes!()` |
| CLI entry point | Tauri `#[tauri::command]` replaces the CLI |
| Ed25519 signature verification | Moves to Rust (`ed25519-dalek`) — key never in Python |

The key security improvement over the standalone PoC: signature verification happens
inside the Rust binary (which is code-signed by the OS), so extracting the embedded
public key becomes significantly harder. The Python sidecar handles clock chains,
HMAC, NTP, and anchor writes — but can never forge a license on its own.

---

## Build — embed public key before compiling

> ⚠️ **Do not skip this step.** A binary built without the embedded key will fall back
> to reading `public_key.pem` from disk. If that file is absent on the client machine,
> the client gets **E0001** immediately after activation. If the file is present but
> user-controlled, an attacker can substitute their own key and forge licenses.

Before running Nuitka, set `_VENDOR_PUBLIC_KEY_PEM` in `src/license_core.py` to your
actual key bytes:

```python
# scripts/print_pubkey_bytes.py
from pathlib import Path
data = Path("public_key.pem").read_bytes()
print(repr(data))
```

Paste the output as the value of `_VENDOR_PUBLIC_KEY_PEM` in `src/license_core.py`,
then build. Do **not** include `public_key.pem` in the distributed package.

```bash
# Example Nuitka onefile build (Windows)
python -m nuitka ^
  --onefile ^
  --output-filename=onemachine-license-win.exe ^
  --include-package=src ^
  src/cli.py
```

For the activation server URL, patch `_ACTIVATION_SERVER_URL` in
`src/activation_client.py` to your production URL before building:

```python
_ACTIVATION_SERVER_URL: Optional[str] = "https://license.yourcompany.com"
```
