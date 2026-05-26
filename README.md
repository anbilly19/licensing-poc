# OneMachine Licensing POC

Minimal proof-of-concept for **offline, node-locked, time-bound, feature-gated** software licensing.

## Architecture

- **Ed25519 signatures** — license tamper-proof without network calls
- **Machine fingerprint** — derived from OS hardware identifiers (see [Fingerprinting](#fingerprinting))
- **Time bounds** — `not_before` / `not_after` UTC timestamps
- **Feature flags** — per-license module gating
- **Seat cap** — SQLite-backed limit on concurrent machines (vendor side)
- **Clock rollback detection** — chained `last_seen.json` guard + NTP + boot-time anchor
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
4. Place the **two files** from the vendor in the same folder as the binary:
   ```
   onemachine-license-win.exe   ← binary
   license.json                 ← rename from license_<fp8>.json
   ```
   > **Note:** `public_key.pem` is no longer distributed to clients — it is embedded
   > inside the binary at build time (see [Security Notes](#security-notes)).
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
| `public_key.pem` | Embedded in binary at build time | ❌ Do not distribute |
| `seats.db` | Tracks issued seats | ❌ Keep locally |

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
| 5 | Medium | `NUITKA_ONEFILE_DIRECTORY` env var allowed redirect of extracted `.so` files, enabling full cryptography layer replacement | `_check_nuitka_env()` aborts immediately if the env var is set |
| 6 | Medium | HMAC key constants (`_HMAC_SALT`, `_last_seen_hmac_key`) extractable from Nuitka bytecode | Dual-key split reduces blast radius; full mitigation requires a server-side heartbeat or TPM-sealed key (future work) |

### Threat coverage summary

| Attack | Mitigated by |
|---|---|
| Forge `license.json` from `public_key.pem` | Embedded vendor key (VULN-1 fix) |
| Substitute own public key to sign arbitrary license | Embedded vendor key (VULN-1 fix) |
| Delete all mirrors + roll back clock | libsecret keychain anchor; cold-start refused (VULN-2 fix) |
| Forge anchor by copying `last_seen.json` sig | Dual HMAC keys — anchor uses independent salt (VULN-3 fix) |
| Spoof machine fingerprint via `LD_PRELOAD` | sysfs / registry / ioreg fingerprint sources (VULN-4 fix) |
| `.so` redirect via `NUITKA_ONEFILE_DIRECTORY` | Env var blocked at startup (VULN-5 fix) |
| Roll back clock while files intact | NTP check |
| Roll back clock while offline | Boot-time uptime anchor |
| VM snapshot restore with mismatched clock | Boot-time anchor (uptime goes backward → ignored; NTP catches online) |
| Primary ↔ mirror file swap | Cross-check of chained entry hashes |

### Remaining limitations (known, accepted for PoC)

- **HMAC key extraction (VULN-6):** Any secret embedded in a client binary can
  eventually be extracted by a sufficiently motivated attacker. The only fully robust
  solution is a **server-side timestamp authority** that issues signed time attestations.
  This is scoped as future work.
- **Binary protection (open-source constraint):** Nuitka alone is reversible with FLIRT
  signatures. Stronger options (PyArmor + Nuitka, ChaosProtector, VMProtect) exist but
  require commercial or non-open-source tooling, which is out of scope for this PoC.
- **`secretstorage` dependency (Linux):** If `libsecret` / GNOME Keyring is unavailable
  (headless servers, minimal distros), the anchor falls back to the user-writable dotfile,
  reducing VULN-2 protection to pre-fix level. A root-owned `/etc/onemachine/.anchor`
  written via a setuid helper would close this gap.

---

## Build — embed public key before compiling

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
# Example Nuitka onefile build (Linux)
python -m nuitka \
  --onefile \
  --output-filename=onemachine-license-linux \
  --include-package=src \
  src/cli.py
```
