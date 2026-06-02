# Design & Security

Architecture overview, threat model, and hardening history.

---

## Architecture

```
Client (EXE)                  Activation Server             seats.db
  │                                 │                            │
  │── POST /activate ──────────────►│                            │
  │   {activation_key, fingerprint} │── lookup + seat check ────►│
  │                                 │── sign license (Ed25519)   │
  │◄── {license: {payload, sig}} ───│── upsert issued_licenses ─►│
  │                                 │                            │
  │  (every 7 days)                 │                            │
  │── POST /heartbeat ─────────────►│── check subscription ─────►│
  │◄── {valid: true, license: ...} ─│── re-sign                  │
```

**Offline after activation.** The client verifies the Ed25519 signature locally on every launch — no server call required. The heartbeat renews the `not_after` window; missing it degrades gracefully until the cached license expires.

**Revocation.** Delete or expire the activation key on the server. The next heartbeat returns `{valid: false}`. The client prints a warning; the cached license expires naturally at `not_after`.

---

## Core components

| Component | File | Role |
|---|---|---|
| License signing | `src/issuer.py` | Ed25519 sign/verify, seat tracking, `seats.db` |
| License verification | `src/license_core.py` | Offline verify: signature, fingerprint, time bounds, Nuitka guard |
| Clock chain | `src/license_core.py` | HMAC-chained `last_seen.json` + NTP + boot-time anchor |
| Machine fingerprint | `src/fingerprint.py` | OS hardware ID — no libc indirection |
| Activation server | `src/activation_server.py` | FastAPI: `/activate`, `/heartbeat`, `/admin/create-key` |
| Activation client | `src/activation_client.py` | HTTP calls to the server |
| CLI | `src/cli.py` | `keygen`, `create-key`, `activate`, `heartbeat`, `demo`, … |

---

## Machine fingerprinting

Derived from OS-level hardware identifiers — not `gethostname()` or `uuid.getnode()`, which are interceptable via `LD_PRELOAD`.

| Platform | Source |
|---|---|
| Linux | `/etc/machine-id` (fallback: `/sys/class/dmi/id/product_uuid`) |
| macOS | `IOPlatformUUID` via `ioreg` |
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |

---

## Clock rollback detection

Three independent anchors must agree:

1. **`last_seen.json`** — HMAC-chained entries; each entry signs `(timestamp, prev_hash)` with `_HMAC_SALT_PRIMARY`
2. **Filesystem / registry anchor** — Linux: xattr + `~/.config/.licensing-poc/anchor` (or libsecret keyring); Windows: `HKLM` registry key. Signed with `_HMAC_SALT_ANCHOR` (independent key)
3. **Boot-time uptime anchor** — stores `(wall_clock, uptime)` at startup; on next run reconstructs expected wall clock from elapsed uptime

NTP check (Cloudflare → pool.ntp.org → Google) is performed when online; raw UDP, no external dependencies.

---

## Security hardening history

| # | Severity | Vulnerability | Fix |
|---|---|---|---|
| VULN-1 | Critical | `public_key.pem` was user-controlled — attacker could substitute their own key and forge any license | Vendor public key embedded as `_VENDOR_PUBLIC_KEY_PEM` compiled constant; file no longer read from disk at runtime |
| VULN-2 | High | All three mirrors deletable simultaneously — cold-start had no rollback check | Cold-start refused if any anchor exists; Linux anchor written to libsecret keyring (not `rm`-able by user) |
| VULN-3 | Medium | Anchor file stored an identical copy of `last_seen.json` sig — forging one satisfied the other | Two independent HMAC keys: `_HMAC_SALT_PRIMARY` and `_HMAC_SALT_ANCHOR` |
| VULN-4 | High | Machine fingerprint used `gethostname()` + `uuid.getnode()` — both interceptable via `LD_PRELOAD` | Fingerprint derived from sysfs / registry / ioreg directly |
| VULN-5 | Medium | `NUITKA_ONEFILE_DIRECTORY` allowed redirect of extracted `.so` files | Guard inside `load_and_verify_license` — aborts with E0002 if env var is set |
| VULN-6 | Medium | HMAC key constants extractable from Nuitka bytecode | Dual-key split reduces blast radius; heartbeat + revocation partially mitigate |

---

## Threat coverage

| Attack | Mitigated by |
|---|---|
| Forge `license.json` with own key | Embedded vendor key (VULN-1) |
| Delete mirrors + roll back clock | Keychain anchor; cold-start refused (VULN-2) |
| Forge anchor by copying sig | Dual HMAC keys (VULN-3) |
| Spoof machine fingerprint via `LD_PRELOAD` | sysfs / registry / ioreg sources (VULN-4) |
| `.so` redirect via Nuitka env var | Env var guard (VULN-5) |
| Clock rollback (online) | NTP check |
| Clock rollback (offline) | Boot-time uptime anchor |
| VM snapshot restore | Boot anchor — uptime goes backward → detected |
| License used after subscription cancelled | Heartbeat revocation |
| Seat overflow | Per-activation-key seat cap in `seats.db` |

---

## Known limitations (accepted for PoC)

- **HMAC key extraction (VULN-6):** Any secret embedded in a client binary can be extracted by a motivated attacker. A server-side timestamp authority issuing signed time attestations is the only fully robust solution.
- **Binary protection:** Nuitka alone is reversible. Stronger options (PyArmor, VMProtect) are out of scope.
- **`secretstorage` dependency:** If `libsecret` / GNOME Keyring is unavailable (headless servers, minimal distros), the anchor falls back to a user-writable dotfile, reducing VULN-2 protection.
- **HTTPS required:** The activation server must run behind HTTPS in production. Plaintext HTTP exposes activation keys in transit.
