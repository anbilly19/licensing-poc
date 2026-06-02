# Tauri + Rust Integration

Notes for integrating the Licensing POC into a Tauri desktop application.

---

## Component mapping

| POC component | Tauri equivalent |
|---|---|
| `license_core.py` | Python sidecar spawned by Tauri via the sidecar API |
| `activation_client.py` | Python sidecar calls `/activate` and `/heartbeat` |
| `public_key.pem` embedding | Embedded in the **Rust binary** via `include_bytes!()` |
| CLI entry point | Replaced by Tauri `#[tauri::command]` |
| Ed25519 verification | Moves to Rust (`ed25519-dalek`) — key never in Python |

---

## Security improvement over the standalone PoC

In the Tauri architecture, Ed25519 signature verification happens inside the Rust binary (which is OS code-signed), rather than in Python bytecode. This means:

- The embedded public key is in compiled Rust — significantly harder to extract than a Nuitka constant
- The Python sidecar handles clock chains, HMAC, NTP, and anchor writes but **cannot forge a license on its own**
- Tauri's IPC boundary separates UI trust from license trust

---

## Suggested sidecar flow

```
Tauri frontend
    │
    │  invoke("check_license")
    ▼
Tauri Rust core
    │  spawn sidecar (license binary)
    ▼
Python sidecar
    │  reads license.json, verifies HMAC chain
    │  calls /heartbeat if renewal due
    │  returns {valid: bool, features: [...]}
    ▼
Tauri Rust core
    │  verifies Ed25519 signature (ed25519-dalek)
    │  gates feature flags in Rust
    ▼
Frontend (features enabled/disabled)
```

---

## Key management in Rust

```rust
// In your Tauri Rust core
const VENDOR_PUBLIC_KEY: &[u8] = include_bytes!("../../keys/public_key.pem");

fn verify_license(payload_bytes: &[u8], signature_b64: &str) -> Result<(), LicenseError> {
    let key = Ed25519PublicKey::from_pem(VENDOR_PUBLIC_KEY)?;
    let sig_bytes = base64::decode(signature_b64)?;
    key.verify(payload_bytes, &sig_bytes).map_err(|_| LicenseError::InvalidSignature)
}
```

The Python sidecar is responsible for everything that requires a persistent clock chain (HMAC, NTP, boot anchor) but the final gate is always the Rust verification step.
