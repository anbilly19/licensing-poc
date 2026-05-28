# Build & Distribution

How to compile the EXE, embed the public key, and publish a release.

---

## Step 1 — Embed the public key

> ⚠️ **Do not skip this.** A binary built without the embedded key falls back to reading `public_key.pem` from disk. If that file is absent or user-controlled, an attacker can forge licenses.

After running `keygen`, print the key bytes:

```bash
python scripts/print_pubkey_bytes.py
# Output: b'-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n'
```

Paste the output into `src/license_core.py`:

```python
_VENDOR_PUBLIC_KEY_PEM: Optional[bytes] = b'-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n'
```

---

## Step 2 — Set the activation server URL

In `src/activation_client.py`, set the production URL before building:

```python
_ACTIVATION_SERVER_URL: Optional[str] = "https://license.yourcompany.com"
```

---

## Step 3 — Compile with Nuitka

### Windows

```bash
python -m nuitka ^
  --onefile ^
  --output-filename=onemachine-license-win.exe ^
  --include-package=src ^
  src/cli.py
```

### Linux / macOS

```bash
python -m nuitka \
  --onefile \
  --output-filename=onemachine-license-linux \
  --include-package=src \
  src/cli.py
```

---

## Step 4 — Distribute to clients

The binary is self-contained. Clients need **only**:

```
onemachine-license-win.exe    ← the compiled binary (public key embedded)
```

`license.json` and `last_seen.json` are written by the binary on first run. `public_key.pem` must **not** be included in the distributed package.

---

## Dev/testing workaround (no embedded key)

For local testing with a dev build where the key was not embedded:

1. Copy `public_key.pem` from the vendor machine to the same folder as the EXE.
2. Layout on the client:
   ```
   onemachine-license-win.exe
   public_key.pem          ← from vendor
   license.json            ← written by activate
   ```

> ⚠️ Never ship this layout to real customers.

---

## CI release

```bash
git tag v0.X.Y
git push origin v0.X.Y
# GitHub Actions builds all three platform binaries and attaches them to the Release
```

Always tag a new release after security fixes so the distributed EXE reflects the latest hardening.

---

## Files the vendor must protect

| File | Purpose | Share? |
|---|---|---|
| `private_key.pem` | Signs all licenses | ❌ Never |
| `public_key.pem` | Embedded in binary at build time | ❌ Do not distribute as a standalone file |
| `seats.db` | Tracks seats + activation keys | ❌ Keep on server only |
