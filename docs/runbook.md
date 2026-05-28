# Runbook

Step-by-step guide for setting up, testing, and releasing OneMachine Licensing.

---

## Prerequisites

```bash
# Install uv: https://docs.astral.sh/uv/
curl -LsSf https://astral.sh/uv/install.sh | sh   # Linux/macOS
# Windows: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

git clone https://github.com/anbilly19/onemachine-licensing-poc.git
cd onemachine-licensing-poc
uv sync
uv pip install fastapi uvicorn
```

---

## Local dev flow (single machine)

### 1. Generate keypair

```bash
uv run onemachine-license keygen
# Writes: private_key.pem  public_key.pem
```

> Keep `private_key.pem` secret. Embed `public_key.pem` into the binary before shipping — see [`build.md`](build.md).

### 2. Start the activation server (Terminal 1)

```bash
uv run uvicorn src.activation_server:app --reload --port 8000
```

Optional env overrides:

```bash
export PRIVATE_KEY_PATH=private_key.pem
export DB_PATH=seats.db
export ADMIN_TOKEN=my-secret-token   # default: change-me-in-production
```

### 3. Create an activation key (Terminal 2)

```bash
uv run onemachine-license create-key \
  --activation-key  "DEMO-2026-ABCD-EFGH" \
  --customer-id     "cust-de-0042" \
  --customer-name   "Müller GmbH" \
  --max-seats       2 \
  --features        "rag_chat,transcriber" \
  --license-minutes 10080 \
  --subscription-days 365
```

| Parameter | Meaning |
|---|---|
| `--license-minutes` | Validity window of each issued `license.json` (default: 10080 = 7 days) |
| `--subscription-days` | How long the activation key accepts heartbeats (default: 365) |

### 4. Activate a machine

```bash
uv run onemachine-license activate --activation-key "DEMO-2026-ABCD-EFGH"
# Writes license.json
```

### 5. Run the demo REPL

```bash
uv run onemachine-license demo
# Feature-gated REPL. License is re-checked before every command and every 60 s.
```

### 6. Renew / heartbeat

```bash
uv run onemachine-license heartbeat
# Re-signs license.json with a fresh validity window
```

---

## Demo scenarios

| Scenario | How |
|---|---|
| Online activation | Steps 2–5 above on two terminals |
| Node-locking | Copy `license.json` to a second machine → **E0003** (wrong fingerprint) |
| Expiry (mid-session) | Issue with `--license-minutes 2` → sit at the REPL → session terminates |
| Feature gating | Create key with only `rag_chat` → `transcribe` returns **DENIED** |
| Seat cap | Activate a 3rd machine on a `--max-seats 2` key → **E1002** |
| Revocation | Delete the key row from `seats.db` → next heartbeat returns `valid: false` |
| Offline mode | Stop the server → heartbeat warns but cached license works until `not_after` |
| Clock rollback | Roll back system clock → **ROLLBACK DETECTED** |

---

## Releasing a new version

```bash
git tag v0.X.Y
git push origin v0.X.Y
# GitHub Actions builds Linux / Windows / macOS executables and publishes the Release
```

Binaries are attached to the release as:

| Platform | Binary |
|---|---|
| Windows | `onemachine-license-win.exe` |
| Linux | `onemachine-license-linux` |
| macOS | `onemachine-license-mac` |

> Always rebuild and re-release after security patches. See [`build.md`](build.md) for the full Nuitka compilation steps.

---

## Test suite

```bash
uv run pytest -v
```
