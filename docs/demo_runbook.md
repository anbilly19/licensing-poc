# Demo Runbook — OneMachine Licensing POC

Three machines: **Laptop A** (issuer), **Laptop B** (full features, short expiry), **Laptop C** (restricted features).

---

## Prerequisites

All three laptops:
```bash
pip install -r requirements.txt
```

Laptop A only:
```bash
python -m src.keygen
# Generates private_key.pem and public_key.pem
```

Copy `public_key.pem` from Laptop A to Laptops B and C.

---

## Step 1 — Collect fingerprints

On **Laptop B**:
```bash
python -m src.fingerprint
# Copy the printed 64-char hex string and send to Laptop A operator
```

On **Laptop C**: same.

---

## Step 2 — Issue licenses (Laptop A)

```bash
bash scripts/e2e.sh
```

Paste each fingerprint when prompted. The script:
- Issues `license_B.json` — features: `rag_chat`, `transcriber`, valid **2 minutes**
- Issues `license_C.json` — features: `rag_chat` only, valid **10 minutes**
- Attempts a third license → shows **SeatCapError** (max 2 seats)

---

## Step 3 — Distribute licenses

| File | Goes to | Save as |
|---|---|---|
| `license_B.json` | Laptop B | `license.json` |
| `license_C.json` | Laptop C | `license.json` |

---

## Step 4 — Run demo app on each client

```bash
python -m src.demo_app
```

### Laptop B (full features, 2-min license)

| Command | Expected |
|---|---|
| `rag` | `[RAG] Query executed.` |
| `transcribe` | `[Transcriber] Audio transcribed.` |
| *(wait 2 min, rerun app)* | `License error: License expired` |

### Laptop C (restricted, 10-min license)

| Command | Expected |
|---|---|
| `rag` | `[RAG] Query executed.` |
| `transcribe` | `Access denied: Feature 'transcriber' not enabled` |
| `nlsql` | `Access denied: Feature 'nl_sql' not enabled` |

---

## Step 5 — Clock rollback demo (optional)

On Laptop B after a successful run:
1. Set system clock back 10 minutes.
2. Run `python -m src.demo_app`.
3. Expected: `License error: Clock rollback detected`.

---

## Talking points for the demo

- **Node-locking**: copy `license_B.json` to Laptop C → rejected (wrong fingerprint).
- **Time-bound**: Laptop B license expires in 2 min — live countdown.
- **Feature gating**: same binary, different capabilities per customer.
- **Seat cap**: issuer hard-stops at 2 seats, no third license issued.
- **Tamper-proof**: edit any field in `license.json`, app rejects it (bad signature).
