# OneMachine Licensing POC

A minimal proof-of-concept for the OneMachine offline licensing system, built step-by-step with TDD. Three machines: one issuer (Laptop A), two clients (Laptops B & C).

---

## What this demonstrates

- **Node-locked seat** — license bound to a machine fingerprint (hostname + MAC hash).
- **Time-limited validity** — `not_before` / `not_after` timestamps enforced at runtime.
- **Clock-rollback detection** — `last_seen.json` monotonic check.
- **Feature flags** — per-module gates (`rag_chat`, `transcriber`, etc.).
- **Seat cap** — issuer refuses to sign more licenses than `MAX_SEATS` per product.
- **Ed25519 signatures** — license payload signed on Laptop A, verified on clients with the public key only.

---

## Build Plan (TDD, step by step)

Each phase: **write failing tests first → implement → verify tests pass → commit.**

### Phase 0 — Repo skeleton
```
verify: repo created, CLAUDE.md present, README up to date, CI runs (empty)
```
- [ ] Create `src/` and `tests/` directories
- [ ] Add `requirements.txt` (`cryptography`, `pytest`)
- [ ] Add `pytest.ini` / `pyproject.toml`
- [ ] Add GitHub Actions CI (`pytest` on push)

### Phase 1 — Machine fingerprint
```
verify: test_fingerprint.py passes; fingerprint is stable across calls on same machine
```
- [ ] `tests/test_fingerprint.py` — assert fingerprint is 64-char hex, stable, non-empty
- [ ] `src/fingerprint.py` — sha256(hostname + MAC)

### Phase 2 — License file schema & signing (Laptop A)
```
verify: test_issuer.py passes; license JSON validates schema, signature verifies with public key
```
- [ ] `tests/test_issuer.py` — assert signed license parses, signature verifies, fields present
- [ ] `src/keygen.py` — Ed25519 key generation
- [ ] `src/issuer.py` — sign payload, write `license_<fp8>.json`, reject if seat cap reached

### Phase 3 — License core / verification (Clients)
```
verify: test_license_core.py passes for valid license, expired license, wrong machine, tampered payload, clock rollback
```
- [ ] `tests/test_license_core.py` — parametrized tests for each failure mode
- [ ] `src/license_core.py` — load + verify signature, fingerprint check, time window, clock rollback

### Phase 4 — Feature gating
```
verify: test_feature_gate.py passes; disabled features raise clear error; enabled features pass through
```
- [ ] `tests/test_feature_gate.py`
- [ ] `src/demo_app.py` — REPL wired to license core, feature checks per command

### Phase 5 — Seat cap (Issuer)
```
verify: issuing MAX_SEATS+1 licenses raises SeatCapError; SQLite seats.db reflects counts
```
- [ ] `tests/test_seat_cap.py`
- [ ] Update `src/issuer.py` with SQLite seat tracking

### Phase 6 — End-to-end demo script
```
verify: running e2e.sh on three machines produces expected output for each scenario
```
- [ ] `scripts/e2e.sh` — automates fingerprint collection, license issuance, client verification
- [ ] `docs/demo_runbook.md` — instructions for live three-laptop demo

---

## Repo layout (target)

```
onemachine-licensing-poc/
├── CLAUDE.md
├── README.md
├── requirements.txt
├── pyproject.toml
├── src/
│   ├── fingerprint.py
│   ├── keygen.py
│   ├── issuer.py
│   ├── license_core.py
│   └── demo_app.py
├── tests/
│   ├── test_fingerprint.py
│   ├── test_issuer.py
│   ├── test_license_core.py
│   ├── test_feature_gate.py
│   └── test_seat_cap.py
├── scripts/
│   └── e2e.sh
└── docs/
    └── demo_runbook.md
```

---

## Setup

```bash
pip install -r requirements.txt
pytest
```

---

## Architecture reference

See the [design thread context](docs/onemachine_licensing_design_thread_context.md) and the full OneMachine licensing design doc for the complete threat model, hardware fingerprint spec, and floating-seat extension plan.
