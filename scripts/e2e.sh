#!/usr/bin/env bash
# End-to-end demo script for the OneMachine Licensing POC.
# Run on Laptop A (issuer). Laptops B and C must have:
#   - Python 3.11+
#   - requirements.txt installed
#   - public_key.pem copied from Laptop A

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."; pwd)"
cd "$REPO_ROOT"

echo "=== Step 1: Generate keypair (Laptop A only, run once) ==="
if [ ! -f private_key.pem ]; then
    python -m src.keygen
    echo "Keys generated."
else
    echo "Keys already exist, skipping."
fi

echo ""
echo "=== Step 2: Collect fingerprints from Laptops B and C ==="
read -rp "Laptop B fingerprint: " FP_B
read -rp "Laptop C fingerprint: " FP_C

echo ""
echo "=== Step 3: Issue license for Laptop B (rag_chat + transcriber, 2 min) ==="
python - <<EOF
from src.issuer import issue_license
from pathlib import Path
import json
lic = issue_license("$FP_B", ["rag_chat", "transcriber"], Path("private_key.pem"), Path("seats.db"), max_seats=2, minutes_valid=2)
Path("license_B.json").write_text(json.dumps(lic, indent=2))
print("license_B.json written")
EOF

echo ""
echo "=== Step 4: Issue license for Laptop C (rag_chat only, 10 min) ==="
python - <<EOF
from src.issuer import issue_license
from pathlib import Path
import json
lic = issue_license("$FP_C", ["rag_chat"], Path("private_key.pem"), Path("seats.db"), max_seats=2, minutes_valid=10)
Path("license_C.json").write_text(json.dumps(lic, indent=2))
print("license_C.json written")
EOF

echo ""
echo "=== Step 5: Attempt third license (should hit seat cap) ==="
python - <<EOF || echo "[EXPECTED] Seat cap error caught."
from src.issuer import issue_license
from pathlib import Path
issue_license("d" * 64, ["rag_chat"], Path("private_key.pem"), Path("seats.db"), max_seats=2)
EOF

echo ""
echo "=== Done ==="
echo "Copy license_B.json to Laptop B as license.json"
echo "Copy license_C.json to Laptop C as license.json"
echo "On each client: python -m src.demo_app"
echo "  Laptop B: 'rag' and 'transcribe' work for 2 minutes, then expire."
echo "  Laptop C: 'rag' works, 'transcribe' is blocked."
