$TOKEN = "YOUR_GITHUB_TOKEN"
$OWNER = "anbilly19"
$REPO  = "licensing-poc"

$BODY_TEMPLATE = @'
## Licensing POC {VER}

> **No Python or uv required on client machines.** Download the binary, place two files next to it, run.

---

## Vendor setup -- Laptop A (run once)

**Linux/macOS**
```bash
chmod +x poc-license-linux
./poc-license-linux keygen
```

**Windows**
```
poc-license-win.exe keygen
```

Outputs `private_key.pem` (keep secret) and `public_key.pem` (send to every client).

---

## Client setup

### Step 1 -- Download the binary

| Platform | File |
|---|---|
| Windows | `poc-license-win.exe` |
| Linux   | `poc-license-linux` |
| macOS   | `poc-license-mac` |

### Step 2 -- Fingerprint

**Windows**
```
poc-license-win.exe fingerprint
```

**Linux/macOS**
```bash
chmod +x poc-license-linux
./poc-license-linux fingerprint
```

This prints a 64-char hex and saves `fingerprint.txt`. Send that to the vendor.

### Step 3 -- Activate

**Windows**
```
poc-license-win.exe activate --activation-key YOUR-KEY
```

**Linux/macOS**
```bash
./poc-license-linux activate --activation-key YOUR-KEY
```

### Step 4 -- Run demo

**Windows**
```
poc-license-win.exe demo
```

**Linux/macOS**
```bash
./poc-license-linux demo
```

---

## Vendor: issue a license for a client

**Windows**
```
poc-license-win.exe issue --fingerprint <64-char hex> --features rag_chat,transcriber --minutes 60
```

**Linux/macOS**
```bash
./poc-license-linux issue --fingerprint <64-char hex> --features rag_chat,transcriber --minutes 60
```

Outputs `license_<fp8>.json` -- rename to `license.json` and send to the client.

---

## Demo commands (inside the REPL)

| Command | Feature required |
|---|---|
| `rag` | `rag_chat` |
| `transcribe` | `transcriber` |
| `sql` | `nl_sql` |
| `reports` | `reports` |
| `info` | always available |
| `quit` | always available |
'@

$TAGS = @(
    "v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0",
    "v0.5.0", "v0.6.0", "v0.7.0", "v0.8.0",
    "v0.9.0", "v0.10.0", "v0.11.0", "v0.12.0"
)

$HEADERS = @{
    Authorization = "Bearer $TOKEN"
    Accept        = "application/vnd.github+json"
}

foreach ($TAG in $TAGS) {
    $release = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$OWNER/$REPO/releases/tags/$TAG" `
        -Headers $HEADERS

    $body = $BODY_TEMPLATE -replace '\{VER\}', $TAG

    $payload = @{
        name = "Licensing POC $TAG"
        body = $body
    } | ConvertTo-Json -Depth 3

    Invoke-RestMethod `
        -Method Patch `
        -Uri "https://api.github.com/repos/$OWNER/$REPO/releases/$($release.id)" `
        -Headers $HEADERS `
        -ContentType "application/json" `
        -Body $payload `
        | Select-Object -ExpandProperty name `
        | ForEach-Object { Write-Host "  updated: $_" }

    Start-Sleep -Milliseconds 300
}

Write-Host "`nAll releases updated."
