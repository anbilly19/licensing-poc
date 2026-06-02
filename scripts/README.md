# scripts/

| Script | Platform | Purpose |
|---|---|---|
| `uninstall.ps1` | Windows | Remove all license state (files, registry, mirror) |
| `uninstall.sh` | Linux / macOS | Remove all license state (files, mirror, dotfiles, secret store) |

## uninstall.ps1

```powershell
# From repo root (no admin needed for HKCU; admin needed to clear HKLM)
powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1
```

Optional flags:
- `-LicenseDir <path>` — directory containing `license.json` / `last_seen.json` (default: repo root)
- `-Quiet` — suppress per-file output

## uninstall.sh

```bash
bash scripts/uninstall.sh
```

Optional flags:
- `--dir <path>` — directory containing `license.json` / `last_seen.json` (default: repo root)
- `--quiet` — suppress per-file output

## What gets removed

**All platforms**
- `license.json`
- `last_seen.json`
- `public_key.pem`
- `fingerprint.txt`

**Windows**
- `%APPDATA%\LicensePOC\` (mirror + boot anchor)
- `HKLM\Software\LicensePOC`
- `HKCU\Software\LicensePOC`

**macOS**
- `~/Library/Application Support/LicensePOC/`
- Keychain entries under `com.licensing-poc.app`

**Linux**
- `$XDG_DATA_HOME/licensing-poc/` (or `~/.local/share/licensing-poc/`)
- `~/.config/.licensing-poc/` (dotfile anchor)
- secretstorage entries (`app=licensing-poc`)
- xattr `user.licensing_poc_sig` / `user.licensing_poc_anchor` on `last_seen.json`
