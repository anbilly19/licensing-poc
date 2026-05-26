"""Build standalone executables with Nuitka.

Usage (run from repo root with uv):
    uv run python scripts/build_executables.py

Outputs to dist/:
    onemachine-license          (Linux/macOS)
    onemachine-license.exe      (Windows)
"""
from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path


def main() -> None:
    dist = Path("dist")
    dist.mkdir(exist_ok=True)

    system = platform.system()
    exe_name = "onemachine-license" + (".exe" if system == "Windows" else "")
    output_path = dist / exe_name

    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--onefile",
        "--standalone",
        "--assume-yes-for-downloads",
        f"--output-filename={exe_name}",
        f"--output-dir={dist}",
        # Include cryptography and its backends
        "--include-package=cryptography",
        "--include-package=cryptography.hazmat.primitives",
        "--include-package=cryptography.hazmat.backends",
        "--include-package=cryptography.hazmat.bindings",
        # Entry point
        "src/cli.py",
    ]

    print(f"Building {exe_name} for {system}...")
    print("Command:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"\nBuild complete: {output_path}")


if __name__ == "__main__":
    main()
