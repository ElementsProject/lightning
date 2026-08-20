#!/usr/bin/env python

import os
from pathlib import Path

TARGET_SCRIPT = "testplugpass.py"


def get_venv_python():
    base = Path(__file__).resolve().parent

    if os.name == "nt":
        return base / ".venv" / "Scripts" / "python.exe"
    return base / ".venv" / "bin" / "python"


def main():
    base = Path(__file__).resolve().parent
    venv_python = get_venv_python()
    target = base / TARGET_SCRIPT

    if not venv_python.exists():
        raise SystemExit(f"Missing venv python: {venv_python}")

    if not target.exists():
        raise SystemExit(f"Missing target script: {target}")

    # Replace current process (clean execution)
    os.execv(str(venv_python), [str(venv_python), str(target)])


if __name__ == "__main__":
    main()
