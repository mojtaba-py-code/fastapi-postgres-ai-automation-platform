"""Properties of the repository itself that break deployments when lost.

A checkout on Windows does not track the executable bit: a script re-added from
there is stored as 100644, and ``scripts/backup.sh`` then fails with
"Permission denied" on every Linux host - exactly what the first CI run of the
backup-and-restore step found.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Sourced by the PostgreSQL image's entrypoint when not executable (it relies on
# the entrypoint's environment); keep it that way.
_SOURCED = {"deploy/postgres/init/01-roles.sh"}


def _tracked_modes() -> dict[str, str]:
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    listing = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [git, "ls-files", "-s"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    modes: dict[str, str] = {}
    for line in listing.splitlines():
        meta, _, path = line.partition("\t")
        modes[path] = meta.split()[0]
    return modes


def test_every_script_with_a_shebang_is_executable_in_git() -> None:
    modes = _tracked_modes()
    scripts = [
        path
        for path in modes
        if path not in _SOURCED
        and (ROOT / path).is_file()
        and (ROOT / path).read_bytes()[:2] == b"#!"
    ]
    assert "scripts/backup.sh" in scripts
    not_executable = sorted(path for path in scripts if modes[path] != "100755")
    assert not not_executable, f"run: git update-index --chmod=+x {' '.join(not_executable)}"
