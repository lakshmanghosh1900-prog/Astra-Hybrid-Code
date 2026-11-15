"""Clone committed source into a new demo volume; never modify the source checkout."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def main() -> None:
    target = Path("/repositories/repo")
    if target.exists():
        if not (target / ".git").is_dir():
            raise RuntimeError("existing workspace is not a Git repository; refusing to replace it")
        print("existing repository preserved", flush=True)
        return
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git unavailable; refusing to seed a workspace")
    subprocess.run(  # noqa: S603
        [
            git,
            "-c",
            "safe.directory=/source",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--upload-pack=git -c safe.directory=/source/.git upload-pack",
            "/source",
            str(target),
        ],
        check=True,
        timeout=120,
    )
    print("cloned committed HEAD; original checkout and dirty files are unchanged", flush=True)


if __name__ == "__main__":
    main()
