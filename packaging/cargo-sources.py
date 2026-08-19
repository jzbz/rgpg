#!/usr/bin/env python3
"""Generate cargo-sources.json for the Flatpak build from Cargo.lock.

Flathub builds without network access, so every crate has to be declared as a
source up front. Cargo.lock already records the sha256 of each .crate file, so
this needs nothing but the lockfile — no downloads, and nothing to trust beyond
what cargo already verifies on every build.

    python3 packaging/cargo-sources.py > packaging/cargo-sources.json
"""

import json
import sys
import tomllib
from pathlib import Path

CRATES_IO = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
# Where the build expects the vendored registry to appear.
VENDOR = "cargo/vendor"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    lock = tomllib.loads((root / "Cargo.lock").read_text())

    sources = []
    vendored = {}
    for package in lock["package"]:
        checksum = package.get("checksum")
        if checksum is None:
            # No checksum means a path dependency: the workspace's own crates,
            # which arrive with the git source rather than from the registry.
            continue
        name, version = package["name"], package["version"]
        sources.append(
            {
                "type": "archive",
                "archive-type": "tar-gzip",
                "url": CRATES_IO.format(name=name, version=version),
                "sha256": checksum,
                "dest": f"{VENDOR}/{name}-{version}",
            }
        )
        vendored[f"{name}-{version}"] = {"package": checksum, "files": {}}

    # cargo needs a .cargo-checksum.json beside each vendored crate, and a
    # config telling it to use the directory instead of the network.
    for entry, meta in vendored.items():
        sources.append(
            {
                "type": "inline",
                "contents": json.dumps(meta),
                "dest": f"{VENDOR}/{entry}",
                "dest-filename": ".cargo-checksum.json",
            }
        )

    config = (
        "[source.crates-io]\n"
        'replace-with = "vendored-sources"\n\n'
        "[source.vendored-sources]\n"
        f'directory = "{VENDOR}"\n'
    )
    sources.append(
        {
            "type": "inline",
            "contents": config,
            "dest": "cargo",
            "dest-filename": "config.toml",
        }
    )

    json.dump(sources, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
