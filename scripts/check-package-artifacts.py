from __future__ import annotations

import argparse
from pathlib import Path
import tarfile
import zipfile

SCHEMAS = frozenset({
    "canon-document.schema.json", "context-pack.schema.json", "context-policy.schema.json",
    "evidence-event.schema.json", "evidence-record.schema.json", "retention-policy.schema.json",
    "vault.schema.json",
})


class PackageArtifactError(ValueError):
    pass


def archive_names(path: Path) -> set[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return {name.rsplit("/", 1)[-1] for name in archive.namelist()}
    with tarfile.open(path, "r:gz") as archive:
        return {name.rsplit("/", 1)[-1] for name in archive.getnames()}


def check(directory: Path) -> None:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise PackageArtifactError("expected exactly one wheel and sdist")
    for label, artifact in (("wheel", wheels[0]), ("sdist", sdists[0])):
        missing = SCHEMAS - archive_names(artifact)
        if missing:
            raise PackageArtifactError(f"{label} is missing schemas: {sorted(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("build_directory", type=Path)
    args = parser.parse_args()
    try:
        check(args.build_directory)
    except (OSError, PackageArtifactError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"package artifact check failed: {error}")
        return 1
    print("package artifacts valid: wheel and sdist contain seven schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
