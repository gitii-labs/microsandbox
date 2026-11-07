"""Verify complete project license and notice text in an actual built wheel."""

import argparse
from email import message_from_bytes
from pathlib import Path
from zipfile import ZipFile


def check_wheel(wheel: Path) -> None:
    sdk = Path(__file__).resolve().parents[1]
    repository = sdk.parents[1]
    license_bytes = (repository / "LICENSE").read_bytes()
    assert (sdk / "LICENSE").read_bytes() == license_bytes, "SDK license differs from root LICENSE"
    assert b"END OF TERMS AND CONDITIONS" in license_bytes
    assert b"Copyright" in license_bytes

    with ZipFile(wheel) as archive:
        metadata_paths = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        assert len(metadata_paths) == 1, "Wheel must contain exactly one package METADATA file"
        metadata = message_from_bytes(archive.read(metadata_paths[0]))
        assert metadata["Name"] == "microsandbox", "Wheel is not the microsandbox package"

        # A license identifier alone does not distribute the required full text.
        license_text = " ".join(license_bytes.decode().split())
        metadata_license = " ".join((metadata["License"] or "").split())
        matching_files = [
            name
            for name in archive.namelist()
            if Path(name).name.upper() == "LICENSE" and archive.read(name) == license_bytes
        ]
        assert matching_files or license_text in metadata_license, (
            "Wheel contains neither complete LICENSE bytes nor complete license metadata"
        )

        # Only an existing repository NOTICE creates a project-notice requirement.
        notice = repository / "NOTICE"
        if notice.exists():
            notice_bytes = notice.read_bytes()
            assert any(
                Path(name).name.upper() == "NOTICE" and archive.read(name) == notice_bytes
                for name in archive.namelist()
            ), "Wheel does not include the repository NOTICE"

    print(f"Verified complete project license and applicable notice in {wheel}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, help="Actual built microsandbox wheel")
    check_wheel(parser.parse_args().wheel)
