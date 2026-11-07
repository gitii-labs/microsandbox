"""Keep Python package licensing tied to the authoritative repository files."""

from pathlib import Path


def test_python_metadata_uses_complete_repository_license():
    sdk = Path(__file__).resolve().parents[1]
    repository = sdk.parents[1]
    metadata = (sdk / "pyproject.toml").read_text()

    assert 'license = { file = "LICENSE" }' in metadata.splitlines()
    license_bytes = (sdk / "LICENSE").read_bytes()
    assert license_bytes == (repository / "LICENSE").read_bytes()
    assert b"END OF TERMS AND CONDITIONS" in license_bytes
    assert b"Copyright" in license_bytes
