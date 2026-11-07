"""Exercise the kernel-cache action against the selected firmware source."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/cache-libkrunfw-kernel/action.yml"


def resolve_script():
    lines = ACTION.read_text().splitlines()
    start = lines.index("      run: |") + 1
    body = []
    for line in lines[start:]:
        if line and not line.startswith("        "):
            break
        body.append(line[8:])
    return "\n".join(body)


class KernelSourceTests(unittest.TestCase):
    def resolve(self, makefile):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vendor = root / "vendor/libkrunfw"
            vendor.mkdir(parents=True)
            (vendor / "Makefile").write_text(makefile)
            output = root / "output"
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", resolve_script()],
                cwd=root,
                env={**os.environ, "GITHUB_OUTPUT": str(output), "GITHUB_ACTION_PATH": str(ACTION.parent)},
                capture_output=True,
                text=True,
                check=False,
            )
            return result, output.read_text() if output.exists() else ""

    def test_selected_firmware_uses_verified_kernel_input(self):
        makefile = (ROOT / "vendor/libkrunfw/Makefile").read_text()
        result, output = self.resolve(makefile)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        fields = dict(line.split("=", 1) for line in output.splitlines())
        digests = dict(
            reversed(line.split())
            for line in (ROOT / ".github/kernel-tarballs.sha256").read_text().splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual(fields["sha256"], digests[Path(fields["path"]).name])
        self.assertEqual(fields["url"].rsplit("/", 1)[1], Path(fields["path"]).name)
        self.assertTrue(fields["cache-key"].endswith(fields["sha256"]))

    def test_unknown_kernel_cannot_use_unverified_cache(self):
        result, output = self.resolve(
            "KERNEL_VERSION = linux-0.0.0\n"
            "KERNEL_TARBALL = tarballs/$(KERNEL_VERSION).tar.gz\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Add the checksum for linux-0.0.0", result.stdout)
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
