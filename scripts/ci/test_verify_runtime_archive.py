#!/usr/bin/env python3
"""Inventory and native-tool output validation; no substitute native libraries."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.ci.verify_runtime_archive import (
    check_darwin_paths,
    extract_archive,
    inventory,
)

COMMIT = "a" * 40


class RuntimeArchiveTests(unittest.TestCase):
    def test_release_runner_matrix_keeps_linux_and_routes_darwin_to_mba(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github/workflows/runtime-release.yml"
        ).read_text()
        matrix = workflow.split("  build:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn(
            "- os: linux\n            arch: amd64\n            runner: ubuntu-22.04\n",
            matrix,
        )
        self.assertIn(
            "- os: linux\n            arch: arm64\n            runner: ubuntu-22.04-arm\n",
            matrix,
        )
        self.assertIn(
            "- os: darwin\n            arch: arm64\n            runner: [self-hosted, macOS, ARM64, air]\n",
            matrix,
        )
        self.assertEqual(matrix.count("runner:"), 3)
        self.assertIn('MACOSX_DEPLOYMENT_TARGET: "26.0"', workflow)
        self.assertIn("RUSTUP_HOME=$RUNNER_TEMP/", workflow)
        self.assertIn("CARGO_HOME=$RUNNER_TEMP/", workflow)
        self.assertIn("TMPDIR=$RUNNER_TEMP", workflow)
        self.assertLess(
            workflow.index("- name: Verify the packed native runtime"),
            workflow.index("name: runtime-${{ matrix.os }}-${{ matrix.arch }}"),
        )

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.archive = self.root / "runtime.tar.gz"
        self.firmware, self.ffi, self.links = inventory("linux", "5.6.1", "5")

    def pack(self, change: str = "") -> None:
        # These bytes test archive structure only. No native load is attempted;
        # the workflow verifies actual packed binaries separately on each runner.
        with tarfile.open(self.archive, "w:gz") as bundle:
            for name in ("bin", "lib"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                bundle.addfile(info)
            for name in (
                "bin/msb",
                f"lib/{self.firmware}",
                f"lib/{self.ffi}",
                "distributed-runtime.commit",
            ):
                info = tarfile.TarInfo(name)
                data = (
                    (COMMIT + "\n").encode()
                    if name == "distributed-runtime.commit"
                    else b"inventory-only"
                )
                info.size = len(data)
                info.mode = 0o755 if name == "bin/msb" else 0o644
                if change == "mode" and name == "bin/msb":
                    info.mode = 0o644
                if change == "empty" and name.endswith(self.ffi):
                    info.size = 0
                    data = b""
                bundle.addfile(info, io.BytesIO(data))
            for name, target in self.links.items():
                info = tarfile.TarInfo(f"lib/{name}")
                info.type = tarfile.SYMTYPE
                info.linkname = "/outside" if change == "link" else target
                bundle.addfile(info)
            if change in {"duplicate", "traversal", "extra"}:
                name = {
                    "duplicate": "bin/msb",
                    "traversal": "../escape",
                    "extra": "extra",
                }[change]
                bundle.addfile(tarfile.TarInfo(name))

    def extract(self, commit: str = COMMIT) -> None:
        extract_archive(
            self.archive,
            self.root / "extracted",
            self.firmware,
            self.ffi,
            self.links,
            commit,
        )

    def test_exact_inventory_extracts_marker_mode_and_symlink_chain(self) -> None:
        self.pack()
        self.extract()
        root = self.root / "extracted"
        self.assertEqual(
            (root / "distributed-runtime.commit").read_text(), COMMIT + "\n"
        )
        self.assertTrue((root / "bin/msb").stat().st_mode & 0o111)
        self.assertEqual(
            (root / "lib/libkrunfw.so").resolve(), root / "lib" / self.firmware
        )

    def test_rejects_invalid_inventory_before_extraction(self) -> None:
        for change in ("mode", "empty", "link", "duplicate", "traversal", "extra"):
            with self.subTest(change=change):
                self.pack(change)
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse((self.root / "extracted").exists())

    def test_rejects_wrong_commit(self) -> None:
        self.pack()
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            self.extract("b" * 40)

    def test_darwin_inventory(self) -> None:
        self.assertEqual(
            inventory("darwin", "5.6.1", "5"),
            (
                "libkrunfw.5.dylib",
                "libmicrosandbox_go_ffi.dylib",
                {"libkrunfw.dylib": "libkrunfw.5.dylib"},
            ),
        )
        self.firmware, self.ffi, self.links = inventory("darwin", "5.6.1", "5")
        self.pack()
        self.extract()
        self.assertEqual(
            (self.root / "extracted/lib/libkrunfw.dylib").resolve(),
            self.root / "extracted/lib/libkrunfw.5.dylib",
        )

    def test_darwin_system_and_relative_paths(self) -> None:
        check_darwin_paths(
            Path("msb"),
            "msb:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t@rpath/libkrunfw.5.dylib (compatibility version 0.0.0)\n",
            "    minos 26.0\n    path @executable_path/../lib (offset 12)\n",
            "26.0",
        )

    def test_darwin_rejects_builder_dependencies_rpaths_and_old_floor(self) -> None:
        for dependencies, commands in (
            (
                "msb:\n\t/nix/store/id/lib.dylib (compatibility version 1.0.0)\n",
                "    minos 26.0\n",
            ),
            (
                "msb:\n\t/opt/homebrew/lib/lib.dylib (compatibility version 1.0.0)\n",
                "    minos 26.0\n",
            ),
            ("msb:\n", "    minos 26.0\n    path /Users/runner/build (offset 12)\n"),
            ("msb:\n", "    minos 11.0\n"),
        ):
            with (
                self.subTest(dependencies=dependencies, commands=commands),
                self.assertRaises(ValueError),
            ):
                check_darwin_paths(Path("msb"), dependencies, commands, "26.0")


if __name__ == "__main__":
    unittest.main()
