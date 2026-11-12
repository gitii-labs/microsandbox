#!/usr/bin/env python3
"""Inventory and native-tool output validation; no substitute native libraries."""

from __future__ import annotations

import io
import os
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.ci.verify_runtime_archive import (
    check_darwin_paths,
    extract_archive,
    homebrew_install_name_shortfall,
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

    def test_cache_paths_stay_job_local_without_run_identity_in_fingerprint(
        self,
    ) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github/workflows/runtime-release.yml"
        ).read_text()
        build = workflow.split("  build:\n", 1)[1].split("  release:\n", 1)[0]
        script = build.split(
            "- name: Prepare job-local toolchain paths\n        run: |\n", 1
        )[1].split("\n      - uses:", 1)[0]
        script = script.replace("${{ matrix.os }}", "darwin").replace(
            "${{ matrix.arch }}", "arm64"
        )
        script = "\n".join(line[10:] for line in script.splitlines())
        environments = []
        for run_id, attempt in (("100", "1"), ("200", "2")):
            output = self.root / f"env-{run_id}"
            subprocess.run(
                ["bash", "-euc", script],
                check=True,
                env={
                    **os.environ,
                    "RUNNER_TEMP": str(self.root),
                    "GITHUB_ENV": str(output),
                    "GITHUB_RUN_ID": run_id,
                    "GITHUB_RUN_ATTEMPT": attempt,
                },
            )
            environments.append(
                dict(line.split("=", 1) for line in output.read_text().splitlines())
            )
        self.assertEqual(environments[0], environments[1])
        self.assertEqual(
            environments[0]["CARGO_HOME"], str(self.root / "runtime-cargo-darwin-arm64")
        )
        self.assertEqual(
            environments[0]["RUSTUP_HOME"],
            str(self.root / "runtime-rustup-darwin-arm64"),
        )
        self.assertIn("add-rust-environment-hash-key: true", build)
        self.assertIn("env-vars: MACOSX_DEPLOYMENT_TARGET LIBKRUNFW_", build)
        self.assertIn("toolchain: ${{ env.RUST_TOOLCHAIN }}", build)
        self.assertIn("cache-bin: false", build)

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

    @staticmethod
    def dylib(identity: str | None, padding: int, zerofill_offset: int | None = None) -> bytes:
        """A Mach-O header with an optional install name and __text after padding."""
        identity_command = b""
        if identity is not None:
            name = identity.encode() + b"\0"
            name += b"\0" * (-len(name) % 8)
            identity_command = struct.pack("<6I", 0xD, 24 + len(name), 24, 0, 0, 0) + name
        # (name, size, section type); a zero-fill section has no file bytes.
        sections = [(b"__text", 8, 0)]
        if zerofill_offset is not None:
            sections.append((b"__bss", 8, 0x1))
        segment_size = 72 + 80 * len(sections)
        commands_size = len(identity_command) + segment_size
        text_offset = 32 + commands_size + padding
        segment = struct.pack(
            "<2I16s4Q4I", 0x19, segment_size, b"__TEXT", 0, 0, 0, 0, 0, 0, len(sections), 0
        )
        for section_name, size, section_type in sections:
            offset = zerofill_offset if section_type else text_offset
            segment += struct.pack(
                "<16s16sQQ8I", section_name, b"__TEXT", 0, size, offset, 0, 0, 0,
                section_type, 0, 0, 0,
            )
        command_count = 2 if identity is not None else 1
        header = struct.pack("<8I", 0xFEEDFACF, 0, 0, 6, command_count, commands_size, 0, 0)
        return header + identity_command + segment + b"\0" * (padding + 8)

    def test_darwin_install_name_needs_room_for_the_homebrew_path(self) -> None:
        # The published v0.7.13-gitii.3 firmware: a 48-byte identity command and
        # 32 spare bytes, where Homebrew's name needs a 104-byte command.
        self.assertEqual(
            homebrew_install_name_shortfall(self.dylib("libkrunfw.5.dylib", 32)), 24
        )
        self.assertEqual(
            homebrew_install_name_shortfall(self.dylib("libkrunfw.5.dylib", 56)), 0
        )

    def test_darwin_long_install_name_shrinks_into_the_homebrew_path(self) -> None:
        # Like the published FFI: no spare bytes, but its 168-byte builder-path
        # command shrinks to a 112-byte Homebrew command.
        builder = "/builder/work/target/release/deps/" + "x" * 80 + "/libmicrosandbox_go_ffi.dylib"
        self.assertEqual(homebrew_install_name_shortfall(self.dylib(builder, 0)), -56)

    def test_darwin_executable_has_no_install_name_to_fit(self) -> None:
        self.assertEqual(homebrew_install_name_shortfall(self.dylib(None, 0)), 0)

    def test_darwin_zerofill_section_does_not_end_the_header(self) -> None:
        # A zero-fill section's offset lies inside the header; ruby-macho ignores it.
        image = self.dylib("libkrunfw.5.dylib", 56, zerofill_offset=32)
        self.assertEqual(homebrew_install_name_shortfall(image), 0)

    def test_darwin_system_and_relative_paths(self) -> None:
        check_darwin_paths(
            Path("msb"),
            "msb:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t@rpath/libkrunfw.5.dylib (compatibility version 0.0.0)\n",
            "    minos 26.0\n    path @executable_path/../lib (offset 12)\n",
            "26.0",
            "msb:\n",
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
                check_darwin_paths(
                    Path("msb"), dependencies, commands, "26.0", "msb:\n"
                )

    def test_darwin_absolute_dylib_identity_is_not_a_dependency(self) -> None:
        path = Path("libmicrosandbox_go_ffi.dylib")
        identity = "/Users/runner/work/microsandbox/target/release/deps/libmicrosandbox_go_ffi.dylib"
        check_darwin_paths(
            path,
            f"{path}:\n\t{identity} (compatibility version 0.0.0, current version 0.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n",
            f"Load command 0\n          cmd LC_ID_DYLIB\n      cmdsize 128\n         name {identity} (offset 24)\n    minos 26.0\n",
            "26.0",
            f"{path}:\n{identity}\n",
        )

    def test_darwin_dylib_identity_does_not_hide_bad_dependency(self) -> None:
        path = Path("libmicrosandbox_go_ffi.dylib")
        identity = "/Users/runner/work/target/release/libmicrosandbox_go_ffi.dylib"
        with self.assertRaisesRegex(ValueError, "nonportable Mach-O dependency"):
            check_darwin_paths(
                path,
                f"{path}:\n\t{identity} (compatibility version 0.0.0)\n\t/Users/runner/build/libdependency.dylib (compatibility version 1.0.0)\n",
                "    minos 26.0\n",
                "26.0",
                f"{path}:\n{identity}\n",
            )

    def test_darwin_requires_proven_identity_before_skipping_first_entry(self) -> None:
        path = Path("libmicrosandbox_go_ffi.dylib")
        for install_names in (f"{path}:\n", f"{path}:\n/some/other/identity.dylib\n"):
            with (
                self.subTest(install_names=install_names),
                self.assertRaises(ValueError),
            ):
                check_darwin_paths(
                    path,
                    f"{path}:\n\t/Users/runner/build/libdependency.dylib (compatibility version 1.0.0)\n",
                    "    minos 26.0\n",
                    "26.0",
                    install_names,
                )

    def test_darwin_executable_first_dependency_is_not_an_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "nonportable Mach-O dependency"):
            check_darwin_paths(
                Path("msb"),
                "msb:\n\t/Users/runner/build/libdependency.dylib (compatibility version 1.0.0)\n",
                "    minos 26.0\n",
                "26.0",
                "msb:\n",
            )


if __name__ == "__main__":
    unittest.main()
