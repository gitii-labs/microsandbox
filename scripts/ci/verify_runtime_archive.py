#!/usr/bin/env python3
"""Verify the exact fork runtime archive on its native build runner."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import plistlib
import re
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path


def require(condition: bool, message: str) -> None:
    # Artifact validation: reject mismatched release bytes before publication.
    if not condition:
        raise ValueError(message)


def command(*args: str, env: dict[str, str] | None = None) -> str:
    print("+ " + " ".join(args), flush=True)
    command_env = {**(os.environ if env is None else env), "LC_ALL": "C"}
    result = subprocess.run(
        args, check=True, stdout=subprocess.PIPE, text=True, env=command_env
    )
    return result.stdout


def inventory(os_name: str, version: str, abi: str) -> tuple[str, str, dict[str, str]]:
    if os_name == "darwin":
        firmware = f"libkrunfw.{abi}.dylib"
        return firmware, "libmicrosandbox_go_ffi.dylib", {"libkrunfw.dylib": firmware}
    firmware = f"libkrunfw.so.{version}"
    return (
        firmware,
        "libmicrosandbox_go_ffi.so",
        {
            "libkrunfw.so": f"libkrunfw.so.{abi}",
            f"libkrunfw.so.{abi}": firmware,
        },
    )


def extract_archive(
    archive: Path,
    root: Path,
    firmware: str,
    ffi: str,
    links: dict[str, str],
    commit: str,
) -> None:
    files = {"bin/msb", f"lib/{firmware}", f"lib/{ffi}", "distributed-runtime.commit"}
    expected = files | {f"lib/{name}" for name in links} | {"bin", "lib"}
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)), "archive has duplicate paths")
        require(
            set(names) == expected, f"archive paths differ: {set(names) ^ expected}"
        )
        for member in members:
            if member.name in {"bin", "lib"}:
                require(member.isdir(), f"{member.name} must be a directory")
            elif member.name in files:
                require(
                    member.isfile() and member.size > 0,
                    f"{member.name} must be a nonempty file",
                )
                require(
                    not member.mode & 0o022,
                    f"{member.name} must not be group/world writable",
                )
                if member.name == "bin/msb":
                    require(bool(member.mode & 0o111), "bin/msb must be executable")
            else:
                require(member.issym(), f"{member.name} must be a symlink")
                require(
                    member.linkname == links[Path(member.name).name],
                    f"wrong symlink: {member.name}",
                )
        # The exact inventory above excludes traversal, hardlinks, symlink directories
        # and external symlink targets before extraction (also on Python 3.10).
        bundle.extractall(root, members=members)
    require(
        (root / "distributed-runtime.commit").read_text() == commit + "\n",
        "source commit mismatch",
    )


def check_linux(path: Path, arch: str) -> None:
    headers = command("readelf", "-h", "-l", "-d", "-W", str(path))
    machine = "Advanced Micro Devices X86-64" if arch == "amd64" else "AArch64"
    require(
        bool(re.search(rf"Machine:\s+{machine}\s*\n", headers)),
        f"wrong ELF architecture: {path}",
    )
    require("ELF64" in headers, f"expected ELF64: {path}")
    require("/nix/store/" not in headers, f"Nix loader/dependency path: {path}")
    for needed in re.findall(r"\(NEEDED\).*?\[([^]]+)\]", headers):
        require("/" not in needed, f"nonportable ELF dependency: {needed}")
    if path.name == "msb":
        loader = (
            "/lib64/ld-linux-x86-64.so.2"
            if arch == "amd64"
            else "/lib/ld-linux-aarch64.so.1"
        )
        require(
            f"Requesting program interpreter: {loader}]" in headers,
            f"wrong ELF loader: {path}",
        )


def check_darwin_paths(
    path: Path,
    dependencies: str,
    load_commands: str,
    deployment_target: str,
    install_names: str,
) -> None:
    require(
        "/nix/store/" not in dependencies + load_commands,
        f"Nix Mach-O load path: {path}",
    )
    # Apple otool -L includes a dylib's LC_ID_DYLIB before its dependencies.
    # Prove that entry with -D rather than treating a builder's own install name
    # as a runtime dependency, or blindly skipping an executable's first import.
    identities = [
        line.strip() for line in install_names.splitlines()[1:] if line.strip()
    ]
    require(
        len(identities) == (0 if path.name == "msb" else 1),
        f"unexpected dylib identity: {path}",
    )
    imports = [line.strip().split(" (", 1)[0] for line in dependencies.splitlines()[1:]]
    if identities:
        require(
            bool(imports) and imports[0] == identities[0],
            f"otool dylib identity mismatch: {path}",
        )
        imports = imports[1:]
    # Reject builder-specific dependencies/rpaths; the native load below also
    # proves that permitted relative/system paths actually resolve.
    for dependency in imports:
        require(
            dependency.startswith(
                (
                    "/usr/lib/",
                    "/System/Library/",
                    "@rpath/",
                    "@loader_path/",
                    "@executable_path/",
                )
            ),
            f"nonportable Mach-O dependency: {dependency}",
        )
    for rpath in re.findall(r"\bpath (.+) \(offset \d+\)", load_commands):
        require(
            rpath.startswith(
                ("@loader_path", "@executable_path", "/usr/lib/", "/System/Library/")
            ),
            f"nonportable Mach-O rpath: {rpath}",
        )
    require(
        bool(
            re.search(
                rf"\bminos {re.escape(deployment_target)}(?:\.0)?\s*\n", load_commands
            )
        ),
        f"wrong macOS deployment target: {path}",
    )


# Where Distributed's Homebrew formula installs the runtime's libraries.
# Homebrew rewrites each dylib's install name to this directory plus the
# basename of the existing name, and fails the installation when the rewritten
# load command does not fit before the first section.
HOMEBREW_LIBRARY_DIRECTORY = "/opt/homebrew/opt/distributed-node/libexec/runtime/lib"

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_ID_DYLIB = 0xD
MACH_HEADER_64_SIZE = 32
DYLIB_COMMAND_SIZE = 24


def homebrew_install_name_shortfall(image: bytes) -> int:
    """Bytes the header lacks for Homebrew's install name; 0 or less fits."""
    magic, _, _, _, command_count, commands_size, _, _ = struct.unpack_from(
        "<8I", image, 0
    )
    require(magic == MH_MAGIC_64, "expected a thin 64-bit Mach-O")
    offset = MACH_HEADER_64_SIZE
    identity_size = 0
    identity = ""
    first_section = len(image)
    for _ in range(command_count):
        kind, size = struct.unpack_from("<2I", image, offset)
        if kind == LC_ID_DYLIB:
            (name_offset,) = struct.unpack_from("<I", image, offset + 8)
            name = image[offset + name_offset : offset + size].split(b"\0", 1)[0]
            identity, identity_size = name.decode(), size
        if kind == LC_SEGMENT_64:
            (section_count,) = struct.unpack_from("<I", image, offset + 64)
            for index in range(section_count):
                section = offset + 72 + index * 80
                (section_size,) = struct.unpack_from("<Q", image, section + 40)
                (section_offset,) = struct.unpack_from("<I", image, section + 48)
                if section_size and section_offset:
                    first_section = min(first_section, section_offset)
        offset += size
    # Caller validation: an executable has no install name to rewrite.
    if not identity:
        return 0
    rewritten = f"{HOMEBREW_LIBRARY_DIRECTORY}/{identity.rsplit('/', 1)[-1]}"
    rewritten_size = (DYLIB_COMMAND_SIZE + len(rewritten.encode()) + 1 + 7) // 8 * 8
    room = first_section - (MACH_HEADER_64_SIZE + commands_size)
    return rewritten_size - identity_size - room


def check_darwin(path: Path, deployment_target: str) -> None:
    shortfall = homebrew_install_name_shortfall(path.read_bytes())
    require(
        shortfall <= 0,
        f"Mach-O header is {shortfall} bytes short of Homebrew's install name: {path}",
    )
    require(
        command("lipo", "-archs", str(path)).strip() == "arm64",
        f"expected ARM64 Mach-O: {path}",
    )
    check_darwin_paths(
        path,
        command("otool", "-L", str(path)),
        command("otool", "-l", str(path)),
        deployment_target,
        command("otool", "-D", str(path)),
    )


def check_versions(
    root: Path, ffi_name: str, firmware_name: str, version: str, abi: str
) -> None:
    home = root / "home"
    home.mkdir()
    child_env = {
        **os.environ,
        "HOME": str(home),
        "MSB_HOME": str(home / "microsandbox"),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_DATA_HOME": str(home / "data"),
    }
    require(
        command(str(root / "bin/msb"), "--version", env=child_env).strip()
        == f"msb {version}",
        "CLI version mismatch",
    )
    firmware = ctypes.CDLL(str(root / "lib" / firmware_name))
    firmware.krunfw_get_version.argtypes = []
    firmware.krunfw_get_version.restype = ctypes.c_int
    require(firmware.krunfw_get_version() == int(abi), "firmware ABI mismatch")
    ffi = ctypes.CDLL(str(root / "lib" / ffi_name))
    # sdk/go/native/microsandbox_go_ffi.h: caller-owned unsigned char buffer,
    # uintptr_t length; NULL means success, non-NULL is an owned error string.
    ffi.msb_version.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
    ffi.msb_version.restype = ctypes.c_void_p
    ffi.msb_free_string.argtypes = [ctypes.c_void_p]
    ffi.msb_free_string.restype = None
    buffer_size = 4096
    output = (ctypes.c_ubyte * buffer_size)()
    error = ffi.msb_version(output, len(output))
    if error:
        try:
            raise ValueError(f"FFI version failed: {ctypes.string_at(error).decode()}")
        finally:
            ffi.msb_free_string(error)
    actual = json.loads(bytes(output).split(b"\0", 1)[0])
    require(actual == {"version": version}, f"FFI version mismatch: {actual}")
    print(f"CLI/FFI version {version}; firmware ABI {abi}", flush=True)


def verify(args: argparse.Namespace) -> None:
    require(
        platform.system().lower() == args.os,
        "verification must run on the archive's native OS",
    )
    expected_machine = {
        "amd64": "x86_64",
        "arm64": "arm64" if args.os == "darwin" else "aarch64",
    }[args.arch]
    require(
        platform.machine() == expected_machine,
        "verification must run on the archive's native architecture",
    )
    firmware, ffi, links = inventory(args.os, args.firmware_version, args.firmware_abi)
    with tempfile.TemporaryDirectory(
        prefix="msb-runtime-verify-", dir=os.environ.get("RUNNER_TEMP")
    ) as directory:
        root = Path(directory)
        extract_archive(args.archive, root, firmware, ffi, links, args.commit)
        paths = [root / "bin/msb", root / "lib" / ffi, root / "lib" / firmware]
        for path in paths:
            if args.os == "linux":
                check_linux(path, args.arch)
            else:
                check_darwin(path, args.deployment_target)
            print(
                f"sha256 {hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}",
                flush=True,
            )
        if args.os == "darwin":
            command("codesign", "--verify", "--strict", "--verbose=2", str(paths[0]))
            entitlements = command(
                "codesign", "-d", "--entitlements", ":-", str(paths[0])
            )
            require(
                plistlib.loads(entitlements.encode()).get(
                    "com.apple.security.hypervisor"
                )
                is True,
                "msb requires the hypervisor entitlement",
            )
        else:
            symbols = command("objdump", "-T", *(str(path) for path in paths))
            versions = {
                tuple(map(int, item.split(".")))
                for item in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", symbols)
            }
            require(
                bool(versions) and max(versions) <= (2, 35),
                f"glibc floor exceeds 2.35: {sorted(versions)}",
            )
        check_versions(root, ffi, firmware, args.version, args.firmware_abi)
    print(
        f"Verified {args.archive}: {hashlib.sha256(args.archive.read_bytes()).hexdigest()}",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--os", choices=["linux", "darwin"], required=True)
    parser.add_argument("--arch", choices=["amd64", "arm64"], required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--firmware-version", required=True)
    parser.add_argument("--firmware-abi", required=True)
    parser.add_argument("--deployment-target", required=True)
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
