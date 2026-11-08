"""Check Devbox's bindgen argument expansion in a project path containing spaces."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


root = Path(__file__).resolve().parents[3]
declaration = json.loads((root / "devbox.json").read_text())["env"]["BINDGEN_EXTRA_CLANG_ARGS"]
resources = Path(os.environ["LIBCLANG_PATH"]) / "clang" / "23"
assert (resources / "include" / "stdarg.h").is_file(), resources

with tempfile.TemporaryDirectory(prefix="libclang project with spaces ") as directory:
    fixture = Path(directory)
    # Only the environment declaration is under test here. The real selected
    # Ruby, GCC, libclang and resource headers remain the probe's subjects.
    (fixture / "devbox.json").write_text(json.dumps({
        "packages": {},
        "env": {"BINDGEN_EXTRA_CLANG_ARGS": declaration},
    }))
    shell = subprocess.check_output([
        "devbox", "shellenv", "--config", str(fixture), "--init-hook=false",
    ], text=True)
    raw = subprocess.check_output(["bash", "-c", shell + "\nenv -0"])
    expanded = dict(
        os.fsdecode(item).split("=", 1)
        for item in raw.split(b"\0") if b"=" in item
    )
    resource_path = fixture / ".devbox/nix/profile/default/lib/clang/23"
    arguments = shlex.split(expanded["BINDGEN_EXTRA_CLANG_ARGS"])
    assert arguments == [f"-resource-dir={resource_path}"], arguments
    assert '"' in expanded["BINDGEN_EXTRA_CLANG_ARGS"], expanded["BINDGEN_EXTRA_CLANG_ARGS"]
    resource_path.parent.mkdir(parents=True, exist_ok=True)
    resource_path.symlink_to(resources.resolve(), target_is_directory=True)
    # An empty fixture does not provision packages; retain the already selected
    # environment for the actual native header parse, changing only this flag.
    probe_env = dict(os.environ, BINDGEN_EXTRA_CLANG_ARGS=expanded["BINDGEN_EXTRA_CLANG_ARGS"])
    print(f"Devbox expanded argument: {expanded['BINDGEN_EXTRA_CLANG_ARGS']}", flush=True)
    subprocess.run([
        sys.executable, str(Path(__file__).with_name("check-libclang.py")),
    ], env=probe_env, check=True)
    print("Spaced resource path: one bindgen argument; actual C/Ruby header parse passed")
