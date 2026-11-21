#!/usr/bin/env python3
"""Exercise local OAuth omission with released readers and a current runtime.

Usage: python3 oauth-omission-compat.py V060_MSB FORK_MSB NEW_MSB FIRMWARE BUSYBOX SCRATCH
Provide a static BusyBox, the current runtime's firmware, and a private scratch
directory under an owner-controlled parent. The fork binary must be able to load
its own firmware. Requires Linux KVM; uses no network services or image pulls.
"""

import hashlib
import io
import json
import os
import platform
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


IMAGE = "docker.io/library/msb-oauth-omission-fixture:local"
MARKER = {"oauth_token_response_omission_v1": True}
UPGRADE = "does not support OAuth token response field omission; upgrade msb"


def run(binary, env, *args, reject=None):
    result = subprocess.run(
        [binary, *map(str, args)], env=env, text=True, capture_output=True, timeout=90
    )
    if reject is None:
        assert result.returncode == 0, result
    else:
        assert result.returncode != 0 and reject in result.stderr, result
    return result.stdout


def environment(home, binary, firmware=None):
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "MSB_HOME": str(home / "msb"),
        "MSB_BACKEND": "local",
        "MSB_PATH": str(binary),
    }
    if firmware is not None:
        env["MSB_LIBKRUNFW_PATH"] = str(firmware)
    return env


def saved_row(env, name):
    with sqlite3.connect(Path(env["MSB_HOME"]) / "db/msb.db") as db:
        return db.execute("SELECT * FROM sandbox WHERE name = ?", (name,)).fetchone()


def saved_policy(env, name):
    with sqlite3.connect(Path(env["MSB_HOME"]) / "db/msb.db") as db:
        desired, active = db.execute(
            "SELECT config, active_config FROM sandbox WHERE name = ?", (name,)
        ).fetchone()
    return (
        json.loads(desired)["network"],
        json.loads(active)["network"] if active is not None else None,
    )


def latest_run(env, name):
    with sqlite3.connect(Path(env["MSB_HOME"]) / "db/msb.db") as db:
        run = db.execute(
            "SELECT run.* FROM run JOIN sandbox ON run.sandbox_id = sandbox.id "
            "WHERE sandbox.name = ? ORDER BY run.id DESC LIMIT 1",
            (name,),
        ).fetchone()
    assert run is not None
    return run


def load_image(new, env, busybox, home):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    layer_bytes = io.BytesIO()
    with tarfile.open(fileobj=layer_bytes, mode="w") as layer:
        layer.add(busybox, "bin/busybox")
        shell = tarfile.TarInfo("bin/sh")
        shell.type = tarfile.SYMTYPE
        shell.linkname = "busybox"
        layer.addfile(shell)
        for directory in ("dev", "etc", "proc", "root", "run", "sys", "tmp", "var"):
            entry = tarfile.TarInfo(directory)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            layer.addfile(entry)
    layer = layer_bytes.getvalue()
    config = {
        "architecture": architecture,
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]},
    }
    manifest = [{"Config": "config.json", "RepoTags": [IMAGE], "Layers": ["layer.tar"]}]
    archive = home / "image.tar"
    with tarfile.open(archive, "w") as tar:
        for name, data in [
            ("config.json", json.dumps(config).encode()),
            ("manifest.json", json.dumps(manifest).encode()),
            ("layer.tar", layer),
        ]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    run(new, env, "image", "load", "--input", archive)


def check_current(new, old_runtimes, firmware, busybox, home):
    home.mkdir(mode=0o700)
    env = environment(home, new, firmware)
    assert json.loads(run(new, env, "__launch-protocol"))["oauth_token_response_omission"]
    load_image(new, env, busybox, home)
    grant = {
        "broker_endpoint": str(home / "synthetic.sock"),
        "grant_id": "synthetic",
        "token_endpoint": "https://provider.invalid/token",
        "inject_hosts": [{"exact": "provider.invalid"}],
        "require_grant_marker": False,
        "poll_secret_fields": [],
        "mint_endpoints": [],
        "access_token_field": "access_token",
        "refresh_token_field": "refresh_token",
        "access_env_var": "ACCESS",
        "refresh_env_var": "REFRESH",
        "access_sentinel": "$SYNTHETIC_ACCESS",
        "refresh_sentinel": "$SYNTHETIC_REFRESH",
    }
    ordinary = {
        "enabled": True,
        "policy": {"default_egress": "deny", "default_ingress": "deny", "rules": []},
        "tls": {"enabled": True},
        "secrets": {"oauth": [grant]},
    }
    protected = {
        **ordinary,
        "secrets": {"oauth": [dict(grant, omit_token_response_fields=["id_token"])]},
    }

    def check(name):
        desired, active = saved_policy(env, name)
        for network in (desired, active):
            assert network["enabled"] == MARKER, network
            assert network["secrets"]["oauth"] == protected["secrets"]["oauth"], network
        out = run(new, env, "exec", name, "--", "/bin/sh", "-c", 'printf "%s %s" "$ACCESS" "$REFRESH"')
        assert out == "$SYNTHETIC_ACCESS $SYNTHETIC_REFRESH", out
        return desired

    try:
        run(new, env, "create", IMAGE, "--pull", "never", "--no-net", "-m", "256M",
            "--name", "protected")
        run(new, env, "stop", "protected")
        # The CLI does not expose OAuth grant creation. Seed the saved policy
        # on the real sandbox; start and modify must write it back themselves.
        with sqlite3.connect(Path(env["MSB_HOME"]) / "db/msb.db") as db:
            raw, = db.execute("SELECT config FROM sandbox WHERE name = 'protected'").fetchone()
            config = json.loads(raw)
            config["network"].update({**protected, "enabled": MARKER})
            db.execute(
                "UPDATE sandbox SET config = ?, caller_config_overrides = NULL WHERE name = 'protected'",
                (json.dumps(config),),
            )
        for old in old_runtimes:
            run(new, {**env, "MSB_PATH": str(old)}, "start", "protected", reject=UPGRADE)
        run(new, env, "start", "protected")
        check("protected")
        run(new, env, "modify", "protected", "--label", "proof=current")
        current = json.loads(run(new, env, "inspect", "protected", "--format", "json"))
        assert current["config"]["labels"]["proof"] == "current", current
        desired = check("protected")
        before = saved_row(env, "protected"), latest_run(env, "protected")
        for old in old_runtimes:
            old_runtime = {**env, "MSB_PATH": str(old)}
            for flags in ((), ("--force",)):
                run(new, old_runtime, "restart", "protected", *flags, reject=UPGRADE)
                assert (saved_row(env, "protected"), latest_run(env, "protected")) == before
                check("protected")
        global_config = Path(env["MSB_HOME"]) / "config.json"
        assert not global_config.exists()
        global_config.write_text('{"version":1,"deployment_profile":"multi_tenant"}')
        try:
            for flags in ((), ("--force",)):
                run(new, env, "restart", "protected", *flags,
                    reject="token response field omission is not supported in the multi-tenant profile")
                assert (saved_row(env, "protected"), latest_run(env, "protected")) == before
        finally:
            global_config.unlink()
        check("protected")
        run(new, env, "restart", "protected")
        check("protected")
        # Fork explicitly authorizes inheriting this synthetic local grant.
        run(new, env, "fork", "protected", "--name", "child", "--dangerously-inherit-resources")
        check("child")
        run(new, env, "restart", "child")
        check("child")
    finally:
        for name in ("child", "protected"):
            if saved_row(env, name) is not None:
                run(new, env, "stop", name)

    print("current CLI preserved protected policy through live edit, restart, and fork; "
          "refused graceful and forced restart with both old runtimes and the "
          "effective multi-tenant profile without stopping", flush=True)
    return ordinary, {**ordinary, "enabled": desired["enabled"], "secrets": desired["secrets"]}


def check_old(old, home, ordinary, protected, firmware, busybox, *, v060):
    home.mkdir(mode=0o700)
    env = environment(home, old, firmware if v060 else None)
    run(old, env, "list")
    # Each reader initializes its own release's schema. Only the bind shape
    # differs; the network discriminator comes from a real current writer.
    root = home / "rootfs"
    image = {"Bind": str(root) if v060 else {"path": str(root)}}
    with sqlite3.connect(Path(env["MSB_HOME"]) / "db/msb.db") as db:
        for name, network in (("protected", protected), ("ordinary", ordinary)):
            config = {
                "name": name, "image": image, "network": network,
                "resources": {"cpus": 1, "memory_mib": 256},
            }
            db.execute(
                "INSERT INTO sandbox(name, status, config) VALUES (?, 'Stopped', ?)",
                (name, json.dumps(config)),
            )

    if v060:
        for directory in ("bin", "dev", "etc", "proc", "root", "run", "sys", "tmp", "var"):
            (root / directory).mkdir(parents=True)
        shutil.copy2(busybox, root / "bin/busybox")
        (root / "bin/sh").symlink_to("busybox")
        (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
        (root / "etc/group").write_text("root:x:0:\n")
        for name in ("protected", "ordinary"):
            (Path(env["MSB_HOME"]) / "sandboxes" / name).mkdir(parents=True)

    before = saved_row(env, "protected")
    run(old, env, "start", "protected", reject="expected a boolean")
    assert saved_row(env, "protected") == before

    if v060:
        # v0.6.0 has no configuration edit command.
        try:
            run(old, env, "start", "ordinary")
            out = run(old, env, "exec", "ordinary", "--", "/bin/sh", "-c", "printf ordinary")
            assert out == "ordinary", out
        finally:
            run(old, env, "stop", "ordinary")
        assert saved_row(env, "protected") == before
        print("v0.6.0 refused protected start; ordinary boot, exec and stop passed (no edit command)", flush=True)
    else:
        args = ("--next-start", "--label", "proof=old")
        run(old, env, "modify", "protected", *args, reject="expected a boolean")
        assert saved_row(env, "protected") == before
        run(old, env, "modify", "ordinary", *args)
        desired, _ = saved_policy(env, "ordinary")
        assert desired["enabled"] is True and desired["secrets"]["oauth"] == ordinary["secrets"]["oauth"]
        edited = json.loads(run(old, env, "inspect", "ordinary", "--format", "json"))
        assert edited["config"]["labels"]["proof"] == "old", edited
        print("v0.7.13-gitii.5 refused protected start and edit; ordinary edit retained its grant", flush=True)


def main(v060, fork, new, firmware, busybox, scratch):
    with TemporaryDirectory(prefix="mo-", dir=scratch) as directory:
        home = Path(directory)
        ordinary, protected = check_current(new, (v060, fork), firmware, busybox, home / "new")
        check_old(v060, home / "v060", ordinary, protected, firmware, busybox, v060=True)
        check_old(fork, home / "fork", ordinary, protected, firmware, busybox, v060=False)


if __name__ == "__main__":
    main(*(Path(arg).resolve(strict=True) for arg in sys.argv[1:]))
