#!/usr/bin/env python3
"""Exercise offline `msb self downgrade` against a pre-staged released v0.6.0.

Usage: python3 oauth-omission-downgrade.py NEW_MSB V060_MSB FORK_MSB FIRMWARE SCRATCH
Use checksum-verified release binaries and owner-controlled scratch outside /tmp.
The v0.7.13 fork reports the same version as the candidate, so only v0.6.0
can reach the downgrade workflow. No downloads, VM, or provider are needed.
"""

import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory


def run(binary, env, *args, reject=None):
    result = subprocess.run(
        [binary, *args], env=env, text=True, capture_output=True, timeout=40
    )
    if reject is None:
        assert result.returncode == 0, result
    else:
        assert result.returncode != 0 and reject in result.stderr, result
    return result


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def catalog_state(db_path):
    with sqlite3.connect(db_path) as db:
        rows = db.execute("SELECT * FROM sandbox ORDER BY id").fetchall()
        migrations = db.execute("SELECT * FROM seaql_migrations ORDER BY version").fetchall()
    return rows, migrations


def check(new, v060, fork, firmware, scratch, protected_column):
    with TemporaryDirectory(dir=scratch, prefix="modown-") as directory:
        home = Path(directory)
        base = home / "msb"
        env = {"PATH": os.defpath, "HOME": directory, "MSB_HOME": str(base), "MSB_BACKEND": "local"}
        installed = base / "bin/msb"
        library = base / "lib/libkrunfw.so.5"
        public = home / ".local/bin/msb"
        for path in (installed, library, public):
            path.parent.mkdir(parents=True, exist_ok=True)
        installed.symlink_to(new)
        library.write_bytes(b"synthetic installed-library sentinel")
        public.symlink_to(installed)

        run(installed, env, "sandbox", "list")
        db_path = base / "db/msb.db"
        historical = (
            Path(__file__).resolve().parents[3] / "sdk/rust/lib/db/fixtures/bind-config-0.6.0.json"
        ).read_text().rstrip()
        grant = {
            "broker_endpoint": str(home / "unused.sock"),
            "grant_id": "synthetic",
            "token_endpoint": "https://provider.invalid/token",
            "inject_hosts": [{"exact": "provider.invalid"}],
            "access_token_field": "access_token",
            "refresh_token_field": "refresh_token",
            "access_env_var": "ACCESS",
            "refresh_env_var": "REFRESH",
            "access_sentinel": "synthetic-access",
            "refresh_sentinel": "synthetic-refresh",
            "omit_token_response_fields": ["id_token"],
        }
        protected = json.dumps({
            "name": "protected",
            "image": {"Bind": {"path": str(home)}},
            "network": {
                "enabled": {"oauth_token_response_omission_v1": True},
                "secrets": {"oauth": [grant]},
            },
        })
        with sqlite3.connect(db_path) as db:
            db.execute(
                "INSERT INTO sandbox(id, name, status, config, active_config) "
                "VALUES (1, 'legacy-bind', 'Stopped', ?, ?)",
                (historical, historical),
            )
            if protected_column:
                ordinary = json.dumps({"name": "protected", "image": {"Bind": {"path": str(home)}}})
                desired, active = (
                    (protected, ordinary) if protected_column == "config" else (ordinary, protected)
                )
                db.execute(
                    "INSERT INTO sandbox(id, name, status, config, active_config) "
                    "VALUES (2, 'protected', 'Stopped', ?, ?)",
                    (desired, active),
                )

        operation = base / "db/self-downgrade/fixture"
        staged = operation / "target"
        (staged / "bin").mkdir(parents=True)
        (staged / "lib").mkdir()
        (operation / "recovery").mkdir()
        shutil.copy2(v060, staged / "bin/msb")
        shutil.copy2(firmware, staged / "lib/libkrunfw.so.5")
        (operation / "journal.json").write_text(json.dumps({
            "format_version": 1,
            "operation_id": "fixture",
            "source_version": "0.7.13",
            "target_version": "0.6.0",
            "phase": "target_staged",
            "target_dir": str(staged),
            "recovery_dir": str(operation / "recovery"),
            "backup_path": None,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }))

        def install_state():
            return [(path.lstat().st_ino, path.lstat().st_mode, digest(path))
                    for path in (installed, library, public)]

        before = catalog_state(db_path)
        install_before = install_state()
        assert "0.7.13" in run(fork, env, "--version").stdout
        run(installed, env, "self", "downgrade", "0.7.13", "--yes", reject="is not older")
        assert catalog_state(db_path) == before and install_state() == install_before

        if protected_column:
            run(installed, env, "self", "downgrade", "0.6.0", "--yes",
                reject=f"sandbox 2 {protected_column} requires OAuth token response field omission")
            assert catalog_state(db_path) == before
            assert install_state() == install_before
            assert not operation.exists()
            assert not list((base / "db").glob("*.bak*"))
            print(f"v0.6.0 downgrade refused {protected_column} before catalog/installation changes")
        else:
            run(installed, env, "self", "downgrade", "0.6.0", "--yes")
            assert installed.is_file() and not installed.is_symlink()
            assert digest(installed) == digest(v060)
            assert digest(library) == digest(firmware)
            run(installed, env, "list")
            with sqlite3.connect(db_path) as db:
                raw, = db.execute("SELECT config FROM sandbox WHERE id = 1").fetchone()
                assert json.loads(raw) == json.loads(historical), raw
                assert all(row[1] != "active_config" for row in db.execute("PRAGMA table_info(sandbox)"))
            print("ordinary-only downgrade installed released v0.6.0 and preserved the historical row")


if __name__ == "__main__":
    arguments = tuple(Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    for column in ("config", "active_config", None):
        check(*arguments, column)
