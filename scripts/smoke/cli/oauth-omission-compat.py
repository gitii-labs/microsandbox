#!/usr/bin/env python3
"""Verify saved OAuth omission against an actual pre-omission CLI.

Usage: python3 oauth-omission-compat.py OLD_MSB NEW_MSB SCRATCH
SCRATCH must be a private path under an owner-controlled directory, not /tmp.
The CLIs must be able to load their own libkrunfw. No VM or provider is needed.
"""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory


def main(old, new, scratch):
    with TemporaryDirectory(prefix="oauth-omission-", dir=scratch) as directory:
        home = Path(directory)
        env = {
            "PATH": os.defpath,
            "HOME": str(home),
            "MSB_HOME": str(home / "msb"),
            "MSB_BACKEND": "local",
        }

        def run(binary, *args, reject=None):
            result = subprocess.run(
                [binary, *args], env=env, text=True, capture_output=True, timeout=15
            )
            if reject is None:
                assert result.returncode == 0, result
            else:
                assert result.returncode != 0 and reject in result.stderr, result
            return result.stdout

        assert not json.loads(run(old, "__launch-protocol")).get(
            "oauth_token_response_omission"
        )
        assert json.loads(run(new, "__launch-protocol"))["oauth_token_response_omission"]
        assert json.loads(run(new, "sandbox", "list", "--format", "json")) == []

        db_path = home / "msb/db/msb.db"
        grant = {
            "broker_endpoint": str(home / "synthetic.sock"),
            "grant_id": "synthetic",
            "token_endpoint": "https://provider.invalid/token",
            "inject_hosts": [{"Exact": "provider.invalid"}],
            "access_token_field": "access_token",
            "refresh_token_field": "refresh_token",
            "access_env_var": "ACCESS",
            "refresh_env_var": "REFRESH",
            "access_sentinel": "$ACCESS",
            "refresh_sentinel": "$REFRESH",
        }
        # Insert public/declarative input. The new CLI's normal modify path,
        # not the test, must write the protected durable representation.
        with sqlite3.connect(db_path) as db:
            for name, options in [
                ("protected", dict(grant, omit_token_response_fields=["id_token"])),
                ("ordinary", grant),
            ]:
                config = {
                    "name": name,
                    "image": {"Bind": {"path": str(home)}},
                    "network": {"tls": {"enabled": True}, "secrets": {"oauth": [options]}},
                }
                db.execute(
                    "INSERT INTO sandbox(name, status, config) VALUES (?, 'Stopped', ?)",
                    (name, json.dumps(config)),
                )

        def read_row(name):
            with sqlite3.connect(db_path) as db:
                return db.execute(
                    "SELECT status, config FROM sandbox WHERE name = ?", (name,)
                ).fetchone()

        run(new, "sandbox", "modify", "protected", "--next-start", "--label", "proof=new")
        protected_before = read_row("protected")
        saved = json.loads(protected_before[1])
        assert saved["network"]["secrets"]["oauth"][0]["token_response_omission_v1"][
            "omit_token_response_fields"
        ] == ["id_token"], saved

        run(
            old,
            "sandbox", "modify", "protected", "--next-start", "--label", "proof=old",
            reject="missing field",
        )
        run(old, "sandbox", "start", "protected", reject="missing field")
        assert read_row("protected") == protected_before

        run(old, "sandbox", "modify", "ordinary", "--next-start", "--label", "proof=old")
        ordinary = json.loads(read_row("ordinary")[1])
        assert ordinary["labels"]["proof"] == "old"
        ordinary = ordinary["network"]["secrets"]["oauth"][0]
        assert ordinary["grant_id"] == "synthetic"
        assert "token_response_omission_v1" not in ordinary

        run(new, "sandbox", "modify", "protected", "--next-start", "--label", "proof=new-again")
        after = json.loads(read_row("protected")[1])
        assert after["labels"]["proof"] == "new-again"
        assert after["network"]["secrets"] == saved["network"]["secrets"]
        print("old CLI refused protected edit/start; ordinary edit and protected round-trip passed")


if __name__ == "__main__":
    main(*(Path(arg).resolve(strict=True) for arg in sys.argv[1:]))
