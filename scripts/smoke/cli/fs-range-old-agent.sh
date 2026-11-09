#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
home="$(mktemp -d /tmp/msb-range-old.XXXXXX)"
export MSB_HOME="$home"
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -f "$home/started" ]]; then
    "$home/bin/msb" stop range-old --quiet || status=1
    "$home/bin/msb" remove range-old --quiet || status=1
  fi
  rm -rf "$home"
  exit "$status"
}
trap cleanup EXIT

asset=microsandbox-runtime-linux-amd64.tar.gz
curl --fail --location --output "$home/$asset" \
  "https://github.com/gitii-labs/microsandbox/releases/download/v0.7.6-gitii.13/$asset"
echo "70bdc13888706c33161aa4478fc1b14baad2d199bce6e3e083db22ef72eee1c2  $home/$asset" | sha256sum --check
tar -xzf "$home/$asset" -C "$home"
test "$(cat "$home/distributed-runtime.commit")" = f22ae9c1e5a4a9b2c6495114d4d9b944324d477e
export MSB_PATH="$home/bin/msb"
export MSB_LIBKRUNFW_PATH="$home/lib/libkrunfw.so"
export LD_LIBRARY_PATH="$home/lib"
"$home/bin/msb" create mirror.gcr.io/library/alpine:latest --name range-old --memory 256M --root-disk 512M --quiet
touch "$home/started"
python3 - "$home" "$root" <<'PY'
from pathlib import Path
import subprocess
import sys

home, root = map(Path, sys.argv[1:])
sockets = [path for path in (home / "run/agent").glob("*.sock") if not path.name.endswith(".control.sock")]
assert len(sockets) == 1, sockets
subprocess.run([sys.executable, str(root / "scripts/smoke/cli/fs_range_old_agent.py"), str(sockets[0])], check=True)
PY
