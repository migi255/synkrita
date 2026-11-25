#!/usr/bin/env bash
# Run from a verified bundle. The caller verifies the detached release signature first.
set -euo pipefail
umask 022
target=${1:?Usage: bash deploy/operator/install-venv.sh /absolute/new/venv}
[[ "$target" = /* && ! -e "$target" && ! -L "$target" ]] || {
  echo 'Choose a new absolute venv path.' >&2
  exit 2
}
python=${SYNKRITA_PYTHON:-python3.13}
"$python" -c 'import platform, sys; sys.exit(0 if (platform.python_implementation(), sys.version_info[:2], platform.system(), platform.machine()) == ("CPython", (3, 13), "Linux", "x86_64") else "Install glibc Linux x86-64 CPython 3.13 with venv support.")'
sha256sum --strict --check SHA256SUMS > /dev/null
"$python" -m venv "$target"
"$target/bin/python" -I -m pip --isolated install --disable-pip-version-check --no-index --no-deps --require-hashes -r requirements.lock
"$target/bin/python" -I -m pip --isolated check
