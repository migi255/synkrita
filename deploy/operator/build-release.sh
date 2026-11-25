#!/usr/bin/env bash
# Build on the target OS, architecture and Python minor version.
set -euo pipefail
umask 077
root=$(git rev-parse --show-toplevel)
cd "$root"
test -z "$(git status --porcelain --untracked-files=normal)" || { echo 'Use a clean, reviewed release checkout.' >&2; exit 1; }
out=${1:?Supply a new absolute output directory outside the checkout}
[[ "$out" = /* && "$out" != "$root" && "$out" != "$root/"* ]] || exit 2
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/source" "$tmp/release/wheels"
commit=$(git rev-parse HEAD)
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
# No working-tree data, DBs, captures, dotfiles, configs or build cache.
git ls-tree -r --name-only "$commit" -- src/synkrita |
  while IFS= read -r file; do
    [[ "$file" =~ ^src/synkrita/([a-zA-Z0-9_]+/)*[a-zA-Z0-9_]+\.py$ ]] || continue
    mkdir -p "$tmp/source/$(dirname "$file")"
    git show "$commit:$file" > "$tmp/source/$file"
  done
license_files=(LICENSE NOTICE THIRD_PARTY_NOTICES.md third-party/LICENSES.txt)
git archive "$commit" pyproject.toml README.md "${license_files[@]}" | tar -x -C "$tmp/source"
python -c 'import platform, sys; sys.exit(0 if (platform.python_implementation(), sys.version_info[:2], platform.system(), platform.machine()) == ("CPython", (3, 13), "Linux", "x86_64") else "Use the qualified Linux x86-64 CPython 3.13 builder")'
python -m pip wheel --no-build-isolation --no-deps -w "$tmp/release/wheels" "$tmp/source"
python -m pip download --no-deps --require-hashes --only-binary=:all: -d "$tmp/release/wheels" -r deploy/operator/linux-cp313.lock
git archive "$commit" RELEASE-PROVENANCE.json SECURITY.md README.md CONTRIBUTING.md "${license_files[@]}" deploy/operator/{build-release.sh,install-venv.sh,render.py,preflight.py,oauth.example.json,linux-cp313.lock} \
  deploy/remote-mcp-staging/{nginx.conf.template,synkrita-staging.service} \
  scripts/{check,seed}_remote_mcp_staging.py scripts/cold_start_remote_mcp.py \
  docs/{CLAUDE,CODEX,CHATGPT}_QUICKSTART.md \
  docs/{ARCHITECTURE,SELF_HOSTING,REMOTE_MCP_QUALIFICATION}.md \
  docs/INNER_PAYLOAD_CONTRACTS.md \
  examples/{sources.toml,metadata-sources.toml,empty-arguments.json} |
  tar -x -C "$tmp/release"
(cd "$tmp/release" && sha256sum wheels/*.whl | awk '{print "./" $2 " --hash=sha256:" $1}' > requirements.lock)
printf '%s\n' "$commit" > "$tmp/release/REVISION"
(cd "$tmp/release" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
mkdir -m 0700 "$out"
cp -R "$tmp/release/." "$out/"
