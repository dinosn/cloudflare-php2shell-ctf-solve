#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected_controller="17d1cf9dde5b85adbd294d8df3a27b3f850567b9cbbe3bf3e77734d95cdab027"
actual_controller="$(shasum -a 256 evidence/controller.accepted.py | awk '{print $1}')"
if [[ "$actual_controller" != "$expected_controller" ]]; then
  printf 'accepted controller hash mismatch\n' >&2
  exit 1
fi

export PYTHONPATH="$repo_root/src:$repo_root/src/stock:$repo_root/src/native"
export PYTHONDONTWRITEBYTECODE=1

python3 -B - <<'PY'
from pathlib import Path

for path in sorted(Path("src").rglob("*.py")):
    compile(path.read_bytes(), str(path), "exec")
print("syntax: ok")
PY

python3 -B src/stock/flood_heap_oracle_live.py --help >/dev/null
python3 -B src/native/code_dtor_fatal_probe.py --help >/dev/null
python3 -B src/stock/rolling_seedfire_stable25_live.py --help >/dev/null
python3 -B -m unittest tests/test_verifier_schema.py >/dev/null

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/cfctf-package.XXXXXX")"
trap 'rm -rf -- "$tmp_root"' EXIT

python3 -B src/stock/rolling_seedfire_stable25_live.py \
  --heap 0x7f0000000000 \
  --libphp 0x7efffc800000 \
  --timeout 5 \
  --out-dir "$tmp_root/dry-run" \
  --dry-run \
  --session-id attacksessionid0001 >/dev/null

printf 'accepted-controller: ok\n'
printf 'imports: ok\n'
printf 'verifier schema: ok\n'
printf 'terminal dry-run: ok\n'
