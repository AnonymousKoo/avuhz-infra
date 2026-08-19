#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

printf 'check: JSON syntax\n'
find . -path ./.git -prune -o -type f -name '*.json' -print0 |
  xargs -0 -r -n1 jq -e . >/dev/null

printf 'check: JSON Schema and fixtures\n'
python3 tests/contracts/validate_identifiers.py

printf 'check: forbidden paths\n'
tracked_candidates="$(mktemp)"
trap 'rm -f "$tracked_candidates"' EXIT
find . -path ./.git -prune -o -type f -printf '%P\n' | sort > "$tracked_candidates"
if grep -Ev '^[[:space:]]*(#|$)' security/forbidden-path-patterns.txt |
  while IFS= read -r pattern; do
    grep -En "$pattern" "$tracked_candidates" || true
  done | grep -q .; then
  printf 'error: forbidden repository path detected\n' >&2
  exit 1
fi

printf 'check: forbidden credential-shaped content\n'
if rg -n -i --hidden --glob '!.git/**' \
  --glob '!contracts/fixtures/v1/identifiers.cases.json' \
  '(authorization|api[_-]?key|client[_-]?secret|access[_-]?token|bearer)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9_./:+-]{16,}' .; then
  printf 'error: potential literal authentication material detected\n' >&2
  exit 1
fi

printf 'check: Semgrep local secret rules\n'
semgrep scan --config .semgrep.yml --error --quiet .

printf 'check: no legacy fingerprints or prohibited resource classes\n'
if find . -path ./.git -prune -o -type f \( -name '*.sql' -o -name 'linked-project.json' -o -name '*.env' -o -name '.env.*' \) -print -quit | grep -q .; then
  printf 'error: prohibited resource class detected\n' >&2
  exit 1
fi

printf 'baseline checks: PASS\n'
