#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

printf 'check: JSON syntax\n'
find . -path ./.git -prune -o -path ./supabase/.temp -prune -o -type f -name '*.json' -print0 |
  xargs -0 -r -n1 jq -e . >/dev/null

printf 'check: JSON Schema and fixtures\n'
python3 tests/contracts/validate_identifiers.py
python3 tests/contracts/validate_diagnostic_agreement_authority.py
python3 tests/contracts/validate_diagnostic_payment_verification.py
python3 tests/contracts/validate_assessment_access_grant.py

printf 'check: forbidden paths\n'
tracked_candidates="$(mktemp)"
trap 'rm -f "$tracked_candidates"' EXIT
find . -path ./.git -prune -o -path ./supabase/.temp -prune -o -type f -printf '%P\n' | sort > "$tracked_candidates"
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

printf 'check: approved migration SQL and prohibited resource classes\n'
sql_candidates="$(mktemp)"
trap 'rm -f "$tracked_candidates" "$sql_candidates"' EXIT
find . -path ./.git -prune -o -path ./supabase/.temp -prune -o -type f -name '*.sql' -printf '%P\n' | sort > "$sql_candidates"
if grep -Ev '^(supabase/migrations/[0-9]{14}_[A-Za-z0-9][A-Za-z0-9_-]*\.sql|supabase/inventory/current_public_schema\.sql)$' "$sql_candidates" | grep -q .; then
  printf 'error: SQL is permitted only in approved Supabase migrations or the exact schema inventory artifact\n' >&2
  exit 1
fi
while IFS= read -r migration; do
  [ -z "$migration" ] && continue
  if [[ "$migration" =~ (legacy|dump|backup|export) ]]; then
    printf 'error: legacy or dump-like SQL filename is prohibited\n' >&2
    exit 1
  fi
  if awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*(insert|update|delete)[[:space:]]/ { found=1 } END { exit(found ? 0 : 1) }' "$migration"; then
    printf 'error: direct row-data DML is prohibited in approved migration baseline files\n' >&2
    exit 1
  fi
  if rg -n -i '^[[:space:]]*(copy|\\copy)[[:space:]]|dumped from|pg_dump' "$migration"; then
    printf 'error: dump-like SQL content is prohibited in approved migration baseline files\n' >&2
    exit 1
  fi
done < "$sql_candidates"
if find . -path ./.git -prune -o -path ./supabase/.temp -prune -o -type f \( -name 'linked-project.json' -o -name '*.env' -o -name '.env.*' \) -print -quit | grep -q .; then
  printf 'error: prohibited resource class detected\n' >&2
  exit 1
fi

printf 'baseline checks: PASS\n'
