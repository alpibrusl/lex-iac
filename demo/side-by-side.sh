#!/usr/bin/env bash
# The same three Terraform plans, decided twice: by terraform alone, and
# by the gate in front of it.
#
# Terraform validates that a plan is *coherent*. It has no opinion about
# whether you were allowed to make this change, or what it costs, because
# nothing ever told it. That is not a defect in terraform -- it is the
# gap this gate exists to fill, and the point of running both columns is
# to make the gap concrete rather than argue about it.
#
# No cloud is touched and no provider is downloaded: the plans are real
# `terraform show -json` captures kept as fixtures.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
F="$ROOT/tests/fixtures"
GRANT="$F/grant_ecs_only.json"
GATE="$ROOT/target/debug/lex-iac"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

cargo build --quiet --manifest-path "$ROOT/Cargo.toml"

bold "the mandate"
python3 - "$GRANT" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print("  goal:   ", m["goal"]["description"])
print("  may do: ", ", ".join(m["facets"]["infra"]["allow"]))
print("  budget: ", f'USD {m["budget"]["max_money_cents"]/100:.2f}/month')
PY

# What terraform alone would do with a plan: everything in it. This
# reads the plan's own resource_changes, which is exactly what `apply`
# would carry out.
would_apply() {
  python3 - "$1" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1]))
acts = []
for c in plan.get("resource_changes", []):
    for a in c.get("change", {}).get("actions", []):
        if a != "no-op":
            acts.append(f"{a} {c['address']}")
print("; ".join(acts) if acts else "no changes")
PY
}

row() {                       # row <label> <plan> <cost>
  local label="$1" plan="$F/$2.json" cost="$F/$3.json"
  local verdict reason
  if out=$("$GATE" check --grant "$GRANT" --plan "$plan" --cost "$cost" 2>&1); then
    verdict="ACCEPTED"; reason=""
  else
    verdict="REFUSED"
    reason=$(echo "$out" | grep -A 2 "REFUSED" | sed -n '3p' | sed 's/^ *//')
  fi
  printf '\n  %s\n' "$label"
  printf '    terraform alone : \033[33mwould apply\033[0m — %s\n' "$(would_apply "$plan")"
  if [ "$verdict" = ACCEPTED ]; then
    printf '    with the gate   : \033[32m%s\033[0m — every effect inside the grant\n' "$verdict"
  else
    printf '    with the gate   : \033[32m%s\033[0m — %s\n' "$verdict" "$reason"
  fi
}

bold "three plans, both columns"
row "a rotation the mandate covers, priced at USD 12.40/mo" rotate_deployment cost_rotation
row "the same rotation, priced past the ceiling"           rotate_deployment cost_over_budget
row "a plan that also replaces a database in another cloud" multi_provider    cost_rotation

bold "what terraform could not have told you"
cat <<'TXT' | sed 's/^/  /'
All three plans are valid Terraform. `terraform plan` exits 0 on every
one of them and `apply` would carry out all three, because a plan does
not carry a mandate, a budget, or a record of who asked. The second row
is the clearest: nothing in the plan is malformed — it simply costs more
than this mandate was given.
TXT

bold "what this does NOT show"
cat <<'TXT' | sed 's/^/  /'
This is the decision, not the execution. `lex-iac check` verifies the
plan JSON it was handed; `lex-iac apply` then runs terraform against a
saved binary plan supplied separately, and nothing yet ties the two
together — so "the approved plan is the one that ran" is NOT
demonstrated here, and should not be claimed. See finding 2 of the
2026-09-08 review; the fix is to derive the JSON from the binary plan
rather than accept both.

The spend figure is a forecast from an estimator, not a meter reading.
TXT
