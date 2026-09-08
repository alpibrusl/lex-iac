#!/usr/bin/env bash
# The plan that passed review.
#
# Everyone who has run terraform in anger has this fear: the plan is 400
# lines, the summary says "1 to destroy", and the thing being destroyed
# is not what anyone thought. Review does not fail because people are
# careless. It fails because a diff of 400 lines and a diff of 4 lines
# look the same in a CI log, and only one of them is safe to skim.
#
# Everything here is real terraform. `demo/buried/plan.json` is the
# output of `terraform show -json` against a hand-written state file,
# planned with `-refresh=false` and throwaway credentials -- so no AWS
# account is contacted and nothing exists to destroy. Regenerate it with
# REGEN=1 if terraform and the AWS provider are available.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
D="$ROOT/demo/buried"
GRANT="$ROOT/tests/fixtures/grant_ecs_only.json"
GATE="$ROOT/target/debug/lex-iac"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
# Deterministic here so the demo can print the public half; a real
# deployment generates one and keeps the secret out of the repo.
AUDIT_KEY=$(printf '11%.0s' $(seq 1 32))

if [ "${REGEN:-0}" = "1" ]; then
  ( cd "$D" && terraform init -no-color >/dev/null && terraform plan -refresh=false -no-color -out=tfplan >/dev/null \
    && terraform show -json tfplan > plan.json && terraform show -no-color tfplan > plan.txt )
fi

bold "1. the ask"
echo "  \"rotate the ten payments services onto the new task definitions\""

bold "2. what terraform says"
grep -E "^Plan:" "$D/plan.txt" | sed 's/^/  /'
printf '  exit status: 0        plan output: %s lines\n' "$(grep -c "" "$D/plan.txt")"

bold "3. what a reviewer actually sees"
LINE=$(grep -n "will be destroyed" "$D/plan.txt" | head -1 | cut -d: -f1)
TOTAL=$(grep -c "" "$D/plan.txt")
echo "  20 creates of the kind they asked for, and one line at ${LINE} of ${TOTAL}:"
echo
sed -n "${LINE}p" "$D/plan.txt" | sed 's/^ */    /'
echo
echo "  That is the whole signal. It scrolls past at the same speed as the other 413."

bold "4. what apply would have done"
python3 - "$D/plan.json" <<'PY' | sed 's/^/  /'
import json, sys
d = json.load(open(sys.argv[1]))
for c in d["resource_changes"]:
    if "delete" in c["change"]["actions"]:
        b = c["change"]["before"] or {}
        print(f'destroy {c["address"]}')
        for k in ("engine","instance_class","allocated_storage","multi_az",
                  "backup_retention_period","deletion_protection","skip_final_snapshot"):
            if k in b:
                print(f'  {k:24} {b[k]}')
PY
red "  deletion_protection is false and skip_final_snapshot is true."
red "  There is no snapshot and nothing to stop it. That database does not come back."

bold "5. the same plan, through the gate"
START=$(python3 -c 'import time; print(int(time.time()*1000))')
set +e
OUT=$("$GATE" check --grant "$GRANT" --plan "$D/plan.json" --cost "$D/cost.json" \
        --audit-out /tmp/lex-iac-demo-audit.json \
        --checkpoint-out /tmp/lex-iac-demo-cp.json --audit-key "$AUDIT_KEY" 2>&1)
RC=$?
set -e
END=$(python3 -c 'import time; print(int(time.time()*1000))')
echo "$OUT" | sed -n '/REFUSED/,$p' | head -8 | sed 's/^/  /'
grn "  refused in $((END-START)) ms, by name, before anything ran."
[ "$RC" -eq 0 ] && { red "the gate allowed it"; exit 1; }

bold "6. and it left evidence someone else can check"
PK=$("$GATE" audit pubkey --key "$AUDIT_KEY")
python3 - "$PK" <<'PY' | sed 's/^/  /'
import json, sys
log = json.load(open("/tmp/lex-iac-demo-audit.json"))
print(f"{len(log)} hash-chained entries, each sealed by {sys.argv[1][:16]}…")
for e in log:
    k = e["event"].get("kind")
    if k:
        print(f"  seq {e['seq']}: {k}" + (f"  {e['event'].get('effect','')} at {e['event'].get('address','')}" if k == "plan_refused" else ""))
PY
echo
echo "  Now suppose someone would rather the record said this was fine:"
python3 - <<'PY'
import json
log = json.load(open("/tmp/lex-iac-demo-audit.json"))
for e in log:
    if e["event"].get("kind") == "plan_refused":
        e["event"]["kind"] = "plan_accepted"
json.dump(log, open("/tmp/lex-iac-demo-audit-tampered.json", "w"))
PY
echo "    (flipped plan_refused -> plan_accepted)"
set +e
"$GATE" audit verify --log /tmp/lex-iac-demo-audit-tampered.json --trusted-key "$PK" 2>&1 | head -3 | sed 's/^/    /'
set -e

echo
echo "  Editing it is the loud way. The quiet way is to remove the entry:"
python3 - <<'PY'
import json
log = json.load(open("/tmp/lex-iac-demo-audit.json"))
json.dump(log[:-1], open("/tmp/lex-iac-demo-audit-short.json", "w"))
print(f"    (dropped the last entry: {len(log)} -> {len(log)-1})")
PY
echo "    The chain and the seals cannot see it — every entry left is genuine:"
set +e
"$GATE" audit verify --log /tmp/lex-iac-demo-audit-short.json --trusted-key "$PK" 2>&1 | head -2 | sed 's/^/    /'
echo "    The checkpoint can, because it was written while that entry existed:"
"$GATE" audit verify --log /tmp/lex-iac-demo-audit-short.json --trusted-key "$PK" \
  --checkpoint /tmp/lex-iac-demo-cp.json 2>&1 | grep -E "REFUSED|truncated" | head -2 | sed 's/^/    /'
set -e

bold "what this does not prove"
cat <<'TXT' | sed 's/^/  /'
The forecast is an estimator's, not a meter reading: "USD 18.50/month"
is what a cost tool predicts, and a plan that is wrong about the world
prices wrongly too.

The gate reads the plan. A provider that mutates outside its declared
plan -- some do, on drift -- is invisible to any document reader, which
is why `apply` runs inside a lex-os box rather than trusting the plan to
be honest. That perimeter needs KVM and is not exercised here.
TXT
