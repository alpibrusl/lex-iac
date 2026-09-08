#!/usr/bin/env bash
# One mandate, two surfaces.
#
# The usual arrangement is a policy engine per surface: Rego for
# Kubernetes, something else for Terraform, and a human keeping the two
# in agreement. That human is the single point of failure. A rule
# tightened in one place and forgotten in the other produces no error
# anywhere -- the surfaces simply disagree, quietly, until something
# gets through that shouldn't have.
#
# Here the mandate is one document. Both gates read it. There is no
# second copy to drift, which is a structural property rather than a
# discipline: you cannot forget to update the other file, because there
# is no other file.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IAC=${IAC:-$HERE/../../target/debug/lex-iac}
K8S=${K8S:-$HERE/../../../lex-k8s/target/debug/lex-k8s}
cd "$HERE"

# The tightening step edits a copy. The mandate in the repo is read,
# never written, so an interrupted run cannot leave it narrowed.
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
MANDATE="$WORK/mandate.yaml"; cp mandate.yaml "$MANDATE"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
red()  { printf '\033[31m%s\033[0m\n' "$*"; }

[ -x "$K8S" ] || { echo "need lex-k8s built at $K8S (cargo build in the lex-k8s checkout)"; exit 2; }

tf_verdict() {
  { "$IAC" check --grant grant.json --plan plan.json --cost cost.json 2>/dev/null \
    || true; } | grep -E "^(ACCEPTED|REFUSED)" | head -1
}
tf_reason() {
  { "$IAC" check --grant grant.json --plan plan.json --cost cost.json 2>/dev/null \
    || true; } | sed -n '/REFUSED/,$p' | sed -n '3,4p' | sed 's/^ */      /'
}
k8s_verdict() {
  { "$K8S" admit --manifest lexmanifest.json --snapshot cluster.json < "$1" 2>/dev/null || true; } \
    | sed -n '/^{/,$p' | python3 -c "
import json,sys
r = json.load(sys.stdin)['response']
print('ADMITTED' if r['allowed'] else 'REFUSED — ' + r.get('status',{}).get('message','').split(' refused')[0][:60])"
}

bold "the mandate, written once"
sed -n '/^team:/,$p' "$MANDATE" | grep -vE "^\s*#" | sed 's/^/  /'

bold "rendered into what each gate reads"
python3 render.py "$MANDATE" >/dev/null
echo "  grant.json        -> lex-iac      (terraform)"
echo "  lexmanifest.json  -> lex-k8s      (kubernetes admission)"
echo "  neither is edited by hand; both are derived"

bold "both gates, against that mandate"
printf '  terraform: rotate the payments services   %s\n' "$(tf_verdict)"
printf '  k8s:       pod reading payments-db       %s\n' "$(k8s_verdict pod-within.json)"
printf '  k8s:       pod reading observability-tok%s\n' "$(k8s_verdict pod-outside.json)"

bold "now the team is narrowed — one edit, one file"
MANDATE="$MANDATE" python3 - <<'PY'
import pathlib, re
import os
p = pathlib.Path(os.environ["MANDATE"]); s = p.read_text()
s = s.replace("    - aws.cloudwatch.*\n", "")            # no more log-group churn
s = s.replace("  - payments-db\n", "")                    # the DB secret is withdrawn
p.write_text(s)
print("  - dropped  aws.cloudwatch.*        from infra.allow")
print("  - withdrew  payments-db              from secrets")
PY
python3 render.py "$MANDATE" >/dev/null

bold "the same two gates, unchanged, re-reading the same file"
printf '  terraform: rotate the payments services   %s\n' "$(tf_verdict)"
tf_reason
printf '  k8s:       pod reading payments-db       %s\n' "$(k8s_verdict pod-within.json)"
grn "  Both tightened. Neither gate was reconfigured, and nothing was"
grn "  edited twice."


bold "what this does and does not show"
cat <<'TXT' | sed 's/^/  /'
It shows one document governing two enforcement points, with no second
declaration to drift. That is the structural claim, and it is the part
a policy-engine-per-surface arrangement cannot make.

It does not show the two gates agreeing on *meaning* beyond what they
share. They read different facets -- `infra` and `pod` -- and each
understands verbs the other does not. The mandate is one file; the
vocabularies are deliberately not one vocabulary.

And not every field in the mandate is enforced from the mandate. The
tightening above uses `secrets` and `infra.allow`, both of which the
gates read from this document. `pod.imagePrefixes` is NOT one of them:
image trust is taken from the cluster snapshot's
`trusted_image_prefixes`, and narrowing the mandate alone leaves an
untrusted image admitted. That was found by trying it here. Until it is
reconciled, treat `imagePrefixes` in this file as documentation rather
than as the thing doing the work.
TXT
