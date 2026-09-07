#!/usr/bin/env bash
# Build the guest image that `lex-iac apply` runs terraform inside
# (milestone 6 of #1).
#
# lex-os's `exec` runs a command *inside* the microVM, so the binary has
# to exist in the guest's own filesystem — there is no host mount, and
# that is the point: the box gets what we put in it and nothing else.
#
#   sudo bash demo/build-box.sh                 # from lex-os's demo rootfs
#   sudo LEX_OS=/path/to/lex-os bash demo/build-box.sh
#
# Produces demo/assets/box.ext4: lex-os's guest rootfs plus terraform and
# a pre-initialised working directory.
#
# # Why the working directory is pre-initialised on the host
#
# `terraform init` downloads providers from registry.terraform.io. A box
# whose egress is narrowed to the provider endpoints cannot reach a
# registry, and widening it to allow one would hand the box the ability
# to fetch and run arbitrary provider code — which is the opposite of
# what this milestone is for.
#
# So `init` happens outside, and the box receives the plan *and the
# providers it was planned against*. That is also how the real workflow
# runs: plan in CI, apply from the artifact.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LEX_OS=${LEX_OS:-$ROOT/../lex-os}
ASSETS="$ROOT/demo/assets"
SRC_ROOTFS="$LEX_OS/demo/assets/rootfs.ext4"
OUT="$ASSETS/box.ext4"
# lex-os's rootfs has ~72 MB free and terraform is ~85 MB, so the image
# has to grow. Sized for terraform plus a provider plugin dir.
SIZE=${SIZE:-700M}

[ -f "$SRC_ROOTFS" ] || {
  echo "build-box: no rootfs at $SRC_ROOTFS" >&2
  echo "  run lex-os's demo/setup-assets.sh first, or set LEX_OS=" >&2
  exit 1
}
command -v terraform >/dev/null || { echo "build-box: terraform not on PATH" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "build-box: needs root (loop mount)" >&2; exit 1; }

mkdir -p "$ASSETS"
echo "+ copying lex-os's guest rootfs and growing it to $SIZE"
cp "$SRC_ROOTFS" "$OUT"
truncate -s "$SIZE" "$OUT"
e2fsck -fp "$OUT" >/dev/null 2>&1 || true
resize2fs "$OUT" >/dev/null

WORK=$(mktemp -d)
MNT=$(mktemp -d)
trap 'umount "$MNT" 2>/dev/null || true; rm -rf "$WORK" "$MNT"' EXIT

echo "+ planning on the host (init needs a registry; the box must not)"
cat > "$WORK/main.tf" <<'TF'
# Deliberately credential-free and network-free.
#
# The point of this slice is the plumbing — that terraform runs inside a
# real microVM, gated and audited — not that it can reach a cloud. A
# provider needing credentials would confuse "the box works" with "the
# credential design works", and those are separate questions.
terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

resource "local_file" "applied" {
  filename = "/tmp/lex-iac-applied.txt"
  content  = "applied inside the box\n"
}
TF
# A guard, not a promise: refuse to plan anything that could reach a
# cloud account. `local` and `null` create nothing outside the box and
# need no credentials. Any other provider is a different conversation —
# about credentials, blast radius and whose account is being touched —
# and it must not happen by accident in a demo script.
ALLOWED_PROVIDERS='^(local|null|random|time|external)$'
PROVIDERS=$(grep -oE '"hashicorp/[a-z0-9_-]+"' "$WORK/main.tf" | sed 's|"hashicorp/||;s|"||' | sort -u)
for prov in $PROVIDERS; do
  if ! echo "$prov" | grep -qE "$ALLOWED_PROVIDERS"; then
    echo "build-box: REFUSING to plan with provider \`$prov\`." >&2
    echo "  This script creates nothing outside the microVM by design." >&2
    echo "  A provider that talks to a real account needs a credential" >&2
    echo "  design and an explicit decision about whose infrastructure is" >&2
    echo "  at stake — not a demo default." >&2
    exit 2
  fi
done
echo "+ providers: ${PROVIDERS:-none} (credential-free, nothing outside the box)"

( cd "$WORK" && terraform init -input=false >/dev/null && \
                terraform plan -input=false -out=tfplan >/dev/null && \
                terraform show -json tfplan > plan.json )

# Belt and braces: the planned document must not name a cloud resource
# even if main.tf somehow slipped one past the check above.
python3 - "$WORK/plan.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
bad = [c["address"] for c in doc.get("resource_changes", [])
       if not c.get("type", "").startswith(("local_", "null_", "random_", "time_"))]
if bad:
    sys.exit(f"build-box: the plan touches non-local resources {bad}; refusing")
PY
echo "+ plan produced: $(python3 -c "import json;print(len(json.load(open('$WORK/plan.json')).get('resource_changes',[])))" 2>/dev/null || echo '?') resource change(s)"

echo "+ injecting terraform + the planned working directory into the box"
mount -o loop "$OUT" "$MNT"
install -m 0755 "$(command -v terraform)" "$MNT/usr/bin/terraform"
rm -rf "$MNT/work"
mkdir -p "$MNT/work"
cp -a "$WORK/." "$MNT/work/"
sync
umount "$MNT"

# The plan travels to the host side too: `lex-iac apply` gates *this*
# document before the box is ever booted.
cp "$WORK/plan.json" "$ASSETS/plan.json"

echo "+ box image at $OUT"
ls -lh "$OUT" "$ASSETS/plan.json"
