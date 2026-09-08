#!/usr/bin/env python3
"""Render the one mandate into the form each gate reads.

Both outputs are derived, never edited. That is the whole claim: the
mandate exists once, and a tightening cannot reach one surface and miss
the other, because there is no second place to forget.
"""
import json, sys, pathlib, re

import yaml

def load(path):
    return yaml.safe_load(pathlib.Path(path).read_text())

def lst(v):
    """A key whose last item was removed parses as None, not [].

    Withdrawing the only granted secret is a perfectly ordinary
    tightening, and it must render an empty allow-list rather than a
    null -- which the gate rejects as a malformed manifest, turning a
    narrower mandate into a broken one.
    """
    return v or []

m = load(sys.argv[1] if len(sys.argv) > 1 else "mandate.yaml")

# The Terraform gate reads a lex-os manifest with an `infra` facet.
grant = {
    "goal": {"description": m["goal"], "done_signal": None},
    "grant": {"filesystem": "ReadOnly", "network": "Allowlist", "exec": "Sandboxed"},
    "budget": {
        "wall_clock_secs": 900,
        "max_commands": 50,
        "max_money_cents": m["budget"]["max_money_cents"],
        "max_api_calls": 200,
    },
    "isolation_floor": "Namespace",
    "egress": lst(m["egress"]),
    "actuation": None,
    "facets": {"infra": {"allow": lst(m["infra"]["allow"])}},
}
pathlib.Path("grant.json").write_text(json.dumps(grant, indent=2))

# The admission wall reads the same mandate wearing a CRD.
crd = {
    "apiVersion": "lex.dev/v1alpha1",
    "kind": "LexManifest",
    "metadata": {"name": m["team"], "namespace": m["team"]},
    "spec": {
        "goal": m["goal"],
        "grant": {
            "egress": lst(m["egress"]),
            "secrets": lst(m["secrets"]),
            "capabilities": lst(m["pod"]["capabilities"]),
            "hostPath": m["pod"]["hostPath"],
            "privileged": m["pod"]["privileged"],
            "hostNamespaces": m["pod"]["hostNamespaces"],
            "imagePrefixes": lst(m["pod"]["imagePrefixes"]),
        },
    },
}
pathlib.Path("lexmanifest.json").write_text(json.dumps(crd, indent=2))
print(f"  rendered from mandate.yaml: grant.json (terraform), lexmanifest.json (kubernetes)")
print(f"  infra may do:    {', '.join(m['infra']['allow'])}")
print(f"  images must be:  {', '.join(m['pod']['imagePrefixes'])}")
