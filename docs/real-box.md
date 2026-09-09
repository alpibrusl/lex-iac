# The apply path, run for real

Everything in `demo/buried-destroy.sh` and `demo/side-by-side.sh` runs
anywhere, because deciding about a plan needs no special hardware. The
*apply* path does: it boots a Firecracker microVM, which needs KVM and
root. This records a run of it, so "applies inside a box" stops being a
claim the README makes and becomes a thing that happened.

Run on an x86_64 Linux host with `/dev/kvm`, Firecracker v1.16.1 and
terraform 1.8.2, against `lex-iac@b0d28e3` and `lex-os@20892ab`.

## Setup

```sh
( cd lex-os  && sudo bash demo/setup-assets.sh )
( cd lex-iac && sudo LEX_OS=../lex-os bash demo/build-box.sh )
```

`build-box.sh` plans on the host and injects the plan *and the providers
it was planned against*, because `terraform init` needs a registry and
the box must not have one. It also refuses any provider that could reach
a real account — `local`, `null`, `random`, `time`, `external` only — so
running it creates nothing outside the microVM.

## The grant, and two things it refused first

Applying is executing, so the grant has to say so:

```jsonc
{
  "grant": { "filesystem": "ReadOnly", "network": "Allowlist",
             "exec": "Sandboxed" },   // a grant with exec:None cannot apply
  "isolation_floor": "MicroVm",       // sandboxed exec implies at least gvisor
  "facets": { "infra": { "allow": ["local.file.create"] } }
}
```

The first attempt left `isolation_floor: Namespace`, and lex-os refused
before booting anything:

```
Error [PRECONDITION_FAILED]: manifest is not internally consistent:
  grant fs=read-only net=allowlist exec=sandboxed implies an isolation
  floor of `gvisor` but manifest declares `namespace`
```

That refusal is the "one manifest, two enforcement points" property
working: the gate hands the grant to `lex-os exec` verbatim, so lex-os
gets to disagree with it — and did.

The second attempt used `local.file.*`, and the budget wall refused: an
unpriced create cannot be authorised by a wildcard. A local file has no
price, so the honest fix is to name the verb, `local.file.create`,
rather than invent a cost report to satisfy a check.

## Binding, then applying

Approve plan A, bound to the artifact:

```
$ lex-iac check --grant grant.json --tfplan tfplanA --approval-out approval.json
artifact:  sha256:7c96db46d663b5a3d4cf9e6b…  (the saved plan this JSON was read from)
ACCEPTED — every effect is inside the grant.
approval:  written to approval.json
```

Try a *different but equally valid* plan under that approval:

```
$ sudo lex-iac apply --grant grant.json --tfplan tfplanB --approval approval.json …
REFUSED — the plan being applied is not the plan that was approved.
  approved: sha256:7c96db46d663b5a3d4cf9e6b…
  on disk:  sha256:464b603219d4dcc785f2aa96…
Nothing was applied. The box was never booted.
```

Nothing is wrong with plan B. It passes the gate on its own merits, so a
re-check would admit it. Only the digest tells the two apart, which is
the whole reason an approval names one.

Apply the artifact that *was* approved:

```
$ sudo lex-iac apply --grant grant.json --tfplan tfplanA --approval approval.json …
approval:  sha256:7c96db46d663b5a3d4cf9e6b… verified — this is the artifact that was accepted
ALLOWED — applying inside the box.
perimeter: "firecracker"
security_boundary: true
stdout: "local_file.applied: Creating...
         Apply complete! Resources: 1 added, 0 changed, 0 destroyed."
box exited 0
```

`security_boundary: true` is lex-os saying this was a hardware-virtualised
boundary and not the simulator — the distinction `--simulated` exists to
keep honest.

## The state the box wrote, gated on the way back

Run on the same host, 2026-09-09, on the state wall (#17).

A fresh box, planned on the host, applied inside a real microVM:

```
[guest:exec] mediation outcome: Some("ran `proc.exec`") -> allowed=true
decision: "allowed"
perimeter: "firecracker"
security_boundary: true
stdout: "local_file.applied: Creating...
         local_file.applied: Creation complete after 0s [id=b6ba18b0aa…]
         Apply complete! Resources: 1 added, 0 changed, 0 destroyed."
```

The candidate state was then read out of the box's own filesystem — not
constructed, not a fixture:

```
version 4  serial 1
  managed local_file.applied  instances=1
     id: b6ba18b0aa7693b3da9f7a52f9798b1564876840
```

and held against the plan the gate approved:

```
$ lex-iac state commit --plan plan.json \
                       --prior prior.tfstate --candidate candidate.tfstate
ALLOWED — 1 state change(s), each declared by the plan.
  local_file.applied — created
```

Then the case the wall exists for. The same state, from the same real
apply, with one resource appended — a box that did what it was told
*and* something else:

```
$ lex-iac state commit --plan plan.json --prior prior.tfstate \
                       --candidate tampered.tfstate \
                       --commit-to backend.tfstate
REFUSED — 1 state change(s) the plan did not declare:
  aws_iam_user.backdoor — state records `created` for `aws_iam_user.backdoor`,
                          which the gated plan never mentions

The candidate was NOT committed.
$ ls backend.tfstate
  no — the record is untouched
```

The tampered file is valid JSON and a valid Terraform state; it parses,
and every other resource in it is genuine. Only the comparison against
the plan tells the two apart — which is the same shape as the artifact
binding above, one layer further on: there, two valid plans; here, two
valid states.

That `ls` is the half worth keeping. A wall that prints a refusal and
writes anyway is decoration, so the refusal path is the one with a test
of its own.

**What this half does not settle.** `apply` does not yet stage prior
state into the guest or bring the candidate back out — that extraction
was done by hand here, by mounting the image. The wall's verdict is
unaffected, but the two halves are joined by the operator rather than by
the tool, and the verdict does not yet join the audit chain.

## What this run does not settle

Credentials. The box applied a `local_file`, which needs none. Whether
cloud credentials belong inside the box or behind a host-side proxy is a
real decision with real blast radius, and #17 is where it belongs; a
plumbing layer should not settle it by defaulting.
