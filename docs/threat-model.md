# Threat model for in-box apply

`lex-iac apply` runs `terraform apply` inside a lex-os microVM. Milestone 6
shipped that with a credential-free provider on purpose: it proved the
plumbing without deciding the hard part. The hard part is what a real apply
needs and the box does not have — **provider credentials** and **state
backend access** — and [#17](https://github.com/alpibrusl/lex-iac/issues/17)
names three shapes it could take.

Those three shapes are not comparable until someone says what they defend
against. This document says it, so the choice stops being taste.

A design document, except where it says otherwise. **The state axis is
built** — see `lex-iac state commit` and `src/state.rs`. The credential
axis is not, and is still waiting on the one question below that decides
it.

## What the perimeter already gives

Established, and not re-argued here:

- **The plan applied is the plan gated.** `--tfplan` derives the JSON from
  the binary plan via `terraform show -json`, so there is one artifact, and
  `--approval`/`--approval-out` refuse a swap between runs (#22).
- **The box applies a plan file, not a config.** It cannot re-plan into
  something else.
- **The box's confinement is the grant the gate checked.** `apply_argv`
  passes the same manifest to `lex-os exec`, not a document derived from it.
- **Egress is kernel-enforced** and bounds *where* the box can talk.
- **The session is chained**, and `--authorised-by` writes the gate's
  decision head into the box's own first audit entry.

## What it structurally cannot give

**The wall bounds reach, not authority.** A box holding credentials, with the
provider's endpoint allowlisted, can do anything those credentials permit at
that endpoint. Narrowing "the internet" to "your cloud account" is an
improvement; it is not the claim this project wants to make.

Everything below follows from that one sentence.

## Two assets, and only one of them is credentials

The discussion in #17 treats state as a second instance of the credential
problem. It is not. They are different kinds of thing:

| | asset | if it is lost |
| --- | --- | --- |
| **Authority** | the provider credential | the adversary acts inside your account |
| **The record** | terraform state | the adversary decides what the *next* plan says |

The gate reasons about a plan. A plan is a function of config **and state**.
So if the box can write state, it can forge the input to every future
decision this gate makes — and the gate is then reasoning about a document
rather than about reality.

That makes state integrity **upstream of the gate itself**, not a peer
concern to credentials. It is also the cheaper of the two to fix. Both
reasons say: do state first.

## The adversaries

Four, from #17, with the likelihood judgement that #17 left out — because
the ranking matters as much as the list.

1. **A buggy provider that touches more than it planned.** *Routine.*
   Plan/apply divergence is a known class, not a hypothetical. Non-adversarial:
   it will not hunt for the gap between "what my credential permits" and
   "what the plan implied".
2. **A malicious provider or module from a registry.** *Rare, unbounded.*
   Adversarial and running with the box's full authority. It will look for
   exactly that gap, and it can exfiltrate the credential itself to any
   allowlisted endpoint — the provider API is allowlisted by construction.
3. **A compromised plan that passed the gate.** *This is the gate's core
   case.* A plan that is honestly what it says and was authored maliciously
   is what the grant exists to refuse. Credentials change nothing here. The
   interesting sub-case is a plan that passed **because state was forged**,
   which is adversary 1 or 2 arriving through the record.
4. **An operator who wants to exceed their grant.** *Out of scope, and it
   must be said out loud.* The operator owns the host. Under **A** they mint
   the session; under **B** the credentials sit on their machine and the
   proxy is theirs to bypass; under **C** they *are* the executor. No
   credential design defends against them. The audit chain records what they
   did; it does not stop them — the same honest limit lex-k8s states about
   anyone with cluster-admin.

## The options against the adversaries

**A.** Credentials in the box, scoped and short-lived (an STS session as
tight as the plan needs, expiring in minutes).
**B.** Credentials on the host, behind a proxy enforcing method and path,
not merely host and port.
**C.** Split the apply: the box computes, the host performs.

| | 1. buggy provider | 2. malicious provider | 3. compromised plan | 4. operator |
| --- | --- | --- | --- | --- |
| **A** | bounded by session scope | **holds the credential** — bounded only by scope, and can exfiltrate it | gate's job, unaffected | no defence |
| **B** | bounded by permitted calls | **never holds the credential**; every call checked | gate's job, unaffected | no defence |
| **C** | *worse* — the bug now runs on the host, outside the perimeter | ditto | gate's job, unaffected | no defence |

### What falls out

**A and B are nearly identical against adversary 1, and enormously different
against adversary 2.** A bug is not adversarial: a tight enough session scope
bounds it about as well as a call-level proxy would. A malicious provider is
adversarial, and under A it is holding your credential.

**C is dominated and should be dropped.** Against every adversary it either
matches the others or is actively worse, because moving execution to the host
removes the perimeter from the path. #17 called it "probably not worth it";
this is the reason, and it is stronger than "furthest from how terraform
works". Keep it named so the other two are compared against something, not as
a candidate.

**Adversary 4 is undefendable and adversary 3 is unaffected.** So the entire
A-versus-B question reduces to adversary 2.

### The question that decides A versus B

> **Do you run providers or modules you did not vendor and pin?**

If **no** — everything vendored, pinned by digest, from a registry you
control — adversary 2 is close to adversary 1, and **A is defensible**: scope
the session to the plan's resource types, expire it in minutes, and write
down that the wall constrains reach and not authority.

If **yes** — anything pulled from the public registry at apply time — then
adversary 2 is live, A is holding a credential in a box running third-party
code, and **B is the only shape that answers it**. Its cost is real: mapping
a plan to the set of API calls it implies is provider-specific and will not
generalise cleanly. That cost is the price of that threat, and it should be
paid only if the threat is real.

This is a question about how you operate, not about the code. It should be
answered before either is built.

## The state axis, decided

State can be answered now, independently, and more cheaply than either
credential shape.

**The box never gets backend credentials.** It gets prior state as a file,
applies, and produces a candidate successor state as an output artifact. The
host commits it — or refuses.

The refusal is the point, and it is not a rubber stamp. The gate has already
parsed the plan into `ResourceChange { address, change.actions }`
(`src/plan.rs`), so it holds the exact set of `(address, verb)` pairs the
plan declared. Committing a successor state is then a checkable claim:

> the set of resource addresses that differ between prior and candidate
> state must equal the set the gated plan declared it would change, with
> matching verbs.

A box that quietly adds a resource to state, drops one, or reports a `create`
where the plan said `update` fails that check, and the host does not commit.

**What this cannot check, and why.** Not values. Terraform marks
provider-computed attributes as *known after apply*, so IDs, ARNs and
computed fields cannot be predicted from the plan and cannot be verified
against it. The check is **structural** — which resources changed and how —
not semantic. A malicious provider can therefore still write a wrong *value*
into a resource the plan legitimately touched. That is a real residual and it
should be in the README's cautions when this ships, not discovered later.

It nonetheless closes the thing that matters most: the box cannot enlarge the
record beyond what was gated, so it cannot forge the input to the next
decision.

**Read-only is not enough on its own.** Handing the box a read-only copy and
letting the host push whatever comes back unchecked leaves the box in control
of the record by a longer route. The validation is the mechanism; read-only
access is just what makes the validation the only path.

### What was built

```sh
lex-iac state commit --plan plan.json \
                     --prior prior.tfstate --candidate candidate.tfstate \
                     [--commit-to path]
```

```
REFUSED — 1 state change(s) the plan did not declare:
  aws_iam_user.backdoor — state records `created` for `aws_iam_user.backdoor`,
                          which the gated plan never mentions

The candidate was NOT committed. A state the plan does not account for is
the input to every plan after it.
```

Exit 0 allows, 8 refuses, 2 could not run — and that third code is
load-bearing. A malformed candidate is *"I could not tell"*, never *"I
refused"*: an operator who mistypes a path must not be told the box
attacked them, and a rule keyed on exit 8 must not fire on a typo.

`--commit-to` writes the candidate on success and never on a refusal.
Without it the verdict is the output and the caller acts on the exit
code, which is what a remote backend needs — there is no backend
integration here to get wrong.

The decisive test mirrors `a_different_but_equally_valid_plan_is_refused`:
**a candidate state that is internally consistent and well-formed, and
changes one address the plan never mentioned, is refused.** It fails for
the structural reason, which is only meaningful because malformed input
lands on exit 2 instead — otherwise it could be passing for the wrong
reason, and a separate test pins that.

**Deliberately one-directional.** It refuses a change the plan did not
declare; it does not require every declared change to have happened. An
apply that stops halfway leaves changes undone, and that state is a
legitimate thing to record — refusing it would destroy the evidence of
what actually happened, which is what an operator needs most at exactly
that moment.

### Still to build

`apply` does not yet stage prior state into the guest or bring the
candidate back out, so today the two halves are joined by the operator
rather than by the tool, and the verdict does not join the audit chain.
Neither changes what the wall decides.

## What this document does not defend against

Stated plainly, because a threat model that lists only what it beats is
marketing:

- **The operator.** Adversary 4, by construction. Audit, not prevention.
- **Attribute-level state forgery.** Structural validation cannot see it.
- **A provider that is malicious inside the plan's own footprint.** If the
  plan legitimately grants `aws.s3.create`, a provider creating that bucket
  wrongly is inside the grant. The grant's granularity is the ceiling, and
  README caution 2 already admits `provider.service.verb` may be the wrong
  compromise.
- **Anything after apply.** This gate is admission-time. A resource that
  drifts later is another system's problem.
