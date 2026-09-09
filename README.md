# lex-iac

**Part of the [Lex](https://lexlang.org) project** — Substrate · [Manifesto](https://lexlang.org/manifesto) · [lex-lang](https://github.com/alpibrusl/lex-lang) · [lex-os](https://github.com/alpibrusl/lex-os)

> Infrastructure-as-code already has an effect system. It has no type
> checker. `lex-iac` is the type checker.

Terraform, OpenTofu, Pulumi and Crossplane all have the same shape: a
*plan* (the declared set of mutations) and an *apply*. The plan is a
typed diff, and nothing checks it against what the author of the change
was actually allowed to do. Guardrails exist — Sentinel, OPA, Checkov,
cloud SCPs — but they are rule lists evaluated per run: they don't
narrow, they don't attest, and a rule nobody wrote is a hole nobody
finds.

An agent emitting infra changes has exactly the profile lex-lang was
built for. It will confidently produce a plan whose blast radius is
larger than the task it was given, and no human is reading the 400-line
diff.

## The one rule

> The consumer's grant, never the plan's declaration, is the ceiling.

## Try it

```sh
cargo run -- check --grant tests/fixtures/grant_with_rds_wildcard.json \
                   --plan  tests/fixtures/harmless_tag_change.json
```

```
goal:      manage the payments stack
plan:      sha256:2e788cc61dd7…
grant:     manifest:81540195a8cf
spend:     unpriced — no --cost report

REFUSED — 1 effect(s) outside the grant:

  aws.rds.replace  [reversibility]
    at:     aws_db_instance.payments
    reason: only `aws.rds.*` admits it, and a wildcard cannot authorise
            destruction of stateful infrastructure — name the verb explicitly

the grant allows:
  aws.ecs.*
  aws.cloudwatch.*
  aws.rds.*

audit: 2 entries, head sha256:6d27aa34…
```

That plan reads as a routine tagging change. Two of its three resources
are exactly that. The third destroys and recreates a production
database, and `actions: ["delete","create"]` is the only place the plan
admits it.

Note what the grant says: `aws.rds.*`. Under a rule engine that is a
pass. Here it is not, because **a wildcard never authorises destroying
stateful infrastructure** — you have to name the verb:

```sh
cargo run -- check --grant tests/fixtures/grant_names_the_replace.json \
                   --plan  tests/fixtures/harmless_tag_change.json
# ACCEPTED — every effect is inside the grant.
```

And a job cannot hand itself authority its parent never held:

```sh
cargo run -- manifest narrow --parent tests/fixtures/grant_org_parent.json \
                             --child  tests/fixtures/grant_child_mints_rds.json
# REFUSED — the child widens its parent.
#   facet `infra` widens: allow: child claims `aws.rds.delete`,
#   which the parent does not grant (a child manifest may only narrow)
```

And spend is a wall like any other:

```sh
cargo run -- check --grant tests/fixtures/grant_names_the_replace.json \
                   --plan  tests/fixtures/harmless_tag_change.json \
                   --cost  tests/fixtures/cost_over_budget.json
```

```
spend:     USD 412.90 / month against a ceiling of 50.00 (forecast, not a meter)

REFUSED — 1 effect(s) outside the grant:

  spend  [budget]
    at:     aws_db_instance.payments
    reason: predicted monthly spend rises by 412.90, of which
            `aws_db_instance.payments` is 380.00, and the grant's budget is
            50.00 (362.90 over) — this is a ceiling on forecast spend, not a meter
```

On your own plan:

```sh
terraform plan -out=p.tfplan && terraform show -json p.tfplan > plan.json
infracost breakdown --path p.tfplan --format json > cost.json

cargo run -- check --grant env.json --plan plan.json --cost cost.json   # exit 0 or 8
```

Or on a Pulumi stack — same grant file, same command:

```sh
pulumi preview --json > preview.json
cargo run -- check --grant env.json --plan preview.json
```

```sh
cargo run --example compile_plan -- plan.json            # just the effect rows
cargo run --example one_manifest                         # the manifest, end to end
cargo run --example budget_wall                          # the budget, end to end
cargo run --example two_frontends                        # Terraform and Pulumi, side by side
```

Exit codes follow lex-os: `0` allowed, `8` refused, `2` the gate could
not run. The 8-versus-2 distinction is load-bearing — a refusal is a
decision, not a malfunction, and a pipeline that conflates them will
eventually read a broken gate as an approval.

Which is also why **a document that is not a plan is exit 2, never exit
0**. `{"resource_changes": []}` is an empty plan and there is nothing in
it to authorise; a document that merely *omits* `resource_changes` is a
failed `terraform show -json`, a truncated redirect, or another tool's
output, and the gate will not approve what it cannot read. A row with no
`actions` is the same rule one level down: it classifies as unknown, not
as a no-op.

## Where this is

**Milestones 1–3 and 5 of [#1](https://github.com/alpibrusl/lex-iac/issues/1).**
The plan compiles to effect rows ([#2](https://github.com/alpibrusl/lex-iac/issues/2)),
the gate checks them against a grant, refusing what it does not
cover ([#3](https://github.com/alpibrusl/lex-iac/issues/3)), and forecast
spend is charged against the manifest's budget
([#4](https://github.com/alpibrusl/lex-iac/issues/4)).

A grant file is a `lex_os_manifest::Manifest` — one manifest, one
`ManifestId`, one narrowing wall, with `infra` as a facet on it. That
was the acceptance test for
[lex-os#71](https://github.com/alpibrusl/lex-os/issues/71).

Two frontends, one gate: Terraform/OpenTofu plan JSON and
`pulumi preview --json` ([#10](https://github.com/alpibrusl/lex-iac/issues/10)).

Not yet here: attestation, and running the apply itself inside a
perimeter.

## The effect model

A plan compiles to a set of effects. The mapping is mechanical:
`resource_changes[].type` × `actions[]` → `provider.service.verb`,
scoped by the plan address.

```
aws.ecs.update("aws_ecs_service.api")
aws.rds.replace("aws_db_instance.payments")
gcp.sql.replace("google_sql_database_instance.main")
```

Three classes carry reversibility, reusing `lex-os-manifest`'s
`Reversibility` rather than redefining it:

| Verb                                | Class                        |
| ----------------------------------- | ---------------------------- |
| `no-op`, `read`, any data source    | `ReversibleCheap`            |
| `create`, `update`                  | `IrreversibleBounded`        |
| `delete`, `replace` of **stateful** | `IrreversibleConsequential`  |

"Stateful" comes from a small table (databases, buckets, volumes, KMS
keys, DNS zones) — the same idea as the `Reversibility` enum, not a
per-provider plugin system.

### Two frontends, and what that cost

The epic claimed the effect model was not Terraform-shaped. Adding
Pulumi ([#10](https://github.com/alpibrusl/lex-iac/issues/10)) tested
that, and the honest answer is *mostly*.

**What survived unchanged:** `provider.service.verb`, `check`, the
`infra` facet, and the grant file format. One grant governs both tools,
and the refusal for the same overreach is identical word for word —
there is a test asserting exactly that. Better, Pulumi arrives at
`aws.rds.replace` from the *opposite direction*: its types name the
service outright, where Terraform's `aws_db_instance` needed the
`("aws","db") => "rds"` alias. Two spellings meeting on one effect is
the actual evidence the vocabulary is not an artifact of Terraform.

**What did not:** the classification tables were lists of Terraform type
strings, so every Pulumi type missed. Left alone, every Pulumi teardown
would have classified `IrreversibleConsequential` — safe, and useless,
since a gate that refuses every delete whatever the grant says is one
operators route around. They key on `provider.service.kind` now:

```
aws_db_instance              ─┐
                              ├─→  aws.rds.instance
aws:rds/instance:Instance    ─┘
```

The kind is part of the key because service granularity is wrong in the
dangerous direction: `aws.s3.bucket` holds data and
`aws.s3.bucketpolicy` does not.

**Pulumi spells a replacement three ways** — `replace`, plus
`create-replacement` and `delete-replaced` for the same URN. Steps fold
per URN with the worst verb winning, which is the same collapse
`["delete","create"]` already gets on the Terraform side, arrived at
independently.

The frontend is recognised from the document rather than a `--format`
flag: the two shapes are unambiguous, and a flag is one more thing a
pipeline can get wrong. A file carrying *both* marker fields is refused
rather than resolved by precedence — picking one would mean enforcing
half a document on a coin flip.

### Refuse, don't downgrade

A resource type absent from the table is **not** assumed stateless. We
cannot prove a type we have never seen holds no data, so destroying one
is `IrreversibleConsequential`.

Creating one stays bounded, and that is a deliberate judgement rather
than an oversight: escalating every unrecognised resource would refuse
plans wholesale, and the pressure that puts on operators is to widen the
grant until it means nothing — the exact failure this project exists to
prevent. Such rows carry `unknown_type`, so a policy that wants to
escalate can do so explicitly. See `src/classify.rs`.

## The grant manifest

A grant file **is** a `lex_os_manifest::Manifest` — the same JSON
`lex-os run` takes — carrying one extra facet:

```json
{
  "goal": { "description": "rotate the payments API deployment" },
  "grant":  { "filesystem": "ReadOnly", "network": "Allowlist", "exec": "None" },
  "budget": { "wall_clock_secs": 900, "max_commands": 50,
              "max_money_cents": 5000, "max_api_calls": 200 },
  "isolation_floor": "Namespace",
  "facets": {
    "infra": {
      "allow": ["aws.ecs.*", "aws.cloudwatch.*", "aws.iam.read"],
      "scope": { "account": "123456789012", "region": ["eu-west-1"] },
      "currency": "USD"
    }
  }
}
```

Nothing above is this crate's own type. `goal`, `grant`, `budget` and
`isolation_floor` are lex-os's; `infra` is a **facet** — an authority
domain outside the trust lattice — and it sits in lex-os's own
type-erased facet slot, narrowed through that crate's lattice
primitives. What lex-iac contributes is the *rule* for its domain and
the `FacetRegistry` that hands that rule to lex-os. There is one
manifest type, one `ManifestId`, one narrowing wall.

```sh
cargo run --example one_manifest
```

**Allow-only, no deny list.** A deny list does not narrow: a child that
omits one of its parent's deny entries has *widened*, which inverts the
invariant. Since the claim against Sentinel, OPA and Checkov is that we
narrow where they enumerate, shipping a deny list would concede the
argument. A prohibition is the absence of an allow entry.

An allow entry is exactly three segments, `provider.service.verb`, each
a literal or `*`. Two-segment entries like `aws.*` are rejected and warn
loudly rather than being interpreted: a grant whose breadth depends on
how a reader parses it is worse than no grant.

A manifest carrying **no** `infra` facet authorises no infrastructure
change at all — every mutating row is refused, and the refusal is
recorded like any other. A facet that is present but *unreadable* is
different: the gate exits 2 rather than guessing, because neither
"grants nothing" nor "grants everything" is a safe reading of it.

## The four walls

**Narrowing.** Every mutating effect must be admitted by the facet.
Nothing else applies.

**Reversibility.** An effect classified `IrreversibleConsequential` —
`delete` or `replace` of something stateful, or anything on a resource
type this build does not recognise — needs its verb named explicitly. A
wildcard will not do. `aws.rds.*` reads to an operator as "manage RDS",
not "you may delete the production database", and the gate holds it to
the first reading.

**Budget.** The forecast monthly delta is charged against
`budget.max_money_cents`, in integer minor units, and the plan is
refused if it does not fit. Pass `--cost` with the JSON your estimator
already produces (Infracost today).

> **No estimate is not an estimate of zero.**

Without `--cost`, a `create` or `replace` has no known price, and
"nobody measured it" must not read as "it is free". Those rows need
their verb named in the grant — the same explicitness a destructive
verb needs, for its own reason, which the refusal states rather than
conflating:

```
aws.ecs.create  [budget]
  reason: only `aws.ecs.*` admits it, and nothing has priced this change,
          so a wildcard cannot authorise it — supply a cost estimate, or
          name the verb explicitly
```

Two ways out, both deliberate: supply the estimate, or name the verb.
An `update` is *not* escalated this way, though resizing an instance
does cost money — escalating every update would refuse nearly every
plan, and the pressure that puts on operators is to widen the grant
until it means nothing. A real gap, named here rather than papered
over.

`currency` sits on the facet because `max_money_cents` is a bare
integer: nothing in it says which currency, so ¥5000 is not $50, and a
child that redenominated its budget would have widened it. A report in
another currency stops the gate rather than being converted.

**Trust.** A submitter nobody has scored is held to the *narrower*
reading of the same grant: every mutating verb it uses must be named,
no wildcards. Pass `--signer` to say who is asking and `--trusted-keys`
with the keyring `lex producer-trust keyring --min-trust N` writes —
the identical `{"trusted":[…]}` file `lex-os capsule install` already
consumes.

```
aws.ecs.update  [trust]
  reason: only `aws.ecs.*` admits it, and the submitter is not in the
          trusted keyring — name the verb explicitly, or let the
          submitter earn a score
```

> **Trust narrows; it never widens.**

A score waives nothing the manifest did not already allow. All standing
decides is whether a wildcard carries this submitter, and the ceiling
is the manifest either way — a keyring that could admit an effect the
grant does not would be a second source of authority, which is the one
thing this project forbids. Three consequences worth stating:

- **Not consulted is not unknown.** Without `--trusted-keys` nothing is
  consulted and nothing tightens; existing callers are unaffected.
  "We did not ask" and "we asked and they are not on it" are different
  facts, and the log records which.
- **An empty keyring trusts nobody**, the same way an empty allow-list
  grants nothing. Absent evidence is not evidence of absence.
- **The narrower grant is still a grant.** An unscored submitter is not
  locked out; it acts through verbs somebody wrote down.

### Earning it

The keyring is an output of past decisions, not a configuration file:

```sh
lex-iac check --grant env.json --plan plan.json \
    --signer ci@payments --audit-out log.json

lex attest import-apply --audit log.json --gate terraform \
    --accepted plan_accepted --refused plan_refused
lex producer-trust recompute --tool ci@payments
lex producer-trust keyring --min-trust 700 --out trusted.json
```

Both verdicts are promoted, not only acceptances. Producer trust is
`passed / (passed + failed)`, so importing acceptances alone would
score every submitter 1.0 for ever and make the signal worthless.

`--audit-out` writes the `{seq, prev_hash, event, hash}` array
`import-apply` reads. lex-lang knows nothing of this gate's vocabulary,
so a promotable event carries three fields it *does* name —
`artifact_sha256`, `manifest` and `signer` — which is why the plan hash
is spelled `artifact_sha256` in the log while the JSON report still
calls it `plan_sha256`. Without `--signer` the field is absent rather
than invented, and `import-apply` asks for its own.

Every check writes `plan_requested` to a hash-chained log **before** any
wall runs, then `spend_charged` when there is an estimate — whether or
not it fits, because a budget you can only see once it was exceeded is
not a budget anyone can plan against — then `plan_accepted` or
`plan_refused`. That ordering is
lex-os's, and it is why a refusal is exactly as auditable as an
approval. The chain is `lex_os_audit::Chain<E>`, carrying this gate's
own event vocabulary — lex-os made it generic (lex-os#67) so a
downstream gate would not reimplement tamper-evidence.

### Sealing the log

The chain is tamper-*evident* only against someone who cannot recompute
it. Its hashes are **derived from the contents**, so whoever can reach
the file can rewrite a refusal into an acceptance, rebuild every hash,
and hand you a log that verifies perfectly. That is not hypothetical —
it is forty lines of script with no key and no privilege.

`--audit-key-file` seals every entry with Ed25519
([lex-os#54](https://github.com/alpibrusl/lex-os/issues/54)), which is
the part they cannot rebuild:

```sh
lex-iac audit pubkey --key-file audit.key        # the half a verifier needs
lex-iac check … --audit-out log.json --audit-key-file audit.key
lex-iac audit verify --log log.json --trusted-key <public-hex>
```

```
chain:  OK — 3 entries, head sha256:6e3bd809…
seals:  NOT CHECKED — 3 of 3 entries carry one.        # without a key
length: NOT CHECKED — without a checkpoint, entries deleted from the end
        are indistinguishable from entries never written.

REFUSED — the seals do not hold.                        # on a forgery
  audit seal invalid at seq 1: seal does not verify against the entry's
  actual contents
```

`audit verify` reports **three walls separately**, and says `NOT CHECKED`
rather than `OK` for the ones it was given nothing to check with: a log
whose seals nobody checked is not a log whose seals passed, and absence
of a wall has to read as absence.

The third wall is length. The chain catches an edited payload and the
seals catch someone who edits *and* recomputes the hashes; neither can
see a **deletion**, because every entry left after a truncation is
genuine and the chain that remains is intact. Only a commitment made
while the missing entry still existed can contradict that:

```sh
lex-iac check … --audit-out log.json --checkpoint-out cp.json --audit-key-file audit.key
lex-iac audit verify --log log.json --trusted-key <hex> --checkpoint cp.json
```

```
REFUSED — audit checkpoint: chain has 2 entries but was checkpointed at 3
          — 1 entr(y/ies) have been truncated from the tail
```

Keep the checkpoint somewhere the log's editor cannot reach; one stored
beside the log is deleted in the same motion as the entry it would have
testified about.

**What a seal does not do: make `--signer` true.** That flag is a claim
typed on a command line, and nothing upstream of this gate
authenticates who ran `terraform plan` — which is exactly why lex-k8s
takes no such flag and reads the API server's `userInfo.username`
instead ([lex-os#70](https://github.com/alpibrusl/lex-os/issues/70)).
Sealing raises the record from *unattributable and editable* to
*attributable to this gate and tamper-evident*. A real improvement, and
a different claim.

## The approval names the artifact

`check` used to read a plan JSON someone handed it, and `apply` ran
`terraform apply tfplan` against a saved plan named separately. Nothing
connected the two, so the gate could accept plan A while terraform
applied plan B.

The fix is not to check harder — it is to stop having two artifacts.
`--tfplan` takes the **saved binary plan** and derives the JSON from it
with terraform's own `show -json`, so the document the gate reasons over
is a view of the bytes that will be applied:

```sh
lex-iac check --grant payments.json --tfplan tfplan --approval-out approval.json
```

```
plan:      sha256:df0eacf8…
artifact:  sha256:1ff100ee…  (the saved plan this JSON was read from)
ACCEPTED — every effect is inside the grant.
approval:  written to approval.json
```

The approval records the artifact's digest, and a later apply is held to
it:

```
REFUSED — the plan being applied is not the plan that was approved.
  approved: sha256:68f2f1cf…
  on disk:  sha256:516db2ef…
Nothing was applied. The box was never booted.
```

**The case this exists for**: two plans that both pass the gate on their
merits. Nothing is wrong with the second — a re-check would admit it. It
simply is not the one that was approved, and only a digest can tell them
apart.

`--plan <json>` still works for callers deriving the JSON elsewhere.
Those print `artifact: unbound` and cannot write an approval, which is
the honest description of what they hold. `--tfplan` needs terraform on
PATH and a working directory where `init` has been run, because
`show -json` reads the plan through the provider plugins.

## Applying inside the box

The gate decides; something else applies. Milestone 6 makes that
something else a **lex-os microVM whose egress is this grant's own
allowlist**, so a provider that mutates outside its declared plan is
bounded by a wall rather than by the plan's honesty.

```sh
sudo bash demo/build-box.sh          # a guest image with terraform + the planned dir
lex-iac apply --grant payments.json --tfplan tfplan --approval approval.json \
              --box-rootfs demo/assets/box.ext4
```

This has been run, not only described: [`docs/real-box.md`](docs/real-box.md)
records an apply on a KVM host — `perimeter: "firecracker"`,
`security_boundary: true`, `Apply complete! Resources: 1 added` — plus a
substituted artifact being refused before the box booted, and the two
refusals the manifest's own consistency check raised on the way.

**One manifest, two enforcement points.** The grant the gate checks is a
`lex_os_manifest::Manifest`, which is exactly what `lex-os exec` takes —
so the *same file* is passed to both. The egress the gate reasoned about
is the egress the box is confined to, and there is no second declaration
that could drift from the first.

A consequence worth stating: **a grant with `exec: None` cannot apply.**
Applying is executing, and a grant that never said so has authorised a
*decision*, not an action. That is a coherent thing to want, and it is
why `check` and `apply` are separate verbs.

**The state wall.** A plan is a function of configuration *and state*, so a
box that can write state decides what every future plan says — and a gate
reasoning about a plan derived from forged state is reasoning about a
document rather than about reality. The box therefore gets prior state as a
file and no backend credential, emits a *candidate* successor, and the host
decides whether it may become the record:

```sh
lex-iac state commit --plan plan.json \
                     --prior prior.tfstate --candidate candidate.tfstate
```

```
REFUSED — 1 state change(s) the plan did not declare:
  aws_iam_user.backdoor — state records `created` for `aws_iam_user.backdoor`,
                          which the gated plan never mentions
```

The check is **structural, not semantic**: it sees which resources changed
and how, never whether the values written were right — "known after apply"
means a provider-computed id cannot be predicted from the plan. And it is
**one-directional**: it refuses a change the plan did not declare, but does
not require every declared change to have happened, because an apply that
stopped halfway is a legitimate thing to record and refusing it would lose
the evidence of what did happen.

**What this does not yet do is a real account.** Milestone 6 shipped with a
credential-free provider deliberately: it proved the plumbing without
deciding the hard part. A real apply needs provider credentials and state
backend access, and neither can be waved through, because the wall bounds
*where* the box can talk and not *what* it does there.
[`docs/threat-model.md`](docs/threat-model.md) works out what the candidate
designs actually defend against, and reaches two conclusions worth having
before reading further: **no credential design defends against the
operator**, and **state is upstream of the gate itself** — a plan derived
from state the previous run could have forged is a document rather than a
fact ([#17](https://github.com/alpibrusl/lex-iac/issues/17)).

**A refusal never reaches the box.** The gate runs first; on a refusal
`apply` returns the gate's exit code before the box is built, and says
so:

```
REFUSED — 1 effect(s) outside the grant:
  local.file.create  [narrowing]  at: local_file.applied

apply: the gate did not allow this plan, so nothing was executed.
       The box was never booted and terraform was never invoked.
```

Name the effect in the grant and the same plan applies:

```
Apply complete! Resources: 1 added, 0 changed, 0 destroyed.
box exited 0
```

### What the box deliberately cannot do

- **It cannot re-plan.** `apply` receives a *planned document*, not a
  config. Re-planning inside would let it act on something nobody gated.
- **It cannot `init`.** That fetches provider code from a registry, and a
  box allowed to reach one could fetch and run anything. `init` happens
  on the host, and the box receives the plan *and the providers it was
  planned against* — which is also how the real workflow runs: plan in
  CI, apply from the artifact.
- **It holds no credentials**, and `demo/build-box.sh` refuses to plan
  with any provider that would need them. Whether cloud credentials
  belong inside the box or behind a host-side proxy is a real decision
  with real blast radius, and not one a demo should make by defaulting.

### The two chains are linked

`apply` passes the gate's chain head to the box, which records it as its
session's first entry:

```
gate chain: 2 entries, head sha256:225964ae…
box  chain: 7 entries, first entry kind = authorised_by
  domain  lex.iac.audit.v1
  head    sha256:225964ae…
```

A hash cannot be quoted before the thing it commits to exists, so a
session naming one demonstrably began **after** that decision. That is
the whole claim: not that the decision's record survives (the ledger
answers that), and not that this was the only session it authorised.

The head is read back from the chain `check` wrote rather than
recomputed, so a run without `--audit-out` has no persisted decision to
point at, passes no authorisation, and the session correctly claims
none.

## Honest cautions

1. **The gate is exactly as safe as the plan is honest — unless you
   apply in the box.** A provider that mutates outside its declared plan
   — some do, on drift — is invisible to a document reader. `lex-iac
   apply` bounds it at the perimeter instead, which is what milestone 6
   is for. Plain `lex-iac check` followed by an apply on the host still
   has this hole, and always will.
2. **Effect granularity is a judgement call.** Too coarse (`aws.*`) and
   a grant means nothing; too fine and nobody writes one.
   `provider.service.verb` plus scopes is the compromise, and it may
   prove wrong.
3. **Service names are derived, with a small alias table.** Deriving
   mechanically calls RDS `db`, because the resource type is
   `aws_db_instance`. A grant nobody would think to write is a grant
   written too broadly, so a short alias map fixes the genuine
   mismatches. It will need extending.
4. **The budget bounds forecast spend, not actual spend.** Every
   estimator prices the resources it knows, at list rates, ignoring
   commitments, tiering and usage. A reader who treats this as a meter
   will size the budget wrong. It is also monthly, so a plan that is
   cheap per month and enormous per year passes.
5. **A keyring cannot tell "never scored" from "scored badly".** Both
   read as absent, and the gate deliberately does not guess between
   them — but an operator debugging a refusal will want
   `lex producer-trust recompute --tool <id>` to find out which. The
   threshold also lives with whoever exported the keyring, not in the
   manifest, so two teams can disagree about what 700 means.
6. **A seal proves the gate wrote the record, not that the submitter is
   who they said.** `--signer` is asserted by whoever runs the CLI, and
   sealing does not change that — it makes the *record* attributable and
   tamper-evident, which is a different and smaller claim than
   authenticating a submitter. Deletion is answered separately, by
   `--ledger`: one long-lived chain witnessing every decision, so a
   removed log becomes a head with nothing behind it. `audit reconcile`
   checks both directions, since a witnessed head with no file is a
   deletion and a file no witness names is a plant. A ledger kept beside
   the decisions it witnesses still dies to the same `rm -rf` — its
   value is that a checkpoint over it makes that detectable.
7. **Narrowing a facet is subsumption; admitting an effect is not.** A
   parent granting `aws.rds.*` does let a child inherit
   `aws.rds.delete` — the child is genuinely no wider than its parent.
   Neither manifest thereby authorises destroying a database: that is
   the reversibility wall, asked separately. Two questions that read
   alike and are not the same, and the distinction is load-bearing
   enough to be worth stating rather than discovering.

## Develop

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Requires the rustc that `lex-os-manifest`'s dependency chain requires;
CI uses stable.

## License

[EUPL-1.2](LICENSE).
