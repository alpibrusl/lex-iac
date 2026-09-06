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
cargo run --example compile_plan -- plan.json            # just the effect rows
cargo run --example one_manifest                         # the manifest, end to end
cargo run --example budget_wall                          # the budget, end to end
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

**Milestones 1–3 of [#1](https://github.com/alpibrusl/lex-iac/issues/1).**
The plan compiles to effect rows ([#2](https://github.com/alpibrusl/lex-iac/issues/2)),
the gate checks them against a grant, refusing what it does not
cover ([#3](https://github.com/alpibrusl/lex-iac/issues/3)), and forecast
spend is charged against the manifest's budget
([#4](https://github.com/alpibrusl/lex-iac/issues/4)).

A grant file is a `lex_os_manifest::Manifest` — one manifest, one
`ManifestId`, one narrowing wall, with `infra` as a facet on it. That
was the acceptance test for
[lex-os#71](https://github.com/alpibrusl/lex-os/issues/71).

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

## The three walls

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

Every check writes `plan_requested` to a hash-chained log **before** any
wall runs, then `spend_charged` when there is an estimate — whether or
not it fits, because a budget you can only see once it was exceeded is
not a budget anyone can plan against — then `plan_accepted` or
`plan_refused`. That ordering is
lex-os's, and it is why a refusal is exactly as auditable as an
approval. The chain is `lex_os_audit::Chain<E>`, carrying this gate's
own event vocabulary — lex-os made it generic (lex-os#67) so a
downstream gate would not reimplement tamper-evidence.

## Honest cautions

1. **The gate is exactly as safe as the plan is honest.** A provider
   that mutates outside its declared plan — some do, on drift — is
   invisible here. Bounding that needs the apply to run inside the
   perimeter, which is the last milestone, not the first.
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
5. **Narrowing a facet is subsumption; admitting an effect is not.** A
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
