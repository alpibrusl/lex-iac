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
REFUSED — 1 effect(s) outside the grant:

  aws.rds.replace  [reversibility]
    at:     aws_db_instance.payments
    reason: only `aws.rds.*` admits it, and a wildcard cannot authorise
            destruction of stateful infrastructure — name the verb explicitly

the grant allows:
  aws.ecs.*
  aws.cloudwatch.*
  aws.rds.*

audit: 2 entries, head sha256:d8a89c1d…
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

On your own plan:

```sh
terraform plan -out=p.tfplan && terraform show -json p.tfplan > plan.json
cargo run -- check --grant env.json --plan plan.json     # exit 0 or 8
cargo run --example compile_plan -- plan.json            # just the effect rows
```

Exit codes follow lex-os: `0` allowed, `8` refused, `2` the gate could
not run. The 8-versus-2 distinction is load-bearing — a refusal is a
decision, not a malfunction, and a pipeline that conflates them will
eventually read a broken gate as an approval.

## Where this is

**Milestones 1 and 2 of [#1](https://github.com/alpibrusl/lex-iac/issues/1).**
The plan compiles to effect rows ([#2](https://github.com/alpibrusl/lex-iac/issues/2))
and the gate checks them against a grant, refusing what it does not
cover ([#3](https://github.com/alpibrusl/lex-iac/issues/3)).

Not yet here: budget ([#4](https://github.com/alpibrusl/lex-iac/issues/4)),
attestation, and running the apply itself inside a perimeter.

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

```json
{
  "goal": "rotate the payments API deployment",
  "grant":  { "filesystem": "ReadOnly", "network": "Allowlist", "exec": "None" },
  "budget": { "wall_clock_secs": 900, "max_commands": 50,
              "max_money_cents": 5000, "max_api_calls": 200 },
  "infra": {
    "allow": ["aws.ecs.*", "aws.cloudwatch.*", "aws.iam.read"],
    "scope": { "account": "123456789012", "region": ["eu-west-1"] }
  }
}
```

`grant` and `budget` are lex-os's own types, not restatements. `infra`
is a **facet** — an authority domain outside the trust lattice — and it
implements lex-os's `Facet` trait, narrowing through that crate's
lattice primitives.

**Allow-only, no deny list.** A deny list does not narrow: a child that
omits one of its parent's deny entries has *widened*, which inverts the
invariant. Since the claim against Sentinel, OPA and Checkov is that we
narrow where they enumerate, shipping a deny list would concede the
argument. A prohibition is the absence of an allow entry.

An allow entry is exactly three segments, `provider.service.verb`, each
a literal or `*`. Two-segment entries like `aws.*` are rejected and warn
loudly rather than being interpreted: a grant whose breadth depends on
how a reader parses it is worse than no grant.

## The two walls

**Narrowing.** Every mutating effect must be admitted by the facet.
Nothing else applies.

**Reversibility.** An effect classified `IrreversibleConsequential` —
`delete` or `replace` of something stateful, or anything on a resource
type this build does not recognise — needs its verb named explicitly. A
wildcard will not do. `aws.rds.*` reads to an operator as "manage RDS",
not "you may delete the production database", and the gate holds it to
the first reading.

Every check writes `plan_requested` to a hash-chained log **before** any
wall runs, then `plan_accepted` or `plan_refused`. That ordering is
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
4. **`InfraManifest` should be `lex_os_manifest::Manifest`.** lex-os
   ships the `Facet` trait and the narrowing primitives but has no open
   slot on `Manifest` for a facet it does not itself know about, so this
   repo carries a parallel manifest shape. Tracked by
   [lex-os#71](https://github.com/alpibrusl/lex-os/issues/71); collapsing
   the two is that issue's acceptance test.

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
