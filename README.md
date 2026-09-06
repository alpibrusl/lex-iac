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
cargo run --example compile_plan
```

```
ADDRESS                             EFFECT                        CLASS
aws_ecs_service.api                 aws.ecs.update                bounded
aws_cloudwatch_log_group.api        aws.cloudwatch.update         bounded
aws_db_instance.payments            aws.rds.replace               CONSEQUENTIAL

VERDICT: contains irreversible, consequential changes.
```

That fixture is a plan that reads as a routine tagging change. Two of
its three resources are exactly that. The third destroys and recreates a
production database, and `actions: ["delete","create"]` is the only
place the plan admits it.

On your own plan:

```sh
terraform plan -out=p.tfplan && terraform show -json p.tfplan > plan.json
cargo run --example compile_plan -- plan.json
```

## Where this is

**Milestone 1 of [#1](https://github.com/alpibrusl/lex-iac/issues/1) —
plan JSON → effect rows.** A pure function: no cloud access, no
credentials, no state backend. It compiles a plan to typed effect rows
and classifies each by blast radius. It does **not** yet check them
against a grant, and it refuses nothing — that is
[#3](https://github.com/alpibrusl/lex-iac/issues/3).

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
