//! Which resource types hold state, and what that makes a change to them.
//!
//! This is the safety-bearing half of the compiler. Everything else is
//! transcription; this decides blast radius.
//!
//! The rule, following `lex-os-manifest`'s `Reversibility`:
//!
//! | verb                              | class                          |
//! | --------------------------------- | ------------------------------ |
//! | `no-op`, `read`                   | `ReversibleCheap`              |
//! | `create`, `update` (any type)     | `IrreversibleBounded`          |
//! | `delete`, `replace` of *stateful* | `IrreversibleConsequential`    |
//! | anything on an *unknown* type     | treated as stateful            |
//!
//! # Refuse, don't downgrade
//!
//! A resource type absent from the table below is **not** assumed
//! stateless. We cannot prove a type we have never seen holds no data,
//! so destroying one is classified `IrreversibleConsequential` — which
//! `lex-os-manifest` refuses by construction unless the grant bounds it.
//! A table miss must never read as "probably fine".
//!
//! # Keyed on the resource, not on Terraform's spelling
//!
//! The tables below were once lists of Terraform type strings. Adding
//! Pulumi (alpibrusl/lex-iac#10) showed the cost: `aws:rds/instance:Instance`
//! matched nothing, so every Pulumi resource read as unrecognised and
//! every teardown classified consequential. Safe, and useless — a gate
//! that refuses every delete whatever the grant says is one operators
//! route around.
//!
//! So they key on [`ResourceKey`] — `provider.service.kind` — which both
//! frontends map onto from opposite directions. The kind is part of the
//! key because service granularity is wrong in the dangerous direction:
//! `aws.s3.bucket` holds data and `aws.s3.bucketpolicy` does not.
//!
//! Creates and updates on an unknown type stay `IrreversibleBounded`
//! rather than escalating: a plan that touches one unrecognised resource
//! would otherwise be refused wholesale, and the pressure that puts on
//! operators is to widen the grant until it means nothing — the exact
//! failure this project exists to avoid. The row still carries
//! [`EffectRow::unknown_type`](crate::EffectRow), so a policy that wants
//! to escalate on it can, deliberately.

use lex_os_manifest::Reversibility;

use crate::plan::Verb;
use crate::resource::ResourceKey;

/// Resource types that hold data whose destruction is not recoverable by
/// re-running the plan.
///
/// Deliberately a small, legible table rather than a per-provider plugin
/// system — the same shape as lex-os's `Reversibility`, which is a
/// property of the command, not something the caller asserts.
///
/// Being absent from this list does not mean "stateless"; see
/// [`is_stateful`].
const STATEFUL: &[&str] = &[
    // AWS — databases, object stores, volumes, keys, zones.
    "aws.rds.instance",
    "aws.rds.cluster",
    "aws.rds.clusterinstance",
    "aws.dynamodb.table",
    "aws.s3.bucket",
    "aws.ebs.volume",
    "aws.efs.filesystem",
    "aws.elasticache.cluster",
    "aws.elasticache.replicationgroup",
    "aws.kms.key",
    "aws.route53.zone",
    "aws.redshift.cluster",
    "aws.docdb.cluster",
    // GCP.
    "gcp.sql.databaseinstance",
    "gcp.storage.bucket",
    "gcp.bigtable.instance",
    "gcp.spanner.instance",
    "gcp.kms.cryptokey",
    "gcp.dns.managedzone",
    // Azure.
    "azure.storage.account",
    "azure.mssql.database",
    "azure.postgresql.flexibleserver",
    "azure.keyvault.keyvault",
    "azure.dns.zone",
    // Kubernetes.
    "k8s.persistent.volume",
    "k8s.persistent.volumeclaim",
    "k8s.secret.secret",
];

/// Is this resource type known to hold durable state?
///
/// Returns `true` for anything in [`STATEFUL_TYPES`] **and for anything
/// this build does not recognise at all** — see [`is_known`]. The two
/// cases differ in what they mean, not in how destruction is treated.
pub fn is_stateful(key: &ResourceKey) -> bool {
    let q = key.qualified();
    !is_known(key) || STATEFUL.contains(&q.as_str())
}

/// Resource types this build recognises as stateless, so a table miss is
/// distinguishable from a positive "this is safe to destroy".
///
/// Kept explicit for the same reason the stateful list is: an operator
/// reading a refusal deserves to know whether the gate classified the
/// type or merely failed to recognise it.
const STATELESS: &[&str] = &[
    "aws.ecs.service",
    "aws.ecs.taskdefinition",
    "aws.cloudwatch.loggroup",
    "aws.iam.role",
    "aws.iam.policy",
    "aws.iam.rolepolicyattachment",
    "aws.security.group",
    "aws.security.grouprule",
    "aws.elb.lb",
    "aws.elb.listener",
    "aws.elb.targetgroup",
    "aws.lambda.function",
    "aws.cloudwatch.metricalarm",
    "aws.s3.bucketpolicy",
    "gcp.cloud.runservice",
    "gcp.service.account",
    "gcp.project.iammember",
    "k8s.deployment.deployment",
    "k8s.service.service",
    "k8s.config.map",
    "k8s.ingress.v1",
];

/// Does this build have an opinion about `resource_type` at all?
pub fn is_known(key: &ResourceKey) -> bool {
    let q = key.qualified();
    STATEFUL.contains(&q.as_str()) || STATELESS.contains(&q.as_str())
}

/// Classify one change's blast radius.
///
/// `mode` is the plan's `mode` field: a `data` block reads, so it never
/// rises above `ReversibleCheap` however its actions are spelled.
pub fn classify(key: &ResourceKey, verb: Verb, mode: &str) -> Reversibility {
    if mode == "data" {
        return Reversibility::ReversibleCheap;
    }
    match verb {
        Verb::NoOp | Verb::Read => Reversibility::ReversibleCheap,
        Verb::Create | Verb::Update => Reversibility::IrreversibleBounded,
        Verb::Delete | Verb::Replace => {
            if is_stateful(key) {
                Reversibility::IrreversibleConsequential
            } else {
                Reversibility::IrreversibleBounded
            }
        }
        // An actions array we cannot read is not a licence to guess.
        Verb::Unknown => Reversibility::IrreversibleConsequential,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tables are canonical now, but these tests are written in
    /// Terraform's spelling on purpose: it is the frontend that had to
    /// be re-keyed, so it is the one worth pinning.
    fn tf(resource_type: &str) -> ResourceKey {
        ResourceKey::from_terraform(resource_type)
    }

    #[test]
    fn destroying_a_known_stateful_type_is_consequential() {
        for verb in [Verb::Delete, Verb::Replace] {
            assert_eq!(
                classify(&tf("aws_db_instance"), verb, "managed"),
                Reversibility::IrreversibleConsequential
            );
        }
    }

    #[test]
    fn destroying_a_known_stateless_type_is_merely_bounded() {
        assert_eq!(
            classify(&tf("aws_ecs_service"), Verb::Delete, "managed"),
            Reversibility::IrreversibleBounded
        );
    }

    /// The rule that matters most: a type we have never seen is not
    /// assumed safe to destroy.
    #[test]
    fn destroying_an_unknown_type_is_consequential() {
        assert!(!is_known(&tf("acme_widget_cluster")));
        assert!(is_stateful(&tf("acme_widget_cluster")));
        assert_eq!(
            classify(&tf("acme_widget_cluster"), Verb::Delete, "managed"),
            Reversibility::IrreversibleConsequential
        );
        assert_eq!(
            classify(&tf("acme_widget_cluster"), Verb::Replace, "managed"),
            Reversibility::IrreversibleConsequential
        );
    }

    /// ...but creating one is not escalated, or a single unrecognised
    /// resource would refuse the whole plan and push operators toward
    /// grants that mean nothing.
    #[test]
    fn creating_an_unknown_type_stays_bounded() {
        assert_eq!(
            classify(&tf("acme_widget_cluster"), Verb::Create, "managed"),
            Reversibility::IrreversibleBounded
        );
    }

    #[test]
    fn an_unreadable_action_list_is_consequential() {
        assert_eq!(
            classify(&tf("aws_ecs_service"), Verb::Unknown, "managed"),
            Reversibility::IrreversibleConsequential
        );
    }

    #[test]
    fn data_sources_never_rise_above_cheap() {
        assert_eq!(
            classify(&tf("aws_db_instance"), Verb::Read, "data"),
            Reversibility::ReversibleCheap
        );
        assert_eq!(
            classify(&tf("aws_db_instance"), Verb::Delete, "data"),
            Reversibility::ReversibleCheap
        );
    }

    #[test]
    fn reads_and_noops_are_cheap() {
        assert_eq!(
            classify(&tf("aws_s3_bucket"), Verb::NoOp, "managed"),
            Reversibility::ReversibleCheap
        );
        assert_eq!(
            classify(&tf("aws_s3_bucket"), Verb::Read, "managed"),
            Reversibility::ReversibleCheap
        );
    }
}
