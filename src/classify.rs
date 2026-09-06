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
//! Creates and updates on an unknown type stay `IrreversibleBounded`
//! rather than escalating: a plan that touches one unrecognised resource
//! would otherwise be refused wholesale, and the pressure that puts on
//! operators is to widen the grant until it means nothing — the exact
//! failure this project exists to avoid. The row still carries
//! [`EffectRow::unknown_type`](crate::EffectRow), so a policy that wants
//! to escalate on it can, deliberately.

use lex_os_manifest::Reversibility;

use crate::plan::Verb;

/// Resource types that hold data whose destruction is not recoverable by
/// re-running the plan.
///
/// Deliberately a small, legible table rather than a per-provider plugin
/// system — the same shape as lex-os's `Reversibility`, which is a
/// property of the command, not something the caller asserts.
///
/// Being absent from this list does not mean "stateless"; see
/// [`is_stateful`].
const STATEFUL_TYPES: &[&str] = &[
    // AWS — databases, object stores, volumes, keys, zones.
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "aws_ebs_volume",
    "aws_efs_file_system",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_kms_key",
    "aws_route53_zone",
    "aws_redshift_cluster",
    "aws_docdb_cluster",
    // GCP.
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_bigtable_instance",
    "google_spanner_instance",
    "google_kms_crypto_key",
    "google_dns_managed_zone",
    // Azure.
    "azurerm_storage_account",
    "azurerm_mssql_database",
    "azurerm_postgresql_flexible_server",
    "azurerm_key_vault",
    "azurerm_dns_zone",
    // Kubernetes.
    "kubernetes_persistent_volume",
    "kubernetes_persistent_volume_claim",
    "kubernetes_secret",
];

/// Is this resource type known to hold durable state?
///
/// Returns `true` for anything in [`STATEFUL_TYPES`] **and for anything
/// this build does not recognise at all** — see [`is_known`]. The two
/// cases differ in what they mean, not in how destruction is treated.
pub fn is_stateful(resource_type: &str) -> bool {
    !is_known(resource_type) || STATEFUL_TYPES.contains(&resource_type)
}

/// Resource types this build recognises as stateless, so a table miss is
/// distinguishable from a positive "this is safe to destroy".
///
/// Kept explicit for the same reason the stateful list is: an operator
/// reading a refusal deserves to know whether the gate classified the
/// type or merely failed to recognise it.
const STATELESS_TYPES: &[&str] = &[
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_cloudwatch_log_group",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy_attachment",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_lb",
    "aws_lb_listener",
    "aws_lb_target_group",
    "aws_lambda_function",
    "aws_cloudwatch_metric_alarm",
    "google_cloud_run_service",
    "google_service_account",
    "google_project_iam_member",
    "kubernetes_deployment",
    "kubernetes_service",
    "kubernetes_config_map",
    "kubernetes_ingress_v1",
];

/// Does this build have an opinion about `resource_type` at all?
pub fn is_known(resource_type: &str) -> bool {
    STATEFUL_TYPES.contains(&resource_type) || STATELESS_TYPES.contains(&resource_type)
}

/// Classify one change's blast radius.
///
/// `mode` is the plan's `mode` field: a `data` block reads, so it never
/// rises above `ReversibleCheap` however its actions are spelled.
pub fn classify(resource_type: &str, verb: Verb, mode: &str) -> Reversibility {
    if mode == "data" {
        return Reversibility::ReversibleCheap;
    }
    match verb {
        Verb::NoOp | Verb::Read => Reversibility::ReversibleCheap,
        Verb::Create | Verb::Update => Reversibility::IrreversibleBounded,
        Verb::Delete | Verb::Replace => {
            if is_stateful(resource_type) {
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

    #[test]
    fn destroying_a_known_stateful_type_is_consequential() {
        for verb in [Verb::Delete, Verb::Replace] {
            assert_eq!(
                classify("aws_db_instance", verb, "managed"),
                Reversibility::IrreversibleConsequential
            );
        }
    }

    #[test]
    fn destroying_a_known_stateless_type_is_merely_bounded() {
        assert_eq!(
            classify("aws_ecs_service", Verb::Delete, "managed"),
            Reversibility::IrreversibleBounded
        );
    }

    /// The rule that matters most: a type we have never seen is not
    /// assumed safe to destroy.
    #[test]
    fn destroying_an_unknown_type_is_consequential() {
        assert!(!is_known("acme_widget_cluster"));
        assert!(is_stateful("acme_widget_cluster"));
        assert_eq!(
            classify("acme_widget_cluster", Verb::Delete, "managed"),
            Reversibility::IrreversibleConsequential
        );
        assert_eq!(
            classify("acme_widget_cluster", Verb::Replace, "managed"),
            Reversibility::IrreversibleConsequential
        );
    }

    /// ...but creating one is not escalated, or a single unrecognised
    /// resource would refuse the whole plan and push operators toward
    /// grants that mean nothing.
    #[test]
    fn creating_an_unknown_type_stays_bounded() {
        assert_eq!(
            classify("acme_widget_cluster", Verb::Create, "managed"),
            Reversibility::IrreversibleBounded
        );
    }

    #[test]
    fn an_unreadable_action_list_is_consequential() {
        assert_eq!(
            classify("aws_ecs_service", Verb::Unknown, "managed"),
            Reversibility::IrreversibleConsequential
        );
    }

    #[test]
    fn data_sources_never_rise_above_cheap() {
        assert_eq!(
            classify("aws_db_instance", Verb::Read, "data"),
            Reversibility::ReversibleCheap
        );
        assert_eq!(
            classify("aws_db_instance", Verb::Delete, "data"),
            Reversibility::ReversibleCheap
        );
    }

    #[test]
    fn reads_and_noops_are_cheap() {
        assert_eq!(
            classify("aws_s3_bucket", Verb::NoOp, "managed"),
            Reversibility::ReversibleCheap
        );
        assert_eq!(
            classify("aws_s3_bucket", Verb::Read, "managed"),
            Reversibility::ReversibleCheap
        );
    }
}
