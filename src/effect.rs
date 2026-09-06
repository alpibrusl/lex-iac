//! Effect rows: what a plan asks for, in the vocabulary a grant is
//! written in.
//!
//! An effect is `provider.service.verb`, scoped by the resource address:
//!
//! ```text
//! aws.ecs.update("aws_ecs_service.api")
//! aws.s3.delete("aws_s3_bucket.prod_data")
//! gcp.sql.replace("google_sql_database_instance.main")
//! ```
//!
//! The granularity is a judgement call the design doc flags: too coarse
//! (`aws.*`) and a grant means nothing; too fine and nobody writes one.
//! `provider.service.verb` with the address as scope is the compromise —
//! a grant names services and verbs, and scopes carry the rest.

use serde::{Deserialize, Serialize};

use crate::plan::Verb;

/// One authority a plan requires.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Effect {
    /// `aws`, `gcp`, `azure`, `k8s`, or the raw prefix when unrecognised.
    pub provider: String,
    /// `ecs`, `s3`, `rds`, … derived from the resource type.
    pub service: String,
    pub verb: Verb,
    /// The plan address this came from — the scope a grant can pin to.
    pub scope: String,
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}(\"{}\")",
            self.provider, self.service, self.verb, self.scope
        )
    }
}

/// Map a Terraform provider prefix to the name grants are written with.
///
/// `google_*` becomes `gcp` because that is what an operator writes in a
/// grant and what the design doc's examples use; the rest are already
/// the names people say.
fn provider_of(prefix: &str) -> &str {
    match prefix {
        "google" => "gcp",
        "azurerm" => "azure",
        "kubernetes" => "k8s",
        other => other,
    }
}

/// Service-name aliases where the provider's resource naming and the
/// service people write in a grant disagree.
///
/// `aws_db_instance` is RDS. Deriving mechanically would yield
/// `aws.db.*`, which nobody would think to grant — and a grant that does
/// not match how people name the service is a grant that gets written
/// too broadly. Kept to genuine mismatches; this is not a place to
/// re-spell every service.
fn service_alias(provider: &str, service: &str) -> &'static str {
    match (provider, service) {
        ("aws", "db") => "rds",
        ("aws", "lb") => "elb",
        ("aws", "cloudwatch") => "cloudwatch",
        _ => "",
    }
}

/// Split a resource type into `(provider, service)`.
///
/// `aws_s3_bucket` → `("aws", "s3")`, `google_sql_database_instance` →
/// `("gcp", "sql")`. A type with no underscore has no service to speak
/// of and yields the whole string as the provider with an empty service,
/// which downstream renders as `<type>..<verb>` — legible, and never
/// silently attributed to the wrong service.
pub fn split_type(resource_type: &str) -> (String, String) {
    match resource_type.split_once('_') {
        Some((prefix, rest)) => {
            let provider = provider_of(prefix);
            let service = rest.split('_').next().unwrap_or("");
            let aliased = service_alias(provider, service);
            let service = if aliased.is_empty() { service } else { aliased };
            (provider.to_string(), service.to_string())
        }
        None => (resource_type.to_string(), String::new()),
    }
}

impl Effect {
    pub fn new(resource_type: &str, verb: Verb, scope: impl Into<String>) -> Self {
        let (provider, service) = split_type(resource_type);
        Effect {
            provider,
            service,
            verb,
            scope: scope.into(),
        }
    }

    /// `provider.service.verb`, without the scope — the form a grant
    /// entry matches against.
    pub fn qualified(&self) -> String {
        format!("{}.{}.{}", self.provider, self.service, self.verb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_split_into_provider_and_service() {
        assert_eq!(split_type("aws_s3_bucket"), ("aws".into(), "s3".into()));
        assert_eq!(split_type("aws_ecs_service"), ("aws".into(), "ecs".into()));
        assert_eq!(split_type("aws_iam_role"), ("aws".into(), "iam".into()));
    }

    #[test]
    fn google_becomes_gcp_and_kubernetes_becomes_k8s() {
        assert_eq!(
            split_type("google_sql_database_instance"),
            ("gcp".into(), "sql".into())
        );
        assert_eq!(
            split_type("kubernetes_deployment"),
            ("k8s".into(), "deployment".into())
        );
        assert_eq!(
            split_type("azurerm_storage_account"),
            ("azure".into(), "storage".into())
        );
    }

    /// The mechanical split would call RDS `db`, which is not what
    /// anyone writes in a grant.
    #[test]
    fn service_aliases_match_how_grants_are_written() {
        assert_eq!(
            split_type("aws_db_instance"),
            ("aws".into(), "rds".into()),
            "aws_db_instance is RDS"
        );
    }

    #[test]
    fn a_type_without_an_underscore_does_not_guess_a_service() {
        assert_eq!(split_type("weird"), ("weird".into(), "".into()));
    }

    #[test]
    fn effects_render_the_way_grants_are_written() {
        let e = Effect::new("aws_s3_bucket", Verb::Delete, "aws_s3_bucket.prod");
        assert_eq!(e.to_string(), "aws.s3.delete(\"aws_s3_bucket.prod\")");
        assert_eq!(e.qualified(), "aws.s3.delete");
    }
}
