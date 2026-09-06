//! A resource identity neither frontend owns (alpibrusl/lex-iac#10).
//!
//! Milestone 1 keyed everything on Terraform's spelling —
//! `aws_db_instance` — because Terraform was the only frontend. Adding
//! Pulumi showed what that cost: its types are `aws:rds/instance:Instance`,
//! so every lookup missed, every resource read as unrecognised, and every
//! teardown classified `IrreversibleConsequential`. Safe, and useless: a
//! gate that refuses every delete regardless of the grant is one operators
//! route around, which is the failure the README warns about.
//!
//! So classification keys on a canonical triple both frontends map onto:
//!
//! ```text
//! aws_db_instance                    ─┐
//!                                     ├─→  aws . rds . instance
//! aws:rds/instance:Instance          ─┘
//!
//! aws_s3_bucket_policy               ─┐
//!                                     ├─→  aws . s3 . bucketpolicy
//! aws:s3/bucketPolicy:BucketPolicy   ─┘
//! ```
//!
//! # Why the kind is part of the key
//!
//! Service granularity alone is wrong in the dangerous direction:
//! `aws_s3_bucket` holds data and `aws_s3_bucket_policy` does not.
//! Keying on `aws.s3` would classify deleting a bucket policy as
//! destroying a bucket — noisy — or worse, calibrate `aws.s3` to the
//! policy and let the bucket through.
//!
//! # Normalisation is deliberately blunt
//!
//! Case and separators are stripped from the kind, because
//! `bucket_policy` and `bucketPolicy` are the same resource named by two
//! conventions. Nothing else is normalised: no stemming, no plural
//! handling, no fuzzy matching. A key that *almost* matches is a
//! classification nobody can predict, and this table decides blast
//! radius.

use serde::{Deserialize, Serialize};

/// What a resource is, independent of which tool declared it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceKey {
    /// `aws`, `gcp`, `azure`, `k8s`, … as a grant spells it.
    pub provider: String,
    /// `rds`, `s3`, `ecs`, …
    pub service: String,
    /// `instance`, `bucket`, `bucketpolicy`, … lowercased with
    /// separators removed.
    pub kind: String,
}

impl ResourceKey {
    pub fn new(provider: &str, service: &str, kind: &str) -> Self {
        ResourceKey {
            provider: provider.to_string(),
            service: service.to_string(),
            kind: normalise(kind),
        }
    }

    /// `provider.service.kind` — the form the tables below are written
    /// in, and what a refusal names.
    pub fn qualified(&self) -> String {
        format!("{}.{}.{}", self.provider, self.service, self.kind)
    }

    /// Read Terraform's `aws_db_instance` spelling.
    ///
    /// The provider is the first segment, the service the second (after
    /// aliasing), and everything after that is the kind. `aws_db_instance`
    /// is `aws` / `rds` / `instance`; `aws_s3_bucket_policy` is `aws` /
    /// `s3` / `bucketpolicy`.
    pub fn from_terraform(resource_type: &str) -> Self {
        let (provider, service) = crate::effect::split_type(resource_type);
        // Re-split to find where the kind starts. `split_type` aliases
        // the service, so the raw second segment is what to skip past.
        let kind = match resource_type.split_once('_') {
            Some((_, rest)) => match rest.split_once('_') {
                Some((_, kind)) => kind,
                // `aws_vpc` — a service with no further kind. The
                // service *is* the resource.
                None => rest,
            },
            None => resource_type,
        };
        ResourceKey::new(&provider, &service, kind)
    }

    /// Read Pulumi's `aws:rds/instance:Instance` spelling.
    ///
    /// The shape is `provider:module/member:Type`, where the module's
    /// first path segment is the service and the member is the kind.
    /// Pulumi names the service explicitly, which is why it needs no
    /// alias table: `aws:rds/instance:Instance` says `rds` where
    /// Terraform's `aws_db_instance` had to be told.
    ///
    /// Degenerate shapes (`azure-native:dbformysql:Server`, a bare
    /// string) degrade to something legible rather than being guessed
    /// at — see the tests.
    pub fn from_pulumi(pulumi_type: &str) -> Self {
        let mut parts = pulumi_type.split(':');
        let provider = parts.next().unwrap_or("");
        let module = parts.next().unwrap_or("");
        let member = parts.next().unwrap_or("");

        let provider = crate::effect::provider_of(provider);
        // `rds/instance` → service `rds`, kind `instance`. Some
        // providers use a flat module (`dbformysql`), in which case the
        // module is the service and the member carries the kind.
        let (service, module_kind) = match module.split_once('/') {
            Some((service, kind)) => (service, kind),
            None => (module, ""),
        };
        // Prefer the member (`Instance`) over the module tail
        // (`instance`) — they normalise to the same thing when both are
        // present, and the member is the one that is always populated.
        let kind = if member.is_empty() {
            module_kind
        } else {
            member
        };

        ResourceKey::new(provider, service, kind)
    }
}

impl std::fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.qualified())
    }
}

/// Lowercase, and drop the separators the two conventions disagree
/// about. `bucket_policy`, `bucketPolicy` and `BucketPolicy` are one
/// resource.
fn normalise(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the module: the two frontends have to land on
    /// the same key, from opposite directions.
    #[test]
    fn both_frontends_agree_on_the_same_resource() {
        for (tf, pulumi, want) in [
            (
                "aws_db_instance",
                "aws:rds/instance:Instance",
                "aws.rds.instance",
            ),
            ("aws_s3_bucket", "aws:s3/bucket:Bucket", "aws.s3.bucket"),
            (
                "aws_s3_bucket_policy",
                "aws:s3/bucketPolicy:BucketPolicy",
                "aws.s3.bucketpolicy",
            ),
            (
                "aws_ecs_service",
                "aws:ecs/service:Service",
                "aws.ecs.service",
            ),
            (
                "aws_dynamodb_table",
                "aws:dynamodb/table:Table",
                "aws.dynamodb.table",
            ),
            (
                "google_sql_database_instance",
                "gcp:sql/databaseInstance:DatabaseInstance",
                "gcp.sql.databaseinstance",
            ),
        ] {
            let from_tf = ResourceKey::from_terraform(tf);
            let from_pulumi = ResourceKey::from_pulumi(pulumi);
            assert_eq!(from_tf.qualified(), want, "terraform: {tf}");
            assert_eq!(from_pulumi.qualified(), want, "pulumi: {pulumi}");
            assert_eq!(
                from_tf, from_pulumi,
                "{tf} and {pulumi} are the same resource and must key alike"
            );
        }
    }

    /// Pulumi names the service; Terraform had to be told. That the two
    /// still meet is the evidence that `provider.service` is not an
    /// artifact of Terraform's naming.
    #[test]
    fn pulumi_needs_no_alias_where_terraform_did() {
        // Terraform reaches `rds` only through the ("aws","db") alias.
        assert_eq!(
            ResourceKey::from_terraform("aws_db_instance").service,
            "rds"
        );
        // Pulumi says it outright.
        assert_eq!(
            ResourceKey::from_pulumi("aws:rds/instance:Instance").service,
            "rds"
        );
    }

    #[test]
    fn separators_and_case_do_not_matter() {
        assert_eq!(normalise("bucket_policy"), "bucketpolicy");
        assert_eq!(normalise("bucketPolicy"), "bucketpolicy");
        assert_eq!(normalise("BucketPolicy"), "bucketpolicy");
        assert_eq!(normalise("v1_beta"), "v1beta");
    }

    /// A service with no further kind: the service *is* the resource.
    #[test]
    fn a_two_segment_terraform_type_keys_on_its_service() {
        let k = ResourceKey::from_terraform("aws_vpc");
        assert_eq!(k.qualified(), "aws.vpc.vpc");
    }

    /// Degenerate shapes degrade legibly rather than being guessed at.
    /// None of these is silently attributed to the wrong service.
    #[test]
    fn odd_shapes_do_not_panic_or_mislead() {
        // A flat Pulumi module.
        assert_eq!(
            ResourceKey::from_pulumi("azure-native:dbformysql:Server").qualified(),
            "azure-native.dbformysql.server"
        );
        // Provider-only, no module.
        assert_eq!(ResourceKey::from_pulumi("aws").qualified(), "aws..");
        assert_eq!(ResourceKey::from_pulumi("").qualified(), "..");
        // A Terraform type with no underscore at all.
        assert_eq!(
            ResourceKey::from_terraform("weird").qualified(),
            "weird..weird"
        );
        // Pulumi's own provider resources.
        assert_eq!(
            ResourceKey::from_pulumi("pulumi:providers:aws").qualified(),
            "pulumi.providers.aws"
        );
    }

    #[test]
    fn google_and_kubernetes_are_renamed_on_both_sides() {
        assert_eq!(
            ResourceKey::from_terraform("google_storage_bucket").provider,
            "gcp"
        );
        assert_eq!(
            ResourceKey::from_pulumi("google-native:storage/v1:Bucket").provider,
            "gcp",
        );
        assert_eq!(
            ResourceKey::from_terraform("kubernetes_secret").provider,
            "k8s"
        );
        assert_eq!(
            ResourceKey::from_pulumi("kubernetes:core/v1:Secret").provider,
            "k8s"
        );
    }
}
