//! The provenance wall: which providers a plan may draw on.
//!
//! Distinct from every other wall here because it answers a different
//! question. The others ask *may this run do that*. This one asks
//! *whose code is this run executing* — a provider is not a library the
//! run links against, it is a binary Terraform downloads and runs, and
//! hands the credentials to.
//!
//! The rules that need pinning are the ones a reader would get wrong:
//! an empty list means "no policy declared", not "nothing allowed"; a
//! child may not empty a list its parent set; and a row whose provider
//! the gate cannot read is refused rather than admitted, or the policy
//! would be decorative for exactly the plans that skip it.

use lex_iac::{check, Manifest, Verdict, Wall};

fn manifest(providers: &str, allow: &str) -> Manifest {
    Manifest::from_json(&format!(
        r#"{{
          "goal": {{"description":"g","done_signal":null}},
          "grant": {{"filesystem":"ReadOnly","network":"None","exec":"Sandboxed"}},
          "budget": {{"wall_clock_secs":900,"max_commands":50,
                      "max_money_cents":100000,"max_api_calls":10}},
          "isolation_floor":"Namespace","egress":[],"actuation":null,
          "facets": {{"infra": {{"allow": [{allow}]{providers}}}}}
        }}"#
    ))
    .expect("manifest fixture must parse")
}

/// A plan that creates one Hetzner server — the provider actually in use.
fn plan(provider: &str) -> String {
    format!(
        r#"{{"format_version":"1.2","terraform_version":"1.9.0",
             "resource_changes":[
               {{"address":"hcloud_server.web","type":"hcloud_server","name":"web",
                "mode":"managed","provider_name":"{provider}",
                "change":{{"actions":["create"]}}}}]}}"#
    )
}

fn verdict(m: &Manifest, plan_src: &str) -> Verdict {
    check(plan_src, m, None, None)
        .expect("the gate must be able to read these fixtures")
        .verdict
}

const HCLOUD: &str = "registry.terraform.io/hetznercloud/hcloud";

#[test]
fn a_named_provider_is_admitted() {
    let m = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    assert!(
        verdict(&m, &plan(HCLOUD)).allowed(),
        "the short form names the public registry"
    );
}

/// The case the wall exists for: the plan is fine on every other axis —
/// the verb is granted, it is within budget — and draws on a provider
/// nobody approved.
#[test]
fn a_provider_the_mandate_does_not_name_is_refused() {
    let m = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    let v = verdict(&m, &plan("registry.terraform.io/evilcorp/hcloud"));
    match v {
        Verdict::Deny { first, .. } => {
            assert_eq!(first.wall, Wall::Provenance);
            assert!(first.reason.contains("evilcorp"), "{}", first.reason);
        }
        Verdict::Allow => panic!("an unnamed provider must be refused"),
    }
}

/// The host is part of the identity. `team/thing` on a private registry
/// is different code by different people from `team/thing` on the public
/// one, and a provenance check that conflated them would be worse than
/// none.
#[test]
fn the_registry_host_is_part_of_the_provider_identity() {
    let m = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    assert!(
        !verdict(&m, &plan("tf.internal.example/hetznercloud/hcloud")).allowed(),
        "a same-named provider from another registry is not the same provider"
    );
}

#[test]
fn a_private_registry_can_be_named_in_full() {
    let m = manifest(
        r#", "providers": ["tf.internal.example/team/aws"]"#,
        r#""hcloud.server.create""#,
    );
    assert!(verdict(&m, &plan("tf.internal.example/team/aws")).allowed());
}

/// Silence is not a refusal. A mandate that declares no provider policy
/// admits the plan — the alternative reading refuses every plan ever
/// written, which is why `allow`'s "empty grants nothing" is the wrong
/// rule for a provenance list.
#[test]
fn no_provider_policy_admits_the_plan() {
    let m = manifest("", r#""hcloud.server.create""#);
    assert!(verdict(&m, &plan(HCLOUD)).allowed());
}

/// ...and the same silence must not become a way to smuggle anything
/// through: with no policy, an unknown provider is admitted too. That is
/// the honest consequence, and pinning it here stops someone "fixing"
/// the empty case into a refusal without noticing what it costs.
#[test]
fn no_provider_policy_means_no_provider_check_at_all() {
    let m = manifest("", r#""hcloud.server.create""#);
    assert!(verdict(&m, &plan("registry.terraform.io/evilcorp/hcloud")).allowed());
}

/// A plan that does not say which provider owns a row cannot be held to
/// a provider policy. Admitting it would make the policy decorative for
/// exactly the plans that omit the field.
#[test]
fn a_row_with_no_provider_is_refused_when_a_policy_exists() {
    let m = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    let v = verdict(&m, &plan(""));
    match v {
        Verdict::Deny { first, .. } => assert_eq!(first.wall, Wall::Unreadable),
        Verdict::Allow => panic!("an unreadable provider must not pass a provider policy"),
    }
}

#[test]
fn a_child_may_narrow_the_provider_list() {
    let parent = manifest(
        r#", "providers": ["hetznercloud/hcloud", "hashicorp/random"]"#,
        r#""hcloud.server.create""#,
    );
    let child = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    assert!(lex_iac::narrow(&parent, &child).is_ok());
}

/// The asymmetry worth pinning. An empty list means "no policy", so
/// emptying one *removes* a constraint — that is a widening, however
/// much it looks like subtraction.
#[test]
fn a_child_may_not_empty_a_list_its_parent_set() {
    let parent = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    let child = manifest("", r#""hcloud.server.create""#);
    let err = lex_iac::narrow(&parent, &child).expect_err("emptying the list widens it");
    assert!(
        format!("{err}").contains("providers"),
        "the refusal must say which field: {err}"
    );
}

/// The other direction: a parent that declared no policy has not
/// granted "any provider", it has declined to decide — so a child may
/// decide, and that is a tightening.
#[test]
fn a_child_may_add_a_policy_its_parent_left_open() {
    let parent = manifest("", r#""hcloud.server.create""#);
    let child = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    assert!(lex_iac::narrow(&parent, &child).is_ok());
}

#[test]
fn a_child_may_not_claim_a_provider_the_parent_never_granted() {
    let parent = manifest(
        r#", "providers": ["hetznercloud/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    let child = manifest(
        r#", "providers": ["evilcorp/hcloud"]"#,
        r#""hcloud.server.create""#,
    );
    assert!(lex_iac::narrow(&parent, &child).is_err());
}
