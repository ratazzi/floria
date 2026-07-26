use accessfs_core::authz::Enforcement;
use accessfs_core::config::{SECRETS_DIR, SURFACES_DIR};
use accessfs_core::rules::{
    compile_glob, exact_path_glob, ObjectMatch, Rule, RuleOps, SubjectMatch,
    MANAGED_ITEM_PRIORITY, MANAGED_RESOURCE_PRIORITY,
};

/// One catalog/store-managed policy item. The normalized list is diffed when the live catalog
/// changes so semantically identical refreshes do not invalidate grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicyItem {
    pub object: ManagedObject,
    pub enforcement: Enforcement,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedObject {
    Secret { secret_id: String },
    Surface { surface_id: String },
    SshResource { resource_id: String },
}

pub fn normalize_managed_policy(mut items: Vec<ManagedPolicyItem>) -> Vec<ManagedPolicyItem> {
    items.sort_by(|left, right| left.object.cmp(&right.object));
    let mut normalized: Vec<ManagedPolicyItem> = Vec::with_capacity(items.len());
    for item in items {
        if let Some(current) = normalized
            .last_mut()
            .filter(|current| current.object == item.object)
        {
            current.enforcement = stricter(current.enforcement, item.enforcement);
        } else {
            normalized.push(item);
        }
    }
    normalized
}

pub fn managed_rules(items: &[ManagedPolicyItem]) -> Vec<Rule> {
    items
        .iter()
        .map(|item| match &item.object {
            ManagedObject::Secret { secret_id } => Rule {
                id: format!("managed:secret:{secret_id}"),
                priority: MANAGED_ITEM_PRIORITY,
                subject: SubjectMatch::default(),
                object: ObjectMatch::default(),
                path_glob: exact_path_glob(&format!("{SECRETS_DIR}/{secret_id}")),
                ops: RuleOps::READ_WRITE,
                enforcement: item.enforcement,
                enabled: true,
            },
            ManagedObject::Surface { surface_id } => Rule {
                id: format!("managed:surface:{surface_id}"),
                priority: MANAGED_ITEM_PRIORITY,
                subject: SubjectMatch::default(),
                object: ObjectMatch::default(),
                path_glob: exact_path_glob(&format!("{SURFACES_DIR}/{surface_id}")),
                ops: RuleOps::READ_WRITE_SIGN,
                enforcement: item.enforcement,
                enabled: true,
            },
            ManagedObject::SshResource { resource_id } => Rule {
                id: format!("managed:ssh-resource:{resource_id}"),
                priority: MANAGED_RESOURCE_PRIORITY,
                subject: SubjectMatch::default(),
                object: ObjectMatch { resource_id: Some(resource_id.clone()) },
                path_glob: compile_glob(&format!("{SURFACES_DIR}/**"))
                    .expect("`surfaces/**` is a valid glob"),
                ops: RuleOps::SIGN,
                enforcement: item.enforcement,
                enabled: true,
            },
        })
        .collect()
}

fn stricter(left: Enforcement, right: Enforcement) -> Enforcement {
    fn rank(value: Enforcement) -> u8 {
        match value {
            Enforcement::Allow => 0,
            Enforcement::Prompt => 1,
            Enforcement::TouchId => 2,
            Enforcement::Deny => 3,
        }
    }
    if rank(left) >= rank(right) { left } else { right }
}

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_core::authz::Operation;
    use accessfs_core::identity::ProcessIdentity;
    use accessfs_core::rules::{RuleObject, RuleRequest, RuleSet};

    #[test]
    fn normalization_sorts_and_merges_duplicate_objects_by_strictness() {
        let normalized = normalize_managed_policy(vec![
            ManagedPolicyItem {
                object: ManagedObject::Surface { surface_id: "b".to_string() },
                enforcement: Enforcement::Prompt,
            },
            ManagedPolicyItem {
                object: ManagedObject::Secret { secret_id: "a".to_string() },
                enforcement: Enforcement::Allow,
            },
            ManagedPolicyItem {
                object: ManagedObject::Secret { secret_id: "a".to_string() },
                enforcement: Enforcement::TouchId,
            },
        ]);

        assert_eq!(
            normalized,
            vec![
                ManagedPolicyItem {
                    object: ManagedObject::Secret { secret_id: "a".to_string() },
                    enforcement: Enforcement::TouchId,
                },
                ManagedPolicyItem {
                    object: ManagedObject::Surface { surface_id: "b".to_string() },
                    enforcement: Enforcement::Prompt,
                },
            ]
        );
    }

    #[test]
    fn ssh_resource_rule_overrides_its_surface_rule() {
        let items = vec![
            ManagedPolicyItem {
                object: ManagedObject::Surface { surface_id: "agent".to_string() },
                enforcement: Enforcement::TouchId,
            },
            ManagedPolicyItem {
                object: ManagedObject::SshResource { resource_id: "key".to_string() },
                enforcement: Enforcement::Allow,
            },
        ];
        let rules = RuleSet::new(managed_rules(&items));
        let identity = ProcessIdentity::bare(1, 501, 20);
        let request = RuleRequest {
            identity: &identity,
            path: "surfaces/agent",
            repo: None,
            operation: Operation::Sign,
            object: RuleObject { resource_id: Some("key") },
        };

        assert_eq!(
            rules.decide(&request),
            (
                Enforcement::Allow,
                Some("managed:ssh-resource:key".to_string())
            )
        );
    }
}
