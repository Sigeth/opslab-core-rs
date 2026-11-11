//! Rust types of the opslab custom resources.
//!
//! Everything under [`generated`] is produced by `scripts/generate.sh` from the
//! CRDs of [opslab-core-go](https://github.com/Sigeth/opslab-core-go), the
//! source of truth. Never edit it by hand: change the Go types, tag core-go,
//! bump `CORE_GO_VERSION` and regenerate.
//!
//! The binary using this crate must enable exactly one Kubernetes version
//! feature of `k8s-openapi` (e.g. `k8s-openapi = { features = ["v1_34"] }`).

#[allow(clippy::all, missing_docs)]
pub mod generated;

pub use generated::catalogsources::CatalogSource;
pub use generated::challengeinstances::ChallengeInstance;
pub use generated::challenges::Challenge;
pub use generated::checkruns::CheckRun;
pub use generated::platformconfigs::PlatformConfig;

/// Identifiers that change when the project is renamed. Mirrors
/// `pkg/project` in opslab-core-go.
pub mod project {
    /// The (working) project name.
    pub const NAME: &str = "opslab";
    /// Kubernetes API group of all opslab resources.
    pub const API_GROUP: &str = "opslab.io";
    /// API version of the resources in this crate.
    pub const API_VERSION: &str = "opslab.io/v1alpha1";
    /// Prefix of every label and annotation set by opslab.
    pub const LABEL_PREFIX: &str = "opslab.io/";
    /// Namespace holding ChallengeInstances and CheckRuns.
    pub const INSTANCES_NAMESPACE: &str = "opslab-instances";
    /// Name of the only PlatformConfig.
    pub const PLATFORM_CONFIG_NAME: &str = "default";
}

/// Conventions shared with opslab-core-go that are not part of the CRDs.
pub mod conventions {
    /// Container running a pod or sysbox machine, inside the pod named by
    /// the machine status. Mirrors `v1alpha1.MachineContainer`.
    pub const MACHINE_CONTAINER: &str = "machine";
    /// Instructions shown when no other language matches. Mirrors
    /// `challenge.DefaultInstructions`.
    pub const DEFAULT_INSTRUCTIONS: &str = "instructions/en.md";

    /// Key of a package file in a ConfigMap ('/' becomes "__"). Mirrors
    /// `challenge.ConfigMapKey`.
    pub fn config_map_key(path: &str) -> String {
        path.replace('/', "__")
    }
}

#[cfg(test)]
mod tests {
    use kube::Resource;

    use super::generated::challengeinstances::{ChallengeInstanceOwner, ChallengeInstanceSpec};
    use super::*;

    #[test]
    fn config_map_keys() {
        assert_eq!(
            conventions::config_map_key(conventions::DEFAULT_INSTRUCTIONS),
            "instructions__en.md"
        );
    }

    #[test]
    fn resource_metadata_matches_crds() {
        assert_eq!(ChallengeInstance::api_version(&()), project::API_VERSION);
        assert_eq!(ChallengeInstance::plural(&()), "challengeinstances");
        assert_eq!(Challenge::kind(&()), "Challenge");
        assert_eq!(CheckRun::group(&()), project::API_GROUP);
    }

    #[test]
    fn serializes_with_go_field_names() {
        let instance = ChallengeInstance::new(
            "hello-shell-alice",
            ChallengeInstanceSpec {
                challenge: "hello-shell".into(),
                owner: ChallengeInstanceOwner {
                    user_id: "1".into(),
                    display_name: Some("alice".into()),
                },
                expires_at: None,
            },
        );
        let json = serde_json::to_value(&instance).unwrap();
        assert_eq!(json["spec"]["owner"]["userID"], "1");
        assert_eq!(json["spec"]["owner"]["displayName"], "alice");
        assert!(json["spec"].get("expiresAt").is_none());
    }

    #[test]
    fn deserializes_status() {
        let instance: ChallengeInstance = serde_json::from_value(serde_json::json!({
            "apiVersion": "opslab.io/v1alpha1",
            "kind": "ChallengeInstance",
            "metadata": {"name": "x", "namespace": project::INSTANCES_NAMESPACE},
            "spec": {"challenge": "hello-shell", "owner": {"userID": "1"}},
            "status": {"phase": "Ready", "machines": [{"name": "box", "runtime": "pod", "ready": true}]}
        }))
        .unwrap();
        let status = instance.status.unwrap();
        assert_eq!(
            status.phase,
            Some(generated::challengeinstances::ChallengeInstanceStatusPhase::Ready)
        );
        assert!(status.machines.unwrap()[0].ready);
    }
}
