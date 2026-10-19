//! Additive wire compatibility and presence semantics for managed mappings and the policy set descriptor.

use firma_protobuf::v1::{
    ActionMappingRule, ActionMappingSnapshot, PolicyBundle, PolicyBundleCapability,
    PolicyBundleUpdate, PolicySetDescriptor, SidecarCredentials, WatchPolicyBundleRequest,
};
use prost::Message as _;

// Frozen decoder shapes from before mapping snapshots for the extended messages deliberately do not
// use the current bindings: changing an existing tag must not change both sides
// of the compatibility proof. The nested `SidecarCredentials` binding is reused
// because mapping snapshots leave that message untouched; the proof covers the outer field
// additions only.
#[derive(Clone, PartialEq, prost::Message)]
struct LegacyPolicyBundle {
    #[prost(string, tag = "1")]
    version: String,
    #[prost(bytes = "vec", tag = "2")]
    policies: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    entity_schema: Vec<u8>,
    #[prost(uint32, tag = "4")]
    ttl_seconds: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct LegacyWatchRequest {
    #[prost(string, tag = "1")]
    current_version: String,
    #[prost(message, optional, tag = "2")]
    credentials: Option<SidecarCredentials>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct LegacyPolicyBundleUpdate {
    #[prost(message, optional, tag = "1")]
    bundle: Option<PolicyBundle>,
    #[prost(message, optional, tag = "2")]
    updated_at: Option<prost_types::Timestamp>,
}

fn updated_at() -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: 1_700_000_000,
        nanos: 0,
    }
}

fn legacy_bundle() -> LegacyPolicyBundle {
    LegacyPolicyBundle {
        version: "7".to_owned(),
        policies: b"permit".to_vec(),
        entity_schema: b"{}".to_vec(),
        ttl_seconds: 30,
    }
}

fn bundle(mappings: Option<ActionMappingSnapshot>) -> PolicyBundle {
    let legacy = legacy_bundle();
    PolicyBundle {
        version: legacy.version,
        policies: legacy.policies,
        entity_schema: legacy.entity_schema,
        ttl_seconds: legacy.ttl_seconds,
        mappings,
    }
}

#[test]
fn frozen_legacy_bundle_decodes_without_fabricating_mappings() {
    let bytes = b"\x0a\x017\x12\x06permit\x1a\x02{}\x20\x1e";
    let decoded = PolicyBundle::decode(bytes.as_slice()).expect("legacy bundle decodes");
    assert_eq!(decoded, bundle(None));
    assert_eq!(decoded.encode_to_vec(), bytes);
}

#[test]
fn complete_snapshot_roundtrips_and_preserves_the_legacy_bundle_fields() {
    let rules = [
        (
            Some("GET"),
            "api.example.com",
            Some("/v1/items"),
            "code.read",
        ),
        (None, "*.example.com:8443", Some("*"), "code.write"),
        (Some("CONNECT"), "192.0.2.1", None, "code.read"),
        (None, "[2001:db8::1]:8443", None, "code.write"),
    ]
    .into_iter()
    .map(|(method, host, path, action_class)| ActionMappingRule {
        method: method.map(str::to_owned),
        host: host.to_owned(),
        path: path.map(str::to_owned),
        action_class: action_class.to_owned(),
    })
    .collect();
    let current = bundle(Some(ActionMappingSnapshot {
        format_version: 1,
        rules,
        default_protected: true,
    }));
    let bytes = current.encode_to_vec();
    assert_eq!(
        PolicyBundle::decode(bytes.as_slice()).expect("current bundle"),
        current
    );
    assert_eq!(
        LegacyPolicyBundle::decode(bytes.as_slice()).expect("legacy decoder"),
        legacy_bundle()
    );
}

#[test]
fn missing_mappings_and_empty_protected_mappings_remain_distinct_on_the_wire() {
    let absent = bundle(None);
    let empty = bundle(Some(ActionMappingSnapshot {
        format_version: 1,
        rules: Vec::new(),
        default_protected: true,
    }));
    let absent_bytes = absent.encode_to_vec();
    let empty_bytes = empty.encode_to_vec();
    assert_ne!(absent_bytes, empty_bytes);
    assert_eq!(
        PolicyBundle::decode(absent_bytes.as_slice()).expect("absent payload"),
        absent
    );
    assert_eq!(
        PolicyBundle::decode(empty_bytes.as_slice()).expect("empty payload"),
        empty
    );
    assert_eq!(
        LegacyPolicyBundle::decode(empty_bytes.as_slice()).expect("legacy ignores snapshot"),
        legacy_bundle()
    );
}

#[test]
fn optional_matchers_preserve_absence_wildcard_and_invalid_empty_values() {
    // Decoding preserves invalid present-empty values so the consuming validator
    // can reject them, rather than broadening them to unrestricted matchers.
    for (method, path) in [(None, None), (None, Some("*")), (Some(""), Some(""))] {
        let rule = ActionMappingRule {
            method: method.map(str::to_owned),
            host: "example.com".to_owned(),
            path: path.map(str::to_owned),
            action_class: "code.read".to_owned(),
        };
        assert_eq!(
            ActionMappingRule::decode(rule.encode_to_vec().as_slice()).expect("rule decodes"),
            rule
        );
    }
}

#[test]
fn frozen_legacy_subscription_decodes_without_advertising_support() {
    let bytes = b"\x0a\x017\x12\x0b\x0a\x01w\x12\x01s\x1a\x03key";
    let request = WatchPolicyBundleRequest::decode(bytes.as_slice()).expect("legacy subscription");
    assert_eq!(request.current_version, "7");
    assert_eq!(
        request.credentials,
        Some(SidecarCredentials {
            workspace_id: "w".to_owned(),
            sidecar_id: "s".to_owned(),
            pre_shared_key: "key".to_owned(),
        })
    );
    assert_eq!(request.supported_capabilities, Vec::<i32>::new());
    assert_eq!(request.encode_to_vec(), bytes);
}

#[test]
fn capability_advertisement_preserves_unknown_values_and_legacy_authentication() {
    let request = WatchPolicyBundleRequest {
        current_version: "7".to_owned(),
        credentials: Some(SidecarCredentials {
            workspace_id: "w".to_owned(),
            sidecar_id: "s".to_owned(),
            pre_shared_key: "key".to_owned(),
        }),
        supported_capabilities: vec![
            PolicyBundleCapability::Unspecified.into(),
            PolicyBundleCapability::ActionMappingSnapshotV1.into(),
            31_337,
        ],
    };
    let bytes = request.encode_to_vec();
    let decoded = WatchPolicyBundleRequest::decode(bytes.as_slice()).expect("subscription");
    assert_eq!(decoded, request);
    assert_eq!(
        PolicyBundleCapability::try_from(decoded.supported_capabilities[2]),
        Err(prost::UnknownEnumValue(31_337))
    );
    let legacy =
        LegacyWatchRequest::decode(bytes.as_slice()).expect("legacy decoder ignores capability");
    assert_eq!(legacy.current_version, request.current_version);
    assert_eq!(legacy.credentials, request.credentials);
}

#[test]
fn frozen_legacy_bundle_update_decodes_without_fabricating_a_descriptor() {
    let legacy = LegacyPolicyBundleUpdate {
        bundle: Some(bundle(None)),
        updated_at: Some(updated_at()),
    };
    let bytes = legacy.encode_to_vec();

    let decoded = PolicyBundleUpdate::decode(bytes.as_slice()).expect("legacy update decodes");

    assert_eq!(
        decoded,
        PolicyBundleUpdate {
            bundle: Some(bundle(None)),
            updated_at: Some(updated_at()),
            policy_set: None,
        }
    );
    assert_eq!(decoded.encode_to_vec(), bytes);
}

#[test]
fn policy_set_descriptor_roundtrips_and_is_invisible_to_legacy_decoders() {
    let update = PolicyBundleUpdate {
        bundle: Some(bundle(None)),
        updated_at: Some(updated_at()),
        policy_set: Some(PolicySetDescriptor {
            policy_set_id: "pset_01j0000000e008000000000001".to_owned(),
            policy_set_version: 3,
        }),
    };
    let bytes = update.encode_to_vec();

    let roundtrip = PolicyBundleUpdate::decode(bytes.as_slice()).expect("update decodes");
    let legacy =
        LegacyPolicyBundleUpdate::decode(bytes.as_slice()).expect("legacy decoder skips field 3");

    assert_eq!(roundtrip, update);
    assert_eq!(legacy.bundle, update.bundle);
    assert_eq!(legacy.updated_at, update.updated_at);
    assert_ne!(
        legacy.encode_to_vec(),
        bytes,
        "the descriptor occupies bytes a legacy encoder never writes"
    );
}
