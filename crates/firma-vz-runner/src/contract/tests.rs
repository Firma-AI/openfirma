use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use crate::test_utils::{valid_contract_json, valid_contract_json_without_artifacts};
use crate::vm::VmPlan;

use super::{
    Contract, ContractDocument, ContractValidationError, ContractValidationLimits, InvariantName,
};

const SHARED_V2_CONTRACT_FIXTURE: &str =
    include_str!("../../../../tests/fixtures/vz-guest-launch-v2.json");
const SHARED_V2_CONTRACT_ROOT: &str = "/openfirma-contract-v2";

#[test]
fn accepts_shared_producer_v2_contract_and_preserves_custody() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let contract_path = write_shared_v2_contract(temp.path())?;
    let contract = ContractDocument::read_from_path(&contract_path)?.validate()?;
    let shims = contract
        .secret_shims()
        .ok_or_else(|| anyhow::anyhow!("shared v2 fixture must contain secret_shims"))?;

    assert_eq!(contract.version(), 2);
    assert_eq!(shims.guest_target_triple(), "x86_64-unknown-linux-musl");
    assert_eq!(shims.provider_names(), &["op", "vault"]);
    assert_eq!(shims.broker_vsock_port(), 18_083);
    assert_eq!(
        shims.shim_share_directory(),
        temp.path().join("sensitive/secret-shims")
    );
    assert_eq!(
        shims.broker_socket_path(),
        temp.path().join("sensitive/broker.sock")
    );

    let writable_sources = std::iter::once(contract.runtime_dir())
        .chain(
            contract
                .mounts()
                .iter()
                .filter(|mount| !mount.read_only())
                .map(super::Mount::source),
        )
        .collect::<Vec<_>>();
    for writable in writable_sources {
        for sensitive in [shims.shim_share_directory(), shims.broker_socket_path()] {
            assert!(
                !writable.starts_with(sensitive) && !sensitive.starts_with(writable),
                "sensitive path {} must be disjoint from writable share {}",
                sensitive.display(),
                writable.display()
            );
        }
    }

    let plan = VmPlan::from_contract(&contract)?;
    let shim_share = plan
        .directory_shares
        .iter()
        .find(|share| share.name == "secret-shims")
        .ok_or_else(|| anyhow::anyhow!("VM plan must contain the secret shim share"))?;
    assert!(shim_share.read_only);
    assert_eq!(
        shim_share.source,
        std::fs::canonicalize(temp.path().join("sensitive/secret-shims"))?
    );
    assert_eq!(
        plan.broker
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VM plan must contain the broker bridge"))?
            .socket_path,
        std::fs::canonicalize(temp.path().join("sensitive/broker.sock"))?
    );

    Ok(())
}

#[test]
fn validates_contract_v2() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let json = valid_contract_json(temp.path())?;
    let contract = parse_contract(&json)?;

    assert_eq!(contract.version(), 2);
    assert_eq!(
        contract.sandbox_id().to_string(),
        "sbx_01j0000000e008000000000001"
    );

    Ok(())
}

#[test]
fn rejects_unknown_contract_fields_during_parse() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json.as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("contract json must be object"))?
        .insert("new_field".to_string(), json!(true));

    let error = parse_contract_document(&json);

    assert!(error.is_err());
    Ok(())
}

#[test]
fn rejects_malformed_contract_json_fixture() {
    let error = ContractDocument::parse_from_slice(
        Path::new("malformed-contract.json"),
        br#"{"version": 1,"#,
    );

    assert!(error.is_err());
}

#[test]
fn rejects_missing_required_contract_fields() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["guest"]
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("guest must be object"))?
        .remove("rootfs");

    let error = parse_contract_document(&json);

    assert!(error.is_err());
    Ok(())
}

#[test]
fn rejects_unknown_nested_contract_fields() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["guest"]["unexpected"] = json!(true);

    let error = parse_contract_document(&json);

    assert!(error.is_err());
    Ok(())
}

#[test]
fn rejects_unsupported_network_mode_field() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["network"]["mode"] = json!("nat");

    let error = parse_contract_document(&json);

    assert!(error.is_err());
    Ok(())
}

#[test]
fn rejects_relative_contract_paths() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json_without_artifacts(temp.path())?;
    json["runtime_dir"] = json!("runtime");
    let document = parse_contract_document(&json)?;

    let error = document.validate_with_file_checker(|_| true);

    assert!(matches!(
        error,
        Err(ContractValidationError::RelativePath { field: "runtime_dir", path })
            if path.as_path() == Path::new("runtime")
    ));
    Ok(())
}

#[test]
fn rejects_relative_guest_mount_targets() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json_without_artifacts(temp.path())?;
    json["mounts"][0]["target"] = json!("workspace");
    let document = parse_contract_document(&json)?;

    let error = document.validate_with_file_checker(|_| true);

    assert!(matches!(
        error,
        Err(ContractValidationError::RelativePath { field: "mount.target", path })
            if path.as_path() == Path::new("workspace")
    ));

    Ok(())
}

#[test]
fn rejects_missing_guest_artifact_files() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let json = valid_contract_json_without_artifacts(temp.path())?;
    let document = parse_contract_document(&json)?;

    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::MissingFile {
            field: "guest.kernel",
            path,
        }) if path == temp.path().join("vmlinuz")
    ));
    Ok(())
}

#[test]
fn rejects_capability_token_in_env() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["command"]["env"]["FIRMA_CAPABILITY_TOKEN"] = json!("secret");
    let document = parse_contract_document(&json)?;

    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::SecretEnvSerialized {
            key: "FIRMA_CAPABILITY_TOKEN"
        })
    ));
    Ok(())
}

#[test]
fn accepts_noninteractive_terminal_metadata() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["term"] = json!("xterm-256color");
    json["terminal"]["rows"] = json!(40);
    json["terminal"]["cols"] = json!(120);

    let contract = parse_contract(&json)?;

    assert!(contract.terminal().interactive());
    assert!(!contract.terminal().pty());
    assert_eq!(contract.terminal().pty_vsock_port(), None);
    assert_eq!(contract.terminal().pty_control_vsock_port(), None);
    assert_eq!(contract.terminal().term(), Some("xterm-256color"));
    assert_eq!(contract.terminal().rows(), Some(40));
    assert_eq!(contract.terminal().cols(), Some(120));

    Ok(())
}

#[test]
fn accepts_pty_terminal_with_dedicated_vsock_ports() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_vsock_port"] = json!(18081);
    json["terminal"]["pty_control_vsock_port"] = json!(18082);

    let contract = parse_contract(&json)?;

    assert!(contract.terminal().interactive());
    assert!(contract.terminal().pty());
    assert_eq!(contract.terminal().pty_vsock_port(), Some(18081));
    assert_eq!(contract.terminal().pty_control_vsock_port(), Some(18082));

    Ok(())
}

#[test]
fn rejects_pty_terminal_without_vsock_port() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_control_vsock_port"] = json!(18082);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyRequiresVsockPort)
    ));

    Ok(())
}

#[test]
fn rejects_pty_terminal_without_control_vsock_port() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_vsock_port"] = json!(18081);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyRequiresControlVsockPort)
    ));

    Ok(())
}

#[test]
fn rejects_pty_terminal_without_interactive_mode() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_vsock_port"] = json!(18081);
    json["terminal"]["pty_control_vsock_port"] = json!(18082);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyRequiresInteractive)
    ));

    Ok(())
}

#[test]
fn rejects_pty_ports_without_pty() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["pty_vsock_port"] = json!(18081);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyPortRequiresPty)
    ));

    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["pty_control_vsock_port"] = json!(18082);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyControlPortRequiresPty)
    ));

    Ok(())
}

#[test]
fn rejects_pty_ports_reusing_network_or_each_other() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_vsock_port"] = json!(18080);
    json["terminal"]["pty_control_vsock_port"] = json!(18082);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyPortConflictsWithSidecar)
    ));

    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_vsock_port"] = json!(18081);
    json["terminal"]["pty_control_vsock_port"] = json!(18080);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyControlPortConflictsWithSidecar)
    ));

    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);
    json["terminal"]["pty_vsock_port"] = json!(18081);
    json["terminal"]["pty_control_vsock_port"] = json!(18081);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::TerminalPtyControlPortConflictsWithDataPort)
    ));

    Ok(())
}

#[test]
fn rejects_invalid_terminal_dimensions() -> Result<()> {
    for field in ["rows", "cols"] {
        let temp = tempfile::tempdir()?;
        let mut json = valid_contract_json(temp.path())?;
        json["terminal"][field] = json!(0);

        let document = parse_contract_document(&json)?;
        let error = document.validate();
        let expected = if field == "rows" {
            "terminal.rows"
        } else {
            "terminal.cols"
        };

        assert!(matches!(
            error,
            Err(ContractValidationError::ZeroTerminalDimension { field }) if field == expected
        ));
    }

    Ok(())
}

#[test]
fn rejects_missing_required_invariant() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    let invariants = json["invariants"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("invariants must be array"))?;
    invariants.retain(|invariant| invariant["name"] != "dns_confined");
    let document = parse_contract_document(&json)?;

    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::MissingInvariant {
            name: InvariantName::DnsConfined
        })
    ));
    Ok(())
}

#[test]
fn rejects_non_loopback_guest_proxy() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["network"]["guest_http_proxy_addr"] = json!("10.0.0.2:18080");
    let document = parse_contract_document(&json)?;

    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::NonLoopbackSocketAddr {
            field: "network.guest_http_proxy_addr",
            value,
        }) if value == "10.0.0.2:18080"
    ));

    Ok(())
}

#[test]
fn rejects_direct_network_devices() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["network"]["direct_network_devices_allowed"] = json!(true);
    let document = parse_contract_document(&json)?;

    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::DirectNetworkDevicesAllowed)
    ));

    Ok(())
}

#[test]
fn accepts_complete_secret_shims_contract() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    add_valid_secret_shims(&mut json, temp.path());

    let contract = parse_contract(&json)?;
    let shims = contract
        .secret_shims()
        .ok_or_else(|| anyhow::anyhow!("secret shims should be present"))?;

    assert_eq!(shims.guest_target_triple(), "x86_64-unknown-linux-musl");
    assert_eq!(shims.provider_names(), &["vault"]);
    assert_eq!(shims.broker_vsock_port(), 18083);
    assert_eq!(shims.broker_socket_path(), temp.path().join("broker.sock"));
    assert_eq!(
        contract.guest_broker_addr()?,
        Some("127.0.0.1:18084".parse()?)
    );
    Ok(())
}

#[test]
fn rejects_unsafe_secret_shim_provider_basenames() -> Result<()> {
    for name in [
        ".",
        "..",
        "../vault",
        "dir/vault",
        "dir\\vault",
        "C:vault",
        "vault\0x",
    ] {
        let temp = tempfile::tempdir()?;
        let mut json = valid_contract_json(temp.path())?;
        add_valid_secret_shims(&mut json, temp.path());
        json["secret_shims"]["provider_names"] = json!([name]);

        let error = parse_contract_document(&json)?.validate();

        assert!(matches!(
            error,
            Err(ContractValidationError::UnsafeSecretShimProviderName { name: actual })
                if actual == name
        ));
    }
    Ok(())
}

#[test]
fn rejects_non_loopback_guest_broker_address() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    add_valid_secret_shims(&mut json, temp.path());
    json["secret_shims"]["guest_broker_addr"] = json!("10.0.0.2:18084");

    let error = parse_contract_document(&json)?.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::NonLoopbackSocketAddr {
            field: "secret_shims.guest_broker_addr",
            value,
        }) if value == "10.0.0.2:18084"
    ));
    Ok(())
}

#[test]
fn rejects_relative_broker_socket_path() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    add_valid_secret_shims(&mut json, temp.path());
    json["secret_shims"]["broker_socket_path"] = json!("broker.sock");

    let error = parse_contract_document(&json)?.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::RelativePath {
            field: "secret_shims.broker_socket_path",
            path,
        }) if path == Path::new("broker.sock")
    ));
    Ok(())
}

#[test]
fn rejects_empty_secret_shim_provider_list() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    add_valid_secret_shims(&mut json, temp.path());
    json["secret_shims"]["provider_names"] = json!([]);

    let error = parse_contract_document(&json)?.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::EmptySecretShimProviders)
    ));
    Ok(())
}

#[test]
fn rejects_secret_shim_paths_within_guest_writable_runtime() -> Result<()> {
    for field in ["shim_share_directory", "broker_socket_path"] {
        let temp = tempfile::tempdir()?;
        let mut json = valid_contract_json(temp.path())?;
        add_valid_secret_shims(&mut json, temp.path());
        let path = temp.path().join("runtime").join(field);
        json["secret_shims"][field] = json!(&path);

        let error = parse_contract_document(&json)?.validate();

        assert!(matches!(
            error,
            Err(ContractValidationError::SecretShimPathWithinRuntime {
                path: actual_path,
                runtime_dir,
                ..
            }) if actual_path == path && runtime_dir == temp.path().join("runtime")
        ));
    }
    Ok(())
}

#[test]
fn rejects_broker_vsock_port_collisions() -> Result<()> {
    for (port, expected) in [
        (
            18080,
            ContractValidationError::BrokerPortConflictsWithSidecar,
        ),
        (
            18081,
            ContractValidationError::BrokerPortConflictsWithPtyData,
        ),
        (
            18082,
            ContractValidationError::BrokerPortConflictsWithPtyControl,
        ),
    ] {
        let temp = tempfile::tempdir()?;
        let mut json = valid_contract_json(temp.path())?;
        add_valid_secret_shims(&mut json, temp.path());
        json["terminal"]["interactive"] = json!(true);
        json["terminal"]["pty"] = json!(true);
        json["terminal"]["pty_vsock_port"] = json!(18081);
        json["terminal"]["pty_control_vsock_port"] = json!(18082);
        json["secret_shims"]["broker_vsock_port"] = json!(port);

        let error = parse_contract_document(&json)?.validate();

        assert_eq!(
            std::mem::discriminant(
                &error
                    .err()
                    .ok_or_else(|| anyhow::anyhow!("collision should fail"))?,
            ),
            std::mem::discriminant(&expected)
        );
    }
    Ok(())
}

#[test]
fn validates_contract_with_mocked_file_checks() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let json = valid_contract_json_without_artifacts(temp.path())?;
    let document = parse_contract_document(&json)?;
    let mut checked_paths = Vec::new();

    document.validate_with_file_checker(|path| {
        checked_paths.push(path.to_path_buf());
        true
    })?;

    assert_eq!(
        checked_paths,
        vec![
            temp.path().join("vmlinuz"),
            temp.path().join("initrd.img"),
            temp.path().join("rootfs.img"),
        ]
    );
    Ok(())
}

#[test]
fn rejects_contracts_exceeding_mount_limit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let json = valid_contract_json_without_artifacts(temp.path())?;
    let document = parse_contract_document(&json)?;
    let limits = ContractValidationLimits {
        mounts: 0,
        ..ContractValidationLimits::default()
    };

    let error = document.validate_with_limits_and_file_checker(limits, |_| true);

    assert!(matches!(
        error,
        Err(ContractValidationError::TooManyItems {
            field: "mounts",
            actual: 1,
            max: 0,
        })
    ));
    Ok(())
}

#[test]
fn rejects_contracts_exceeding_env_value_limit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json_without_artifacts(temp.path())?;
    json["command"]["env"]["BIG_VALUE"] = json!("abcd");
    let document = parse_contract_document(&json)?;
    let limits = ContractValidationLimits {
        env_value_len: 3,
        ..ContractValidationLimits::default()
    };

    let error = document.validate_with_limits_and_file_checker(limits, |_| true);

    assert!(matches!(
        error,
        Err(ContractValidationError::FieldTooLong {
            field: "command.env value",
            actual: 4,
            max: 3,
        })
    ));
    Ok(())
}

#[test]
fn rejects_contracts_exceeding_path_length_limit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let json = valid_contract_json_without_artifacts(temp.path())?;
    let document = parse_contract_document(&json)?;
    let limits = ContractValidationLimits {
        path_len: 1,
        ..ContractValidationLimits::default()
    };

    let error = document.validate_with_limits_and_file_checker(limits, |_| true);

    assert!(matches!(
        error,
        Err(ContractValidationError::FieldTooLong {
            field: "runtime_dir",
            actual,
            max: 1,
        }) if actual > 1
    ));
    Ok(())
}

#[test]
fn mocked_file_checks_still_fail_closed_for_missing_artifacts() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let rootfs = temp.path().join("rootfs.img");
    let json = valid_contract_json_without_artifacts(temp.path())?;
    let document = parse_contract_document(&json)?;

    let error = document.validate_with_file_checker(|path| path != rootfs.as_path());

    assert!(matches!(
        error,
        Err(ContractValidationError::MissingFile {
            field: "guest.rootfs",
            path,
        }) if path == rootfs
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_group_or_world_readable_contract_file() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let path = temp.path().join("vz-guest-launch.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&valid_contract_json(temp.path())?)?,
    )?;
    let mut permissions = std::fs::metadata(&path)?.permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(&path, permissions)?;

    let error = ContractDocument::read_from_path(&path);

    assert!(error.as_ref().is_err_and(|err| {
        err.to_string()
            .contains("must not be readable or writable by group/other")
    }));
    Ok(())
}

#[cfg(unix)]
#[test]
fn contract_file_mode_rule_is_testable_without_filesystem_metadata() -> Result<()> {
    let path = Path::new("/tmp/vz-guest-launch.json");

    super::validate_contract_file_mode(path, 0o600)?;
    super::validate_contract_file_mode(path, 0o400)?;
    let error = super::validate_contract_file_mode(path, 0o640);

    assert!(error.as_ref().is_err_and(|err| {
        err.to_string()
            .contains("must not be readable or writable by group/other")
    }));
    Ok(())
}

/// Parses and validates a JSON value as a prepared contract.
fn parse_contract(json: &Value) -> Result<Contract> {
    Ok(parse_contract_document(json)?.validate()?)
}

/// Parses a JSON value as a raw contract document.
fn parse_contract_document(json: &Value) -> Result<ContractDocument> {
    ContractDocument::parse_from_slice(Path::new("test-contract.json"), &serde_json::to_vec(&json)?)
}

fn add_valid_secret_shims(json: &mut Value, root: &Path) {
    json["secret_shims"] = json!({
        "guest_target_triple": "x86_64-unknown-linux-musl",
        "provider_names": ["vault"],
        "broker_vsock_port": 18083,
        "shim_share_directory": root.join("secret-shims"),
        "broker_socket_path": root.join("broker.sock"),
        "guest_broker_addr": "127.0.0.1:18084",
    });
}

fn write_shared_v2_contract(root: &Path) -> Result<std::path::PathBuf> {
    let mut json: Value = serde_json::from_str(SHARED_V2_CONTRACT_FIXTURE)?;
    replace_shared_contract_root(&mut json, root);

    for directory in [
        root.join("runtime/vz-guest"),
        root.join("workspace"),
        root.join("sensitive/secret-shims"),
    ] {
        std::fs::create_dir_all(directory)?;
    }
    for (file, size) in [
        ("firma-vz-runner", 1),
        ("vmlinuz", 1),
        ("initrd.img", 1),
        ("rootfs.img", 512),
        ("sensitive/broker.sock", 1),
    ] {
        let artifact = std::fs::File::create(root.join(file))?;
        artifact.set_len(size)?;
    }

    let contract_path = root.join("runtime/vz-guest/vz-guest-launch.json");
    std::fs::write(&contract_path, serde_json::to_vec(&json)?)?;
    #[cfg(unix)]
    crate::test_utils::make_contract_file_owner_only(&contract_path)?;

    Ok(contract_path)
}

fn replace_shared_contract_root(value: &mut Value, root: &Path) {
    match value {
        Value::String(text) if text.starts_with(SHARED_V2_CONTRACT_ROOT) => {
            *text = root
                .join(
                    text.trim_start_matches(SHARED_V2_CONTRACT_ROOT)
                        .trim_start_matches('/'),
                )
                .display()
                .to_string();
        }
        Value::Array(values) => {
            for value in values {
                replace_shared_contract_root(value, root);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_shared_contract_root(value, root);
            }
        }
        Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) => {}
    }
}
