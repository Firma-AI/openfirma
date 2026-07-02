use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use crate::test_utils::{valid_contract_json, valid_contract_json_without_artifacts};

use super::{
    Contract, ContractDocument, ContractValidationError, ContractValidationLimits, InvariantName,
};

#[test]
fn validates_contract_v1() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let json = valid_contract_json(temp.path())?;
    let contract = parse_contract(&json)?;

    assert_eq!(contract.version(), 1);
    assert_eq!(contract.sandbox_id(), "sandbox-test");

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
    assert_eq!(contract.terminal().term(), Some("xterm-256color"));
    assert_eq!(contract.terminal().rows(), Some(40));
    assert_eq!(contract.terminal().cols(), Some(120));

    Ok(())
}

#[test]
fn rejects_pty_terminal_until_bridge_exists() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut json = valid_contract_json(temp.path())?;
    json["terminal"]["interactive"] = json!(true);
    json["terminal"]["pty"] = json!(true);

    let document = parse_contract_document(&json)?;
    let error = document.validate();

    assert!(matches!(
        error,
        Err(ContractValidationError::UnsupportedTerminalPty)
    ));

    Ok(())
}

#[test]
fn rejects_pty_ports_without_pty() -> Result<()> {
    for field in ["pty_vsock_port", "pty_control_vsock_port"] {
        let temp = tempfile::tempdir()?;
        let mut json = valid_contract_json(temp.path())?;
        json["terminal"][field] = json!(18081);

        let document = parse_contract_document(&json)?;
        let error = document.validate();
        let expected = if field == "pty_vsock_port" {
            "terminal.pty_vsock_port"
        } else {
            "terminal.pty_control_vsock_port"
        };

        assert!(matches!(
            error,
            Err(ContractValidationError::TerminalPtyPortWithoutPty { field })
                if field == expected
        ));
    }

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
            temp.path().join("seccomp.bpf"),
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
