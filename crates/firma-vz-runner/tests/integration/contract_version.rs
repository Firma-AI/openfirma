use std::process::Command;

use anyhow::Result;

#[test]
fn prints_supported_contract_version_without_a_contract() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_firma-vz-runner"))
        .arg("--supported-contract-version")
        .output()?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "2\n");
    assert_eq!(String::from_utf8(output.stderr)?, "");
    Ok(())
}
