//! File-watch scope of a running `firma authority`.

use std::time::Duration;

/// Mapping inputs commonly sit next to unrelated, frequently written files:
/// the Authority's own log, audit spools, or editor swap files. Only changes to
/// the configured inputs may trigger a reload. Reacting to every write in the
/// directory turns the Authority's own reload log line into the trigger for
/// the next reload, a self-sustaining loop that burns CPU and fills the disk.
#[test]
fn unrelated_writes_beside_mapping_inputs_do_not_trigger_reloads() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let policies = root.path().join("policies");
    std::fs::create_dir(&policies)?;
    std::fs::write(
        policies.join("permit.cedar"),
        "permit(principal, action, resource);",
    )?;
    // The fixture writes the Authority's stderr log into `root` as well.
    let mapping = root.path().join("mapping-rules.toml");
    std::fs::write(
        &mapping,
        "[[rules]]\nhost = 'api.test'\naction_class = 'code.read'\n",
    )?;
    let authority =
        super::authority_fixture::LocalAuthority::start(root.path(), &policies, &mapping)?;
    std::fs::write(root.path().join("unrelated.txt"), "not a mapping input")?;
    std::thread::sleep(Duration::from_secs(2));
    drop(authority);

    let log = std::fs::read_to_string(root.path().join("authority-fixture.stderr.log"))?;
    let reloads = log
        .lines()
        .filter(|line| line.contains("hot-reload triggered"))
        .count();
    assert_eq!(reloads, 0, "unrelated writes triggered {reloads} reloads");
    Ok(())
}
