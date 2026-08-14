use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::harness::{ProcessOutput, TestWorld};

const MASK_TEST_SENTINEL: &str = "firma-mask-adversarial-sentinel";
const MASK_TEST_RAN_MARKER: &str = "FIRMA-MASK-ADVERSARIAL-RAN";

#[test]
fn masks_firma_config_under_workspace_mount() {
    const SENTINEL: &str = "firma-mask-structural-sentinel";
    const RAN_MARKER: &str = "STRUCTURAL-SANDBOX-RAN";

    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    let state_dir = world.state_path();
    world.scaffold_config("codex", &config_dir, &state_dir, None, &workspace);

    let config_path = config_dir.join("firma.toml");
    let generated = std::fs::read_to_string(&config_path).expect("read generated config");
    std::fs::write(&config_path, format!("{generated}\n# {SENTINEL}\n"))
        .expect("plant sentinel in config");

    let shell = format!(
        "cat {config} 2>/dev/null; echo {RAN_MARKER}",
        config = shell_quote(&config_path),
    );
    let output = world.run_firma(
        "codex",
        Some(&config_path),
        &workspace,
        &[],
        "sh",
        ["-c", &shell],
    );
    assert!(output.success(), "firma run failed:\n{output}");
    assert!(
        output.stdout.contains(RAN_MARKER),
        "sandboxed command did not run:\n{output}"
    );
    assert!(
        !output.stdout.contains(SENTINEL),
        "config mask leaked under the codex workspace mount — the agent read firma.toml.\n{output}"
    );
}

#[test]
fn missing_nearer_firma_candidate_cannot_be_planted() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let run_cwd = workspace.join("service");
    let config_dir = workspace.join(".firma");
    std::fs::create_dir_all(&run_cwd).expect("mkdir run cwd");
    scaffold_mask_test_config(&world, &config_dir, &workspace);

    let planted_config = run_cwd.join(".firma/firma.toml");
    assert!(
        !planted_config.exists(),
        "precondition: nearer config candidate must be absent"
    );
    let shell = format!(
        "mkdir -p {candidate_dir} && printf '%s\\n' '# planted by sandbox' > {candidate}; \
         echo {ran}",
        candidate_dir = shell_quote(planted_config.parent().expect("candidate parent")),
        candidate = shell_quote(&planted_config),
        ran = MASK_TEST_RAN_MARKER,
    );

    let output = run_structural_shell(&world, None, &run_cwd, &shell);
    assert_mask_test_ran(&output);
    assert!(
        !planted_config.exists(),
        "sandbox created a higher-precedence host config at {}",
        planted_config.display()
    );
}

#[test]
fn directory_symlink_config_fails_closed_before_agent_launch() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let external_config_dir = workspace.join("external-config");
    let config_file = scaffold_mask_test_config(&world, &external_config_dir, &workspace);

    let lexical_firma = workspace.join(".firma");
    std::os::unix::fs::symlink(&external_config_dir, &lexical_firma)
        .expect("symlink workspace .firma to external config directory");

    let shell = format!(
        "rm {firma_dir} && mkdir {firma_dir} && printf '%s\\n' '# poisoned' > {config}; \
         echo {ran}",
        firma_dir = shell_quote(&lexical_firma),
        config = shell_quote(&workspace.join(".firma/firma.toml")),
        ran = MASK_TEST_RAN_MARKER,
    );
    let output = run_structural_shell(&world, None, &workspace, &shell);
    assert!(
        !output.success(),
        "firma run unexpectedly allowed a symlinked .firma directory"
    );
    assert!(
        !output.stdout.contains(MASK_TEST_RAN_MARKER),
        "sandboxed command ran even though symlinked .firma should fail closed"
    );
    let metadata = std::fs::symlink_metadata(&lexical_firma).expect("inspect lexical .firma");
    assert!(
        metadata.file_type().is_symlink(),
        "sandbox replaced the host .firma symlink"
    );
    assert!(
        std::fs::read_to_string(&config_file)
            .expect("read canonical config")
            .contains(MASK_TEST_SENTINEL),
        "canonical config was unexpectedly modified"
    );
}

#[test]
fn file_symlink_config_cannot_be_read_or_modified_via_target() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    let lexical_config = scaffold_mask_test_config(&world, &config_dir, &workspace);
    let canonical_target = workspace.join("firma-target.toml");
    std::fs::rename(&lexical_config, &canonical_target).expect("move config to symlink target");
    std::os::unix::fs::symlink(&canonical_target, &lexical_config)
        .expect("symlink firma.toml to workspace target");
    let original = std::fs::read_to_string(&canonical_target).expect("read pristine target");

    let shell = format!(
        "cat {target} 2>/dev/null; printf '%s\\n' '# modified by sandbox' >> {target}; \
         echo {ran}",
        target = shell_quote(&canonical_target),
        ran = MASK_TEST_RAN_MARKER,
    );
    let output = run_structural_shell(&world, None, &workspace, &shell);
    assert_mask_test_ran(&output);
    assert!(
        !output.stdout.contains(MASK_TEST_SENTINEL),
        "sandbox read the selected config through the canonical file-symlink target"
    );
    assert_eq!(
        std::fs::read_to_string(&canonical_target).expect("read target after run"),
        original,
        "sandbox modified the selected config through its canonical symlink target"
    );
}

#[test]
fn workspace_mount_alias_does_not_reexpose_firma_config() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    let mount_alias = world.path("workspace-alias");
    std::fs::create_dir_all(&mount_alias).expect("mkdir mount alias target");
    let config_file = scaffold_mask_test_config(&world, &config_dir, &workspace);
    append_profile_mount(&config_file, &workspace, &mount_alias);

    let aliased_config = mount_alias.join(".firma/firma.toml");
    let shell = format!(
        "cat {config} 2>/dev/null; echo {ran}",
        config = shell_quote(&aliased_config),
        ran = MASK_TEST_RAN_MARKER,
    );
    let output = run_structural_shell(&world, Some(&config_file), &workspace, &shell);
    assert_mask_test_ran(&output);
    assert!(
        !output.stdout.contains(MASK_TEST_SENTINEL),
        "workspace mount exposed firma.toml through {}",
        aliased_config.display()
    );
}

#[test]
fn mount_targeting_firma_dir_does_not_replace_mask() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    let config_file = scaffold_mask_test_config(&world, &config_dir, &workspace);
    append_profile_mount(&config_file, &config_dir, &config_dir);

    let shell = format!(
        "cat {config} 2>/dev/null; echo {ran}",
        config = shell_quote(&config_file),
        ran = MASK_TEST_RAN_MARKER,
    );
    let output = run_structural_shell(&world, Some(&config_file), &workspace, &shell);
    assert_mask_test_ran(&output);
    assert!(
        !output.stdout.contains(MASK_TEST_SENTINEL),
        "post-mask mount targeting .firma re-exposed the selected config"
    );
}

#[test]
fn firma_source_mount_alias_does_not_reexpose_config() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    let alias = world.path("firma-alias");
    let config_file = scaffold_mask_test_config(&world, &config_dir, &workspace);
    append_profile_mount(&config_file, &config_dir, &alias);

    let aliased_config = alias.join("firma.toml");
    let shell = format!(
        "cat {config} 2>/dev/null; echo {ran}",
        config = shell_quote(&aliased_config),
        ran = MASK_TEST_RAN_MARKER,
    );
    let output = run_structural_shell(&world, Some(&config_file), &workspace, &shell);
    assert_mask_test_ran(&output);
    assert!(
        !output.stdout.contains(MASK_TEST_SENTINEL),
        "firma source mount re-exposed firma.toml through {}",
        aliased_config.display()
    );
}

#[test]
fn parent_dir_mount_target_does_not_replace_firma_mask() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    let config_file = scaffold_mask_test_config(&world, &config_dir, &workspace);
    let parent_dir_target = config_dir.join("..");
    append_profile_mount(&config_file, &workspace, &parent_dir_target);

    let shell = format!(
        "cat {config} 2>/dev/null; echo {ran}",
        config = shell_quote(&config_file),
        ran = MASK_TEST_RAN_MARKER,
    );
    let output = run_structural_shell(&world, Some(&config_file), &workspace, &shell);
    assert_mask_test_ran(&output);
    assert!(
        !output.stdout.contains(MASK_TEST_SENTINEL),
        "unnormalized .firma/.. mount target was emitted after the mask and re-exposed the selected config"
    );
}

fn scaffold_mask_test_config(world: &TestWorld, config_dir: &Path, workspace: &Path) -> PathBuf {
    world.scaffold_config(
        "generic",
        config_dir,
        &world.state_path(),
        Some(workspace),
        workspace,
    );
    let config_file = config_dir.join("firma.toml");
    TestWorld::disable_host_home_masks(&config_file);
    let generated = std::fs::read_to_string(&config_file).expect("read generated config");
    std::fs::write(
        &config_file,
        format!("{generated}\n# {MASK_TEST_SENTINEL}\n"),
    )
    .expect("plant config sentinel");
    config_file
}

fn append_profile_mount(config_file: &Path, source: &Path, target: &Path) {
    let mut config = std::fs::read_to_string(config_file).expect("read generated config");
    write!(
        config,
        "\n[[run.profiles.generic.mounts]]\n\
         source = \"{}\"\n\
         target = \"{}\"\n\
         read_only = false\n",
        source.display(),
        target.display(),
    )
    .expect("render adversarial profile mount");
    std::fs::write(config_file, config).expect("append adversarial profile mount");
}

fn run_structural_shell(
    world: &TestWorld,
    config_file: Option<&Path>,
    cwd: &Path,
    shell: &str,
) -> ProcessOutput {
    world.run_firma("generic", config_file, cwd, &[], "sh", ["-c", shell])
}

fn assert_mask_test_ran(output: &ProcessOutput) {
    assert!(output.success(), "firma run failed:\n{output}");
    assert!(
        output.stdout.contains(MASK_TEST_RAN_MARKER),
        "sandboxed command did not run:\n{output}"
    );
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}
