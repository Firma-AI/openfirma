use std::collections::BTreeSet;

use crate::support::{
    DEFAULT_POLICY_SOURCE, DISABLED_POLICY_SOURCE, OTHER_POLICY_SOURCE, PolicyStateReadCounts,
    app_with_audit_rows, app_with_default_policies, app_with_policy_files, audit_row,
    generated_policy_id, generated_policy_ids, generated_policy_source, handle_key,
    last_visible_audit_index, policy_status, rewrite_ids_for_file, selected_audit_resource,
    write_named_policy_file,
};
use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditFilter, AuditViewportMode, ControlError, Pane,
    PolicyRewriteCompletion, PolicyRewriteError, PolicyRewriteStart, PolicyRowStatus, PolicyState,
    set_policy_states,
};

const LARGE_POLICY_COUNT: usize = 1_000;
const LARGE_POLICY_FILE_COUNT: usize = 10;
const LARGE_POLICIES_PER_FILE: usize = LARGE_POLICY_COUNT / LARGE_POLICY_FILE_COUNT;

#[test]
fn tab_switches_panes() {
    let mut app = app_with_audit_rows();

    assert_eq!(app.selected_pane(), Pane::Policies);

    handle_key(&mut app, KeyCode::Tab);
    assert_eq!(app.selected_pane(), Pane::Audit);

    handle_key(&mut app, KeyCode::Tab);
    assert_eq!(app.selected_pane(), Pane::Policies);
}

#[test]
fn j_k_and_arrows_clamp_policy_selection() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;

    assert_eq!(app.selected_policy_index(), 0);

    handle_key(&mut app, KeyCode::Char('k'));
    handle_key(&mut app, KeyCode::Up);
    assert_eq!(app.selected_policy_index(), 0);

    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_policy_index(), 1);

    handle_key(&mut app, KeyCode::Down);
    handle_key(&mut app, KeyCode::Down);
    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_policy_index(), 2);

    handle_key(&mut app, KeyCode::Char('k'));
    handle_key(&mut app, KeyCode::Up);
    assert_eq!(app.selected_policy_index(), 0);

    Ok(())
}

#[test]
fn gg_jumps_to_first_policy_row() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;

    app.move_selection_last();
    assert_eq!(app.selected_policy_index(), 2);

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_policy_index(), 2);

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_policy_index(), 0);

    Ok(())
}

#[test]
fn gg_jumps_to_first_audit_row() {
    let mut app = app_with_audit_rows();
    app.switch_pane();

    app.move_selection_last();
    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);
}

#[test]
fn capital_g_jumps_last_and_resumes_audit_follow_tail() {
    let mut app = app_with_audit_rows();

    app.switch_pane();
    app.move_selection_first();
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);

    handle_key(&mut app, KeyCode::Char('G'));

    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}

#[test]
fn j_to_last_audit_row_resumes_follow_tail() {
    let mut app = app_with_audit_rows();

    app.switch_pane();
    app.move_selection_first();

    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);

    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}

#[test]
fn help_overlay_changes_key_context() {
    let mut app = app_with_audit_rows();

    handle_key(&mut app, KeyCode::Char('h'));
    assert!(app.help_visible());

    handle_key(&mut app, KeyCode::Char('j'));
    assert!(app.help_visible());
    assert_eq!(app.selected_pane(), Pane::Policies);

    handle_key(&mut app, KeyCode::Esc);
    assert!(!app.help_visible());
    assert!(!app.should_quit());
}

#[test]
fn audit_buffer_drops_oldest_row_at_capacity() {
    let mut app = App::new(None, true);
    for index in 0..=1_000 {
        app.push_audit_row(audit_row(AuditDecision::Allow, index));
    }

    assert_eq!(app.audit_rows_len(), 1_000);
    assert_eq!(
        app.visible_audit_rows()
            .next()
            .map(|row| row.resource.as_str()),
        Some("resource-1")
    );
}

#[test]
fn empty_audit_navigation_stays_clamped() {
    let mut app = App::default();
    app.switch_pane();

    app.move_selection_up();
    app.move_selection_down();
    app.move_selection_first();
    app.move_selection_last();

    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}

#[test]
fn queued_or_writing_policies_cannot_be_toggled_again() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;
    let request = app
        .request_selected_policy_toggle()
        .ok_or_else(|| anyhow::anyhow!("selected policy did not produce a rewrite request"))?;

    assert_eq!(request.ids.len(), 1);
    let selected_id =
        request.ids.first().cloned().ok_or_else(|| {
            anyhow::anyhow!("selected rewrite request did not include a policy id")
        })?;
    assert_eq!(
        policy_status(&app, &selected_id),
        Some(PolicyRowStatus::Queued)
    );
    assert!(app.request_selected_policy_toggle().is_none());

    app.start_policy_rewrite(&PolicyRewriteStart {
        file: request.file,
        ids: request.ids,
    });

    assert_eq!(
        policy_status(&app, &selected_id),
        Some(PolicyRowStatus::Writing)
    );
    assert!(app.request_selected_policy_toggle().is_none());

    Ok(())
}

#[test]
fn toggle_all_skips_rows_already_matching_requested_state() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;
    let rewrites = app.request_all_policy_toggle();

    assert_eq!(rewrites.len(), 1);
    assert_eq!(
        rewrites.first().map(|request| request.ids.clone()),
        Some(vec!["second_policy".to_string()])
    );
    assert_eq!(
        rewrites.first().map(|request| request.requested),
        Some(PolicyState::Enabled)
    );
    assert_eq!(
        policy_status(&app, "first_policy"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );
    assert_eq!(
        policy_status(&app, "second_policy"),
        Some(PolicyRowStatus::Queued)
    );
    assert_eq!(
        policy_status(&app, "third_policy"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );

    Ok(())
}

#[test]
fn toggle_all_groups_rewrites_by_file() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_policy_files(&[
        ("policies.cedar", DEFAULT_POLICY_SOURCE),
        ("other.cedar", OTHER_POLICY_SOURCE),
    ])?;
    let rewrites = app.request_all_policy_toggle();

    assert_eq!(rewrites.len(), 2);
    assert_eq!(
        rewrite_ids_for_file(&rewrites, "other.cedar"),
        Some(vec!["fourth_policy".to_string()])
    );
    assert_eq!(
        rewrite_ids_for_file(&rewrites, "policies.cedar"),
        Some(vec!["second_policy".to_string()])
    );

    Ok(())
}

#[test]
fn toggle_all_1000_policies_in_one_cedar_file_produces_one_batch_request() -> anyhow::Result<()> {
    let source = generated_policy_source("one_file_policy", LARGE_POLICY_COUNT, |_| true);
    let (_temp, mut app) = app_with_policy_files(&[("large.cedar", &source)])?;

    let rewrites = app.request_all_policy_toggle();
    let request = single_rewrite_request(&rewrites)?;

    assert_eq!(app.policies().len(), LARGE_POLICY_COUNT);
    assert_eq!(request.requested, PolicyState::Enabled);
    assert_eq!(request.ids.len(), LARGE_POLICY_COUNT);
    assert_eq!(
        string_set(&request.ids),
        string_set(&generated_policy_ids("one_file_policy", LARGE_POLICY_COUNT))
    );

    Ok(())
}

#[test]
fn toggle_all_1000_policies_across_files_produces_one_batch_per_file() -> anyhow::Result<()> {
    let files = (0..LARGE_POLICY_FILE_COUNT)
        .map(|file_index| {
            (
                format!("large-{file_index:02}.cedar"),
                generated_policy_source(
                    &format!("file_{file_index:02}_policy"),
                    LARGE_POLICIES_PER_FILE,
                    |_| true,
                ),
            )
        })
        .collect::<Vec<_>>();
    let file_refs = files
        .iter()
        .map(|(name, source)| (name.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    let (_temp, mut app) = app_with_policy_files(&file_refs)?;

    let rewrites = app.request_all_policy_toggle();

    assert_eq!(app.policies().len(), LARGE_POLICY_COUNT);
    assert_eq!(rewrites.len(), LARGE_POLICY_FILE_COUNT);
    assert!(
        rewrites
            .iter()
            .all(|request| request.ids.len() == LARGE_POLICIES_PER_FILE)
    );
    assert!(
        rewrites
            .iter()
            .all(|request| request.requested == PolicyState::Enabled)
    );
    assert_eq!(
        rewrite_file_names(&rewrites)?.len(),
        LARGE_POLICY_FILE_COUNT
    );

    Ok(())
}

#[test]
fn toggle_all_1000_policies_skips_already_matching_rows() -> anyhow::Result<()> {
    let source = generated_policy_source("mixed_policy", LARGE_POLICY_COUNT, |index| {
        !index.is_multiple_of(2)
    });
    let (_temp, mut app) = app_with_policy_files(&[("mixed.cedar", &source)])?;

    let rewrites = app.request_all_policy_toggle();
    let request = single_rewrite_request(&rewrites)?;
    let expected_ids = (0..LARGE_POLICY_COUNT)
        .filter(|index| !index.is_multiple_of(2))
        .map(|index| generated_policy_id("mixed_policy", index))
        .collect::<Vec<_>>();

    assert_eq!(request.requested, PolicyState::Enabled);
    assert_eq!(string_set(&request.ids), string_set(&expected_ids));
    assert_eq!(
        policy_status(&app, "mixed_policy_0000"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );
    assert_eq!(
        policy_status(&app, "mixed_policy_0001"),
        Some(PolicyRowStatus::Queued)
    );

    Ok(())
}

#[test]
fn policy_refresh_reads_each_affected_file_once() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let source = generated_policy_source("refresh_policy", LARGE_POLICY_COUNT, |_| true);
    let policy_path = write_named_policy_file(temp.path(), "refresh.cedar", &source)?;
    let read_counts = PolicyStateReadCounts::default();
    let mut app =
        App::with_policy_state_reader(Some(temp.path().to_path_buf()), false, read_counts.reader());
    assert_eq!(app.policies().len(), LARGE_POLICY_COUNT);
    read_counts.clear()?;

    let ids = generated_policy_ids("refresh_policy", LARGE_POLICY_COUNT);
    set_policy_states(&policy_path, &ids, PolicyState::Enabled)?;
    app.finish_policy_rewrite(&PolicyRewriteCompletion {
        file: policy_path.clone(),
        ids,
        requested: PolicyState::Enabled,
        result: Ok(()),
    });

    assert_eq!(read_counts.count_for(&policy_path)?, 1);
    assert_eq!(
        policy_status(&app, "refresh_policy_0000"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );
    assert_eq!(
        policy_status(&app, "refresh_policy_0999"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );

    Ok(())
}

#[test]
fn start_event_marks_all_batch_ids_writing() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_policy_files(&[("policies.cedar", DISABLED_POLICY_SOURCE)])?;
    let rewrites = app.request_all_policy_toggle();
    assert_eq!(rewrites.len(), 1);
    let request = rewrites
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("toggle all did not produce a rewrite request"))?;

    app.start_policy_rewrite(&PolicyRewriteStart {
        file: request.file,
        ids: request.ids,
    });

    assert_eq!(
        policy_status(&app, "first_policy"),
        Some(PolicyRowStatus::Writing)
    );
    assert_eq!(
        policy_status(&app, "second_policy"),
        Some(PolicyRowStatus::Writing)
    );

    Ok(())
}

#[test]
fn batch_completion_refreshes_disk_derived_state_for_file() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_policy_files(&[("policies.cedar", DISABLED_POLICY_SOURCE)])?;
    let request = app
        .request_all_policy_toggle()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("toggle all did not produce a rewrite request"))?;

    set_policy_states(&request.file, &request.ids, request.requested)?;

    app.finish_policy_rewrite(&PolicyRewriteCompletion {
        file: request.file,
        ids: request.ids,
        requested: request.requested,
        result: Ok(()),
    });

    assert_eq!(
        policy_status(&app, "first_policy"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );
    assert_eq!(
        policy_status(&app, "second_policy"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );

    Ok(())
}

#[test]
fn rewrite_completion_stores_structured_policy_rewrite_error() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_policy_files(&[("policies.cedar", DEFAULT_POLICY_SOURCE)])?;
    let request = app
        .request_selected_policy_toggle()
        .ok_or_else(|| anyhow::anyhow!("selected policy did not produce a rewrite request"))?;
    let rewrite_error = ControlError::policy_rewrite(
        &request.file,
        request.ids.clone(),
        PolicyRewriteError::operation("write failed"),
    );

    app.finish_policy_rewrite(&PolicyRewriteCompletion {
        file: request.file,
        ids: request.ids,
        requested: request.requested,
        result: Err(rewrite_error.clone()),
    });

    assert_eq!(app.policy_error(), Some(&rewrite_error));

    Ok(())
}

#[test]
fn audit_filters_preserve_and_clamp_selected_row() {
    let mut app = app_with_audit_rows();

    app.switch_pane();
    app.move_selection_first();
    app.move_selection_down();
    assert_eq!(app.selected_audit_index(), 1);

    handle_key(&mut app, KeyCode::Char('l'));
    assert_eq!(app.audit_filter(), AuditFilter::Allow);
    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(selected_audit_resource(&app), Some("resource-2"));

    handle_key(&mut app, KeyCode::Char('d'));
    assert_eq!(app.audit_filter(), AuditFilter::Deny);
    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(selected_audit_resource(&app), Some("resource-1"));
}

fn single_rewrite_request(
    rewrites: &[firma_tui::control::PolicyRewriteRequest],
) -> anyhow::Result<&firma_tui::control::PolicyRewriteRequest> {
    assert_eq!(rewrites.len(), 1);
    rewrites
        .first()
        .ok_or_else(|| anyhow::anyhow!("toggle all did not produce a rewrite request"))
}

fn rewrite_file_names(
    rewrites: &[firma_tui::control::PolicyRewriteRequest],
) -> anyhow::Result<BTreeSet<String>> {
    rewrites
        .iter()
        .map(|request| {
            request
                .file
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow::anyhow!("rewrite request path has no valid file name"))
        })
        .collect()
}

fn string_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}
