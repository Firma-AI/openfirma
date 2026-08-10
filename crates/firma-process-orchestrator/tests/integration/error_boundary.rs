use firma_process_orchestrator::{
    LifecycleTimeouts, StackTopology, StartError, spawn_stack_from_plan,
};

#[derive(Debug, Eq, PartialEq)]
struct PlanFailure;

#[test]
fn plan_failure_after_lock_acquisition_retains_caller_type() {
    let state_dir = tempfile::tempdir().expect("state dir");

    let topology = StackTopology::new(["worker"]).expect("valid topology");
    let result = spawn_stack_from_plan(
        &topology,
        |_| {
            assert!(state_dir.path().join("stack.lock").is_file());
            Err::<firma_process_orchestrator::ComponentSpec, _>(PlanFailure)
        },
        state_dir.path(),
        LifecycleTimeouts::default(),
    );
    let Err(error) = result else {
        panic!("plan must fail");
    };

    assert!(matches!(error, StartError::Plan(PlanFailure)));
}
