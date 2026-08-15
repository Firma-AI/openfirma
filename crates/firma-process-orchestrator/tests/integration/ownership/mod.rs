//! Ownership, generation fencing, and publication through production APIs.

mod detach_reaper;
mod rollback_replacement;
mod shutdown_foreground;
mod startup_transactions;

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentEndpoint, ComponentPlanContext, ComponentSpec, LifecycleTimeouts, OrchestratorError,
    RunningStack, ShutdownError, StackGeneration, StackTopology, StartError,
    publish_startup_report, spawn_stack_from_plan, start_detached, start_foreground_from_plan,
    stop_components, supervise_owned_generation_from_plan,
};
use firma_runtime_state::UserProcessId;
use fs2::FileExt as _;

const CHILD_MARKER: &str = "FIRMA_ORCHESTRATOR_CHILD_MARKER";
const CHILD_LISTEN: &str = "FIRMA_ORCHESTRATOR_CHILD_LISTEN";
const CHILD_PUBLICATION: &str = "FIRMA_ORCHESTRATOR_CHILD_PUBLICATION";
const CHILD_RELEASE: &str = "FIRMA_ORCHESTRATOR_CHILD_RELEASE";
const CHILD_BLOCK_PIDFILE: &str = "FIRMA_ORCHESTRATOR_CHILD_BLOCK_PIDFILE";
const SUPERVISOR_STATE_DIR: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_STATE_DIR";
const SUPERVISOR_GENERATION: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_GENERATION";
const SUPERVISOR_MODE: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_MODE";
const SUPERVISOR_SENTINEL_PID: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_SENTINEL_PID";

fn fast_timeouts() -> LifecycleTimeouts {
    LifecycleTimeouts {
        graceful_teardown: Duration::ZERO,
        ..LifecycleTimeouts::default()
    }
}

struct ProcessCleanup(Vec<u32>);

impl ProcessCleanup {
    fn new(pids: impl IntoIterator<Item = u32>) -> Self {
        Self(pids.into_iter().collect())
    }

    fn disarm(mut self) {
        self.0.clear();
    }
}

impl Drop for ProcessCleanup {
    fn drop(&mut self) {
        for pid in &self.0 {
            best_effort_terminate_scope(*pid);
        }
    }
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn owned_child_fixture() {
    if let (Some(state_dir), Some(generation)) = (
        std::env::var_os(SUPERVISOR_STATE_DIR),
        std::env::var_os(SUPERVISOR_GENERATION),
    ) {
        let state_dir = Path::new(&state_dir);
        let generation = generation
            .to_string_lossy()
            .parse::<StackGeneration>()
            .expect("parse supervisor generation");
        if std::env::var(SUPERVISOR_MODE).as_deref() == Ok("attach-replacement") {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind replacement endpoint");
            let endpoint = listener.local_addr().expect("replacement endpoint");
            let supervisor_pid = UserProcessId::new(std::process::id()).expect("supervisor PID");
            let replacement = StackGeneration::default();
            let replacement_state = format!("{replacement}\n");
            std::fs::write(state_dir.join("stack.lock"), &replacement_state)
                .expect("publish replacement generation");
            std::fs::write(state_dir.join("replacement.generation"), &replacement_state)
                .expect("record replacement generation");
            firma_runtime_state::pidfile::write(&state_dir.join("stack.pid"), supervisor_pid)
                .expect("write replacement owner");
            firma_runtime_state::pidfile::write(&state_dir.join("authority.pid"), supervisor_pid)
                .expect("write replacement component");
            std::fs::write(state_dir.join("authority.listen"), format!("{endpoint}\n"))
                .expect("write replacement endpoint");
            let ready = state_dir.join(format!("stack.{supervisor_pid}.ready"));
            firma_runtime_state::pidfile::write(&ready, supervisor_pid)
                .expect("publish supervisor readiness");
            while ready.exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            firma_runtime_state::pidfile::write(
                &state_dir.join(format!("stack.{supervisor_pid}.attached")),
                supervisor_pid,
            )
            .expect("publish supervisor attachment");
            std::thread::sleep(Duration::from_secs(1));
            return;
        }
        if std::env::var(SUPERVISOR_MODE).as_deref() == Ok("replace") {
            let replacement = StackGeneration::default();
            let sentinel = std::env::var(SUPERVISOR_SENTINEL_PID)
                .expect("sentinel PID")
                .parse::<u32>()
                .expect("parse sentinel PID");
            let sentinel = UserProcessId::new(sentinel).expect("sentinel PID");
            std::fs::write(state_dir.join("stack.lock"), format!("{replacement}\n"))
                .expect("publish replacement generation");
            firma_runtime_state::pidfile::write(&state_dir.join("stack.pid"), sentinel)
                .expect("write replacement owner");
            firma_runtime_state::pidfile::write(&state_dir.join("authority.pid"), sentinel)
                .expect("write replacement component");
            return;
        }
        supervise_owned_generation_from_plan(
            &topology(&["authority", "sidecar"]),
            component_planner(state_dir, &["authority", "sidecar"]),
            state_dir,
            generation,
            fast_timeouts(),
        )
        .expect("supervise detached fixture");
        return;
    }
    if let Some(address) = std::env::var_os(CHILD_LISTEN) {
        if let Some(release) = std::env::var_os(CHILD_RELEASE) {
            while !Path::new(&release).exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(path) = std::env::var_os(CHILD_BLOCK_PIDFILE) {
            std::fs::create_dir(path).expect("create blocking pidfile directory");
        }
        let listener = std::net::TcpListener::bind(address.to_string_lossy().as_ref())
            .expect("bind component readiness listener");
        if let Some(publication) = std::env::var_os(CHILD_PUBLICATION) {
            publish_startup_report(
                Path::new(&publication),
                &firma_process_orchestrator::ComponentEndpoint::Tcp(
                    listener.local_addr().expect("effective component endpoint"),
                ),
            )
            .expect("publish component endpoint");
        }
        if let Some(marker) = std::env::var_os(CHILD_MARKER) {
            std::fs::write(marker, std::process::id().to_string()).expect("write marker");
        }
        println!("{}", std::process::id());
        std::io::stdout().flush().expect("flush PID");
        loop {
            let _ = listener.accept();
        }
    }
}

fn assert_component_exit_tears_down_foreground_stack(exiting_component: usize) {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let (result_tx, result_rx) = mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let result = start_foreground_from_plan(
            &topology(&["authority", "sidecar"]),
            component_planner(&state_dir, &["authority", "sidecar"]),
            &state_dir,
            fast_timeouts(),
        );
        let _ = result_tx.send(result);
    });
    let pids = [
        wait_for_marker(&dir.path().join("authority.marker")),
        wait_for_marker(&dir.path().join("sidecar.marker")),
    ];
    wait_for_file(&dir.path().join("authority.listen"));
    wait_for_file(&dir.path().join("sidecar.listen"));
    wait_for_transaction_release(dir.path());
    terminate_process(pids[exiting_component]);

    result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("foreground result")
        .expect("foreground teardown");
    supervisor.join().expect("join supervisor");
    assert_all_absent(&pids);
    assert!(!dir.path().join("stack.lock").exists());
}

fn spawn_stack(state_dir: &Path, names: &[&str]) -> (RunningStack, Vec<u32>) {
    let stack = spawn_stack_from_plan(
        &topology(names),
        component_planner(state_dir, names),
        state_dir,
        fast_timeouts(),
    )
    .expect("spawn public stack");
    let pids = names
        .iter()
        .map(|name| wait_for_marker(&state_dir.join(format!("{name}.marker"))))
        .collect();
    (stack, pids)
}

fn component_spec(context: &ComponentPlanContext<'_>, state_dir: &Path) -> ComponentSpec {
    let publication = context.child_published(firma_process_orchestrator::ComponentEndpoint::Tcp(
        "127.0.0.1:0".parse().expect("fixture bind endpoint"),
    ));
    let mut command = fixture_command();
    command
        .env_remove(SUPERVISOR_STATE_DIR)
        .env_remove(SUPERVISOR_GENERATION)
        .env_remove(SUPERVISOR_MODE)
        .env_remove(SUPERVISOR_SENTINEL_PID)
        .env(CHILD_LISTEN, "127.0.0.1:0")
        .env(CHILD_PUBLICATION, publication.startup_report_path())
        .env(
            CHILD_MARKER,
            state_dir.join(format!("{}.marker", context.name())),
        );
    ComponentSpec {
        command,
        readiness: publication.into_readiness(),
    }
}

fn component_planner<'a>(
    state_dir: &Path,
    names: &'a [&'a str],
) -> impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, std::convert::Infallible> + use<'a>
{
    let state_dir = state_dir.to_path_buf();
    let mut index = 0;
    move |context| {
        assert_eq!(context.name(), names[index]);
        assert!(
            names[..index]
                .iter()
                .all(|name| context.ready_endpoint(name).is_some()),
            "each staged invocation sees every prior ready endpoint"
        );
        assert!(context.ready_endpoint(names[index]).is_none());
        index += 1;
        Ok(component_spec(&context, &state_dir))
    }
}

fn delayed_component_planner<'a>(
    state_dir: &Path,
    names: &'a [&'a str],
) -> impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, std::convert::Infallible> {
    let state_dir = state_dir.to_path_buf();
    let mut planner = component_planner(&state_dir, names);
    move |context| {
        let name = context.name().to_string();
        let mut spec = planner(context)?;
        spec.command
            .env(CHILD_RELEASE, state_dir.join(format!("{name}.release")));
        Ok(spec)
    }
}

fn assert_stop_waits_for_partial_publication(published_components: usize) {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let (start_tx, start_rx) = mpsc::channel();
    let start_dir = state_dir.clone();
    let starter = std::thread::spawn(move || {
        let result = spawn_stack_from_plan(
            &topology(&["authority", "sidecar"]),
            delayed_component_planner(&start_dir, &["authority", "sidecar"]),
            &start_dir,
            fast_timeouts(),
        );
        let _ = start_tx.send(result);
    });
    wait_for_file(&state_dir.join("authority.pid"));
    if published_components == 2 {
        std::fs::write(state_dir.join("authority.release"), []).expect("release authority");
        wait_for_file(&state_dir.join("sidecar.pid"));
    }
    let stop_dir = state_dir.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        let _ = stop_tx.send(stop_components(
            &stop_dir,
            Duration::ZERO,
            &topology(&["authority", "sidecar"]),
        ));
    });
    assert!(matches!(
        stop_rx.recv_timeout(Duration::from_millis(200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    std::fs::write(state_dir.join("authority.release"), []).expect("release authority");
    std::fs::write(state_dir.join("sidecar.release"), []).expect("release sidecar");
    let stack = start_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("startup result")
        .expect("startup");
    drop(stack);
    stop_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("stop result")
        .expect("serialized stop");
    starter.join().expect("join starter");
    stopper.join().expect("join stopper");
}

#[cfg(unix)]
fn reserve_address() -> (std::net::SocketAddr, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve address");
    (listener.local_addr().expect("reserved address"), listener)
}

fn spawn_published_fixture(
    state_dir: &Path,
    name: &str,
) -> (std::process::Child, std::net::SocketAddr) {
    let publication = state_dir.join(format!("{name}.endpoint"));
    let marker = state_dir.join(format!("{name}.marker"));
    let mut command = fixture_command();
    command
        .env(CHILD_LISTEN, "127.0.0.1:0")
        .env(CHILD_PUBLICATION, &publication)
        .env(CHILD_MARKER, &marker);
    let child = command.spawn().expect("spawn published fixture");
    wait_for_marker(&marker);
    let record = std::fs::read_to_string(publication).expect("read fixture endpoint");
    let addr = record
        .lines()
        .find_map(|line| line.strip_prefix("endpoint = \"")?.strip_suffix('"'))
        .expect("fixture endpoint field")
        .parse()
        .expect("parse fixture endpoint");
    (child, addr)
}

fn wait_for_transaction_release(state_dir: &Path) {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(state_dir.join(".stack-state.lock"))
        .expect("open transaction lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match lock.try_lock_shared() {
            Ok(()) => {
                fs2::FileExt::unlock(&lock).expect("release observed transaction lock");
                return;
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                assert!(
                    Instant::now() < deadline,
                    "startup transaction remained held"
                );
                std::thread::yield_now();
            }
            Err(std::fs::TryLockError::Error(error)) => {
                panic!("observe startup transaction: {error}")
            }
        }
    }
}

fn fixture_command() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command.args(["--exact", "ownership::owned_child_fixture", "--ignored"]);
    command
}

fn supervisor_command(state_dir: &Path, generation: StackGeneration, mode: &str) -> Command {
    let mut command = fixture_command();
    command
        .env(SUPERVISOR_STATE_DIR, state_dir)
        .env(SUPERVISOR_GENERATION, generation.to_string())
        .env(SUPERVISOR_MODE, mode);
    command
}

fn exiting_command() -> Command {
    #[cfg(unix)]
    {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        command
    }
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.args(["/C", "exit 0"]);
        command
    }
}

fn topology(names: &[&str]) -> StackTopology {
    StackTopology::new(names.iter().copied()).expect("valid topology")
}

fn wait_for_marker(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(pid) = contents.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_all_absent(pids: &[u32]) {
    for pid in pids {
        assert_process_absent(*pid);
    }
}

fn assert_process_absent(pid: u32) {
    let process = UserProcessId::new(pid).expect("fixture PID");
    let deadline = Instant::now() + Duration::from_secs(5);
    while process.process_exists().expect("probe fixture") {
        assert!(Instant::now() < deadline, "process {pid} remains alive");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_process_present(pid: u32) {
    assert!(
        UserProcessId::new(pid)
            .expect("fixture PID")
            .process_exists()
            .expect("probe fixture"),
        "process {pid} is absent"
    );
}

fn read_pidfile(path: &Path) -> u32 {
    firma_runtime_state::pidfile::read(path)
        .expect("read pidfile")
        .expect("pidfile present")
        .get()
}

fn best_effort_terminate_scope(pid: u32) {
    #[cfg(unix)]
    {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid.as_raw()),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
}

fn terminate_process(pid: u32) {
    #[cfg(unix)]
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(pid).expect("PID fits i32")),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("terminate fixture");
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .expect("run taskkill")
            .success()
    );
}
