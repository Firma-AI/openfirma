#[cfg(all(unix, not(target_os = "macos")))]
use std::{
    env, fs, io,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::{self, Command},
};

#[cfg(all(unix, not(target_os = "macos")))]
use firma_login::print_and_open;
#[cfg(all(unix, not(target_os = "macos")))]
use url::Url;

#[cfg(all(unix, not(target_os = "macos")))]
const CHILD_MODE: &str = "FIRMA_LOGIN_BROWSER_TEST_CHILD";
#[cfg(all(unix, not(target_os = "macos")))]
const FLUSH_MARKER: &str = "FIRMA_LOGIN_BROWSER_TEST_FLUSH_MARKER";
#[cfg(all(unix, not(target_os = "macos")))]
const OBSERVATION: &str = "FIRMA_LOGIN_BROWSER_TEST_OBSERVATION";
#[cfg(all(unix, not(target_os = "macos")))]
const TEST_NAME: &str = "browser::prints_and_flushes_the_url_before_opening_the_browser";
#[cfg(all(unix, not(target_os = "macos")))]
const TEST_URL: &str = "https://issuer.example.test/authorize?state=opaque-state";

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn prints_and_flushes_the_url_before_opening_the_browser() -> Result<(), Box<dyn std::error::Error>>
{
    if env::var_os(CHILD_MODE).is_some() {
        return run_child();
    }

    let directory = env::temp_dir().join(format!("firma-login-browser-order-{}", process::id()));
    fs::create_dir(&directory)?;
    let browser = directory.join("w3m");
    let flush_marker = directory.join("flushed");
    let observation = directory.join("observation");
    fs::write(
        &browser,
        "#!/bin/sh\nif [ -f \"$FIRMA_LOGIN_BROWSER_TEST_FLUSH_MARKER\" ]; then\n  printf after\nelse\n  printf before\nfi > \"$FIRMA_LOGIN_BROWSER_TEST_OBSERVATION\"\n",
    )?;
    fs::set_permissions(&browser, fs::Permissions::from_mode(0o700))?;

    let status = Command::new(env::current_exe()?)
        .args(["--exact", TEST_NAME])
        .env(CHILD_MODE, "1")
        .env("BROWSER", &browser)
        .env(FLUSH_MARKER, &flush_marker)
        .env(OBSERVATION, &observation)
        .status()?;
    let observed_order = fs::read_to_string(&observation);
    fs::remove_dir_all(&directory)?;

    assert!(status.success());
    assert_eq!(observed_order?, "after");
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn run_child() -> Result<(), Box<dyn std::error::Error>> {
    let flush_marker = env_path(FLUSH_MARKER)?;
    let mut output = FlushMarkerWriter {
        bytes: Vec::new(),
        flush_marker,
    };

    print_and_open(&Url::parse(TEST_URL)?, &mut output)?;

    assert_eq!(output.bytes, format!("{TEST_URL}\n").into_bytes());
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn env_path(name: &str) -> io::Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other(format!("{name} is not set")))
}

#[cfg(all(unix, not(target_os = "macos")))]
struct FlushMarkerWriter {
    bytes: Vec<u8>,
    flush_marker: PathBuf,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl io::Write for FlushMarkerWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.bytes != format!("{TEST_URL}\n").as_bytes() {
            return Err(io::Error::other("authorization URL line is incomplete"));
        }

        fs::write(&self.flush_marker, b"flushed")
    }
}
