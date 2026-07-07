#[cfg(target_os = "linux")]
mod linux;

/// Starts the Linux guest init payload.
#[cfg(target_os = "linux")]
fn main() -> ! {
    linux::main()
}

/// Rejects accidental host execution outside the Linux guest.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("firma-vz-guest-init is only useful inside the Linux VZ guest initrd");
    std::process::exit(1);
}
