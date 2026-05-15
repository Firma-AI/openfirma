#![no_main]

use firma_sidecar::config::SeedFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<SeedFile>(s);
    }
});
