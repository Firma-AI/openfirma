#![no_main]

use firma_core::{AgentId, SessionId};
use firma_core::token::TokenId;
use firma_sidecar::config::SeedFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Exercise the full capability seed loading pipeline:
    //   1. TOML deserialization of SeedFile (datetime, string, optional fields)
    //   2. ID parsing — mirrors seed_into_entry in startup/capability.rs
    let Ok(file) = toml::from_str::<SeedFile>(s) else {
        return;
    };

    let _ = file.token_id.parse::<TokenId>();
    let _ = file.agent_id.parse::<AgentId>();
    let _ = file.session_id.parse::<SessionId>();
});
