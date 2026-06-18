#![no_main]

use std::sync::OnceLock;

use firma_core::token::{TokenVerifier, paseto::PasetoV4Verifier};
use libfuzzer_sys::fuzz_target;

// Ed25519 public key from RFC 8032 §7.1 Test 1.
// Public, deterministic test vector — never used to sign real tokens.
// Pinned so fuzz corpora stay reproducible across runs.
const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn static_verifier() -> &'static PasetoV4Verifier {
    static V: OnceLock<PasetoV4Verifier> = OnceLock::new();
    V.get_or_init(|| PasetoV4Verifier::try_new(&PUBLIC_KEY).expect("static key is valid"))
}

fuzz_target!(|input: String| {
    let _ = static_verifier().verify(&input);
});
