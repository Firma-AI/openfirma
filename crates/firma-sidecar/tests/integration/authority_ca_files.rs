//! What a named Authority CA file must hold: at least one certificate. The
//! Sidecar at startup and the `firma run` capability mint both read the files
//! through `read_ca_pems`. A file that is missing, not PEM, or anchors nothing
//! is refused there, instead of failing only at the handshake it was meant to
//! secure.

#![allow(clippy::expect_used, reason = "test code")]

use std::assert_matches;
use std::path::Path;

use firma_sidecar::authority_tls::{AuthorityTlsError, read_ca_pems};
use firma_sidecar::config::AuthorityTrust;

use super::authority_trust::certificate_authority;

fn ca_pem(name: &str) -> String {
    certificate_authority(name).0
}

fn read(dir: &Path, names: &[&str]) -> Result<Vec<Vec<u8>>, AuthorityTlsError> {
    read_ca_pems(&AuthorityTrust::CustomCas(
        names.iter().map(|name| dir.join(name)).collect(),
    ))
}

/// Every listed file holding a certificate is passed on unchanged, in order.
#[test]
fn listed_ca_files_are_passed_on_unchanged() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let first = ca_pem("First CA");
    let bundle = format!("{}{}", ca_pem("Second CA"), ca_pem("Third CA"));
    std::fs::write(dir.path().join("first.pem"), &first).expect("write first CA");
    std::fs::write(dir.path().join("bundle.pem"), &bundle).expect("write bundle");

    let pems =
        read(dir.path(), &["first.pem", "bundle.pem"]).expect("both files hold certificates");

    assert_eq!(pems, vec![first.into_bytes(), bundle.into_bytes()]);
}

/// A listed file that does not exist is an error naming it: skipping it could
/// leave no CA at all, and an empty list means the platform's roots.
#[test]
fn a_missing_ca_file_is_rejected() {
    let dir = tempfile::tempdir().expect("temporary directory");
    std::fs::write(dir.path().join("first.pem"), ca_pem("First CA")).expect("write first CA");
    let missing = dir.path().join("next.pem");

    let error =
        read(dir.path(), &["first.pem", "next.pem"]).expect_err("a missing file must be rejected");

    assert_matches!(&error, AuthorityTlsError::Read { path, .. } if path == &missing);
    let rendered = error.to_string();
    let path = missing.display().to_string();
    assert!(rendered.contains(&path), "{rendered}");
    insta::assert_snapshot!(rendered.replace(&path, "[NEXT]"), @"failed to read authority CA cert [NEXT]");
}

/// A readable file without a certificate, such as an empty placeholder left
/// for a rotation, is an error naming the file, not an empty trust anchor.
#[test]
fn a_ca_file_without_a_certificate_is_rejected() {
    let dir = tempfile::tempdir().expect("temporary directory");
    std::fs::write(dir.path().join("first.pem"), ca_pem("First CA")).expect("write first CA");
    std::fs::write(dir.path().join("next.pem"), "").expect("write placeholder");

    let error = read(dir.path(), &["first.pem", "next.pem"])
        .expect_err("a certificate-less file must be rejected");

    assert_matches!(
        &error,
        AuthorityTlsError::EmptyCaCert { path } if path == &dir.path().join("next.pem")
    );
    let rendered = error.to_string();
    let placeholder = dir.path().join("next.pem").display().to_string();
    assert!(rendered.contains(&placeholder), "{rendered}");
    insta::assert_snapshot!(rendered.replace(&placeholder, "[NEXT]"), @"authority CA cert [NEXT] holds no CERTIFICATE PEM block");
}

/// A listed file that is not valid PEM is rejected the same way.
#[test]
fn a_listed_file_that_is_not_pem_is_rejected() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let broken = dir.path().join("broken.pem");
    std::fs::write(
        &broken,
        "-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----\n",
    )
    .expect("write broken PEM");

    let error = read(dir.path(), &["broken.pem"]).expect_err("a broken PEM must be rejected");

    assert_matches!(&error, AuthorityTlsError::ParseCaCert { path, .. } if path == &broken);
    let rendered = error.to_string();
    let path = broken.display().to_string();
    assert!(rendered.contains(&path), "{rendered}");
    insta::assert_snapshot!(rendered.replace(&path, "[CA]"), @"failed to parse authority CA cert [CA]");
}
