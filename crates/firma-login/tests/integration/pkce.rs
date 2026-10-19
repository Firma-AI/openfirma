use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use firma_login::AuthorizationAttempt;
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};

#[test]
fn derives_the_s256_challenge_from_the_generated_verifier() -> Result<(), Box<dyn std::error::Error>>
{
    let attempt = AuthorizationAttempt::start()?;
    let verifier = attempt.verifier().as_secret().expose_secret();
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    assert_eq!(attempt.pkce_challenge().as_str(), expected);
    Ok(())
}

#[test]
fn compares_authorization_state_for_each_attempt() -> Result<(), Box<dyn std::error::Error>> {
    let first = AuthorizationAttempt::start()?;
    let second = AuthorizationAttempt::start()?;

    assert!(first.state().matches(first.state()));
    assert!(!first.state().matches(second.state()));
    Ok(())
}

#[test]
fn generates_url_safe_state_and_verifier_values() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = AuthorizationAttempt::start()?;
    let values = [
        attempt.state().as_str(),
        attempt.verifier().as_secret().expose_secret(),
    ];

    for value in values {
        assert_eq!(value.len(), 43);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    Ok(())
}
