//! Runs the shared mapping compatibility corpus against the Authority loader.
//!
//! The Authority is the only production parser of authored mapping files, so
//! the observed corpus outcomes that describe an authored document as a whole
//! must hold for it exactly as they hold for the Sidecar table compiler.

use std::num::NonZeroU32;
use std::path::Path;

use firma_authority::CedarPolicyStore;
use serde::Deserialize;

const BUNDLE_TTL: NonZeroU32 = NonZeroU32::new(30).unwrap();

const CORPUS: &str = include_str!("../../../../compatibility/mapping/cases.toml");

#[derive(Deserialize)]
struct Corpus {
    parse_cases: Vec<Case>,
    validation_cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    outcome: Outcome,
    document: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Accept,
    Reject,
}

fn load(root: &Path, document: &str) -> anyhow::Result<()> {
    let mapping = root.join("mapping-rules.toml");
    std::fs::write(&mapping, document)?;
    CedarPolicyStore::load_with_mappings(root, None, BUNDLE_TTL, vec![mapping]).map(drop)
}

#[test]
fn authority_loader_matches_the_corpus_document_outcomes() -> anyhow::Result<()> {
    let corpus: Corpus = toml::from_str(CORPUS)?;
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("permit.cedar"),
        "permit(principal, action, resource);",
    )?;

    // Parse acceptance only promises a document survives decoding; rejection
    // and every validation outcome describe the complete authored document.
    let cases = corpus
        .parse_cases
        .iter()
        .filter(|case| case.outcome == Outcome::Reject || case.id == "parse-unknown-fields-ignored")
        .chain(&corpus.validation_cases);
    let mismatches = cases
        .filter_map(|case| {
            let actual = match load(root.path(), &case.document) {
                Ok(()) => Outcome::Accept,
                Err(_) => Outcome::Reject,
            };
            (actual != case.outcome)
                .then(|| format!("{}: expected {:?}, got {actual:?}", case.id, case.outcome))
        })
        .collect::<Vec<_>>();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    Ok(())
}
