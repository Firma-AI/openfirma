use firma_secret_provider::non_empty::{
    NonEmptyStr, NonEmptyString, NonEmptyVec, string::EmptyError as StringEmptyError,
    vec::EmptyError as VecEmptyError,
};

#[test]
fn non_empty_string_accepts_trimmed_content() {
    let value = NonEmptyString::new(String::from("secret")).expect("non-empty");
    assert_eq!(&*value, "secret");
}

#[test]
fn non_empty_string_rejects_whitespace_only() {
    for input in ["", "   ", "\t\n"] {
        let error = NonEmptyString::new(String::from(input)).expect_err("empty");
        assert!(matches!(error, StringEmptyError));
        assert_eq!(error.to_string(), "empty string");
    }
}

#[test]
fn non_empty_string_keeps_inner_whitespace() {
    // Only emptiness is validated; surrounding whitespace is retained.
    let value = NonEmptyString::new(String::from(" secret ")).expect("non-empty");
    assert_eq!(&*value, " secret ");
}

#[test]
fn non_empty_string_deserialization_rejects_empty() {
    let error = toml::from_str::<NonEmptyString>(r#""""#).expect_err("empty");
    assert!(matches!(error, toml::de::Error { .. }));
}

#[test]
fn non_empty_str_trims_and_rejects_whitespace_only() {
    let value = NonEmptyStr::new(" secret ").expect("non-empty");
    assert_eq!(&*value, "secret");
    for input in ["", "   "] {
        assert!(NonEmptyStr::new(input).is_err());
    }
}

#[test]
fn non_empty_vec_accepts_non_empty() {
    let value = NonEmptyVec::new(vec!["secret"]).expect("non-empty");
    assert_eq!(&*value, ["secret"]);
}

#[test]
fn non_empty_vec_rejects_empty() {
    let error = NonEmptyVec::<String>::new(vec![]).expect_err("empty");
    assert!(matches!(error, VecEmptyError));
    assert_eq!(error.to_string(), "empty vec");
}

#[test]
fn non_empty_vec_deserialization_rejects_empty_array() {
    let error = toml::from_str::<NonEmptyVec<String>>("[]").expect_err("empty");
    assert!(matches!(error, toml::de::Error { .. }));
}
