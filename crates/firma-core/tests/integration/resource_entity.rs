use cedar_policy::EvalResult;
use firma_core::FirmaEntityUid;

#[test]
fn resource_entity_populates_id_host_and_path() {
    let entity =
        FirmaEntityUid::resource_entity("api.openai.com/v1/models").expect("resource entity");

    assert_eq!(entity.uid().type_name().to_string(), "Firma::Resource");
    assert_eq!(entity.uid().id().as_ref(), "api.openai.com/v1/models");
    assert_eq!(
        entity.attr("id").expect("id attr").expect("id value"),
        EvalResult::String("api.openai.com/v1/models".to_string())
    );
    assert_eq!(
        entity.attr("host").expect("host attr").expect("host value"),
        EvalResult::String("api.openai.com".to_string())
    );
    assert_eq!(
        entity.attr("path").expect("path attr").expect("path value"),
        EvalResult::String("/v1/models".to_string())
    );
}

#[test]
fn resource_entity_strips_scheme_before_host_path_attributes() {
    let entity = FirmaEntityUid::resource_entity("https://api.openai.com/v1/models")
        .expect("resource entity");

    assert_eq!(
        entity.attr("id").expect("id attr").expect("id value"),
        EvalResult::String("https://api.openai.com/v1/models".to_string())
    );
    assert_eq!(
        entity.attr("host").expect("host attr").expect("host value"),
        EvalResult::String("api.openai.com".to_string())
    );
    assert_eq!(
        entity.attr("path").expect("path attr").expect("path value"),
        EvalResult::String("/v1/models".to_string())
    );
}

#[test]
fn resource_entity_omits_empty_optional_attributes() {
    let entity = FirmaEntityUid::resource_entity("").expect("resource entity");

    assert_eq!(
        entity.attr("id").expect("id attr").expect("id value"),
        EvalResult::String(String::new())
    );
    assert!(entity.attr("host").is_none());
    assert!(entity.attr("path").is_none());
}
