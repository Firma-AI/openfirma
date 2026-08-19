use std::collections::HashSet;

use firma_http::{Authority, Str};
use firma_secret_provider::{
    GatewayRequest, PlaceholderResult, PushRequest, PushResponse, ResolveRequest,
    SecretPlaceholder,
    broker::{BrokerRequest, BrokerResponse},
};

#[test]
fn gateway_resolve_serializes_with_action_tag() {
    let request = GatewayRequest::Resolve(ResolveRequest {
        placeholders: vec![Str::from("fsp_placeholder")],
        domain: Authority::from_static("example.com"),
    });
    let wire = serde_json::to_string(&request).expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"action":"secret.resolve","placeholders":["fsp_placeholder"],"domain":"example.com"}"#);
}

#[test]
fn gateway_push_serializes_with_action_tag() {
    let request = GatewayRequest::Push(PushRequest {
        placeholder: Str::from("fsp_placeholder"),
        value_b64: Str::from("aGVsbG8="),
        domain: HashSet::from([Authority::from_static("example.com")]),
    });
    let wire = serde_json::to_string(&request).expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"action":"secret.push","placeholder":"fsp_placeholder","value_b64":"aGVsbG8=","domain":["example.com"]}"#);
}

#[test]
fn placeholder_result_round_trips() {
    let wire = serde_json::to_string(&PlaceholderResult::Ok {
        secret_b64: Str::from("aGVsbG8="),
    })
    .expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"type":"ok","secret_b64":"aGVsbG8="}"#);
    let back: PlaceholderResult = serde_json::from_str(&wire).expect("deserialize");
    match &back {
        PlaceholderResult::Ok { secret_b64 } => assert_eq!(&**secret_b64, "aGVsbG8="),
        PlaceholderResult::Err { .. } => panic!("expected ok result"),
    }

    let wire = serde_json::to_string(&PlaceholderResult::Err {
        error: Str::from("unknown placeholder"),
    })
    .expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"type":"err","error":"unknown placeholder"}"#);
    let back: PlaceholderResult = serde_json::from_str(&wire).expect("deserialize");
    match &back {
        PlaceholderResult::Err { error } => assert_eq!(&**error, "unknown placeholder"),
        PlaceholderResult::Ok { .. } => panic!("expected err result"),
    }
}

#[test]
fn push_response_ok_round_trips_placeholder() {
    let placeholder = SecretPlaceholder::new();
    let response = PushResponse::Ok {
        placeholder: placeholder.clone(),
    };
    let wire = serde_json::to_string(&response).expect("serialize");
    let back: PushResponse = serde_json::from_str(&wire).expect("deserialize");
    match back {
        PushResponse::Ok {
            placeholder: returned,
        } => assert_eq!(returned, placeholder),
        PushResponse::Err { .. } => panic!("expected ok response"),
    }
}

#[test]
fn push_response_err_round_trips() {
    let response = PushResponse::Err {
        error: Str::from("malformed placeholder"),
    };
    let wire = serde_json::to_string(&response).expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"type":"err","error":"malformed placeholder"}"#);
    let back: PushResponse = serde_json::from_str(&wire).expect("deserialize");
    match &back {
        PushResponse::Err { error } => assert_eq!(&**error, "malformed placeholder"),
        PushResponse::Ok { .. } => panic!("expected err response"),
    }
}

#[test]
fn broker_request_round_trips() {
    let request = BrokerRequest {
        bin: Str::from("bws"),
        args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
    };
    let wire = serde_json::to_string(&request).expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"bin":"bws","args":["secret","get","abc"]}"#);
    let back: BrokerRequest = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back, request);
}

#[test]
fn broker_response_ok_round_trips() {
    let response = BrokerResponse::ok(b"secret-value");
    let wire = serde_json::to_string(&response).expect("serialize");
    insta::assert_snapshot!(wire, @r#"{"type":"ok","stdout":"c2VjcmV0LXZhbHVl"}"#);
    let back: BrokerResponse = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back.into_stdout().expect("stdout"), b"secret-value");
}

#[test]
fn broker_response_err_into_stdout_reports_reason() {
    let response = BrokerResponse::err("tool not found");
    assert_eq!(
        response.into_stdout().expect_err("error response"),
        "tool not found"
    );
}
