use std::collections::HashMap;
use std::time::Duration;

use firma_core::{
    ActionParams, Connector, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
    HttpParams, InjectedCredentials, TransportView,
};
use firma_http::Method;
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::connector::provider::{GenericHttpConnector, HttpConnectorConfig};
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::normalizer::{IntentNormalizer, MappingTable, RawRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn view_for(resource: &str, query: HashMap<String, String>) -> anyhow::Result<TransportView> {
    let intent = ExecutionIntent {
        action_class: "code.read".to_string(),
        resource: ExecutionIntent::resource_map_from(resource),
        params: ActionParams::Http(HttpParams {
            method: HttpMethod::GET,
            headers: HashMap::new(),
            body: None,
            query,
        }),
        raw_transport: "http".to_string(),
        raw_action_ref: "GET /info/refs".to_string(),
    };
    let envelope = ExecutionEnvelope::new(
        intent,
        "v4.public.test".to_string(),
        ExecutionMetadata {
            session_id: "sess_http_connector".parse()?,
            agent_id: "agt_01j0000000e008000000000001".parse()?,
            timestamp: chrono::Utc::now(),
            trace_id: None,
            budget_consumed: 0.0,
            risk_score: None,
            thread_id: None,
            parent_action_id: None,
        },
        None,
    );
    Ok(TransportView::new(envelope, InjectedCredentials::empty()))
}

fn github_normalizer() -> anyhow::Result<IntentNormalizer> {
    let rules = MappingRulesFile {
        rules: vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "github.com".to_string(),
            path: Some("/*/*.git/git-receive-pack".to_string()),
            action_class: "code.write".to_string(),
        }],
    };
    let table = MappingTable::from_config(&rules, &ActionClassRegistry::v0_1(), true)?;
    Ok(IntentNormalizer::new(table))
}

fn receive_pack_body(commands: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, (old_id, new_id, git_ref)) in commands.iter().enumerate() {
        let capabilities = if index == 0 { "\0report-status" } else { "" };
        let command = format!("{old_id} {new_id} {git_ref}{capabilities}\n");
        let len = command.len() + 4;
        body.extend_from_slice(format!("{len:04x}{command}").as_bytes());
    }
    body.extend_from_slice(b"0000");
    body
}

async fn serve_one_request(listener: TcpListener, request_line_tx: oneshot::Sender<String>) {
    let Ok((mut stream, _peer)) = listener.accept().await else {
        return;
    };
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let Ok(read) = stream.read(&mut buf).await else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buf[..read]);
    }
    let request_text = String::from_utf8_lossy(&request);
    let request_line = request_text.lines().next().unwrap_or_default().to_string();
    let _ = request_line_tx.send(request_line);
    let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await;
}

#[tokio::test]
async fn connector_does_not_duplicate_query_already_present_in_resource() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (request_line_tx, request_line_rx) = oneshot::channel();
    let server = tokio::spawn(serve_one_request(listener, request_line_tx));

    let connector = GenericHttpConnector::new(&HttpConnectorConfig {
        timeout: Duration::from_secs(5),
        rate_limit: None,
    })?;
    let view = view_for(
        &format!("{addr}/info/refs?service=git-upload-pack"),
        HashMap::from([("service".to_string(), "git-upload-pack".to_string())]),
    )?;

    let response = connector.dispatch(&view).await?;
    assert_eq!(response.status, 200);
    assert_eq!(
        request_line_rx.await?,
        "GET /info/refs?service=git-upload-pack HTTP/1.1"
    );
    server.await?;
    Ok(())
}

#[tokio::test]
async fn connector_restores_redacted_query_from_http_params() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (request_line_tx, request_line_rx) = oneshot::channel();
    let server = tokio::spawn(serve_one_request(listener, request_line_tx));

    let connector = GenericHttpConnector::new(&HttpConnectorConfig {
        timeout: Duration::from_secs(5),
        rate_limit: None,
    })?;
    let view = view_for(
        &format!("{addr}/info/refs?access_token=<redacted>&service=git-upload-pack"),
        HashMap::from([
            ("access_token".to_string(), "secret-token".to_string()),
            ("service".to_string(), "git-upload-pack".to_string()),
        ]),
    )?;

    let response = connector.dispatch(&view).await?;
    assert_eq!(response.status, 200);
    let request_line = request_line_rx.await?;
    assert!(request_line.starts_with("GET /info/refs?"));
    assert!(request_line.ends_with(" HTTP/1.1"));
    assert!(request_line.contains("access_token=secret-token"));
    assert!(request_line.contains("service=git-upload-pack"));
    assert!(!request_line.contains("redacted"));
    server.await?;
    Ok(())
}

#[test]
fn multiple_receive_pack_updates_fail_closed() -> anyhow::Result<()> {
    let request = RawRequest {
        method: Method::POST,
        host: "github.com".to_string(),
        path: "/owner/repo.git/git-receive-pack".to_string(),
        headers: HashMap::new(),
        body: Some(receive_pack_body(&[
            (
                "1111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222",
                "refs/heads/allowed",
            ),
            (
                "3333333333333333333333333333333333333333",
                "4444444444444444444444444444444444444444",
                "refs/heads/not-evaluated",
            ),
        ])),
        is_https: true,
    };

    let result = github_normalizer()?.normalize(&request);
    let decision = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("multiple ref updates should be denied"))?;
    assert!(decision.is_deny());
    Ok(())
}
