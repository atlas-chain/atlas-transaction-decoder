use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::Address;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::decode::{ARKIV_ADDRESS, DecodeError, decode_input};
use crate::frontend::INDEX_HTML;
use crate::reference::{
    DEV_CHAIN_ID, PAYLOAD_REFERENCE_CONTENT_TYPE, TRUSTED_DEV_PROVIDER_SIGNER,
    TRUSTED_PROVIDER_SIGNER,
};

const SERVICE_NAME: &str = "atlas-transaction-decoder";
const ENDPOINTS: [&str; 6] = [
    "/",
    "/?tx=0x...",
    "/status",
    "/healthz",
    "/decode",
    "/decode?data=0x...",
];

#[derive(Clone)]
pub struct AppState {
    pub html_title: Arc<String>,
    pub max_input_bytes: usize,
    pub default_chain_id: u64,
    pub rpc_url: Arc<Option<String>>,
    pub extra_trusted: Arc<Vec<Address>>,
}

#[derive(Debug, Deserialize)]
struct DecodeQuery {
    data: Option<String>,
    #[serde(rename = "chainId", default)]
    chain_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DecodeBody {
    data: String,
    #[serde(rename = "chainId", default)]
    chain_id: Option<u64>,
}

pub async fn run_server(state: AppState, listen_host: String, listen_port: u16) {
    let bind_address = format!("{listen_host}:{listen_port}");

    let listener = match TcpListener::bind(&bind_address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind HTTP server on {bind_address}: {error}");
            return;
        }
    };

    println!(
        "{}",
        json!({
            "message": "atlas transaction decoder listening",
            "url": format!("http://{bind_address}/decode"),
            "ui": format!("http://{bind_address}/"),
            "defaultChainId": state.default_chain_id,
            "rpcConfigured": state.rpc_url.is_some(),
            "extraTrustedSigners": state.extra_trusted.len(),
            "endpoints": ENDPOINTS,
        })
    );

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/status", get(status_handler))
        .route("/healthz", get(health_handler))
        .route("/decode", get(decode_get).post(decode_post))
        .fallback(not_found_handler)
        .with_state(state);

    if let Err(error) = axum::serve(listener, app).await {
        eprintln!("HTTP server failed: {error}");
    }
}

async fn index_handler(State(state): State<AppState>) -> Response {
    let html = INDEX_HTML.replace("__HTML_TITLE__", &escape_html(state.html_title.as_str()));
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn status_handler(State(state): State<AppState>) -> Json<Value> {
    let extra: Vec<String> = state
        .extra_trusted
        .iter()
        .map(|address| address.to_checksum(None))
        .collect();
    Json(json!({
        "ok": true,
        "service": SERVICE_NAME,
        "arkivAddress": ARKIV_ADDRESS,
        "defaultChainId": state.default_chain_id,
        "maxInputBytes": state.max_input_bytes,
        "rpcUrl": state.rpc_url.as_deref(),
        "payloadReferenceContentType": PAYLOAD_REFERENCE_CONTENT_TYPE,
        "trustedProviderSigners": {
            "default": TRUSTED_PROVIDER_SIGNER,
            "devChainOnly": { "chainId": DEV_CHAIN_ID, "signer": TRUSTED_DEV_PROVIDER_SIGNER },
            "configured": extra,
        },
        "endpoints": ENDPOINTS,
    }))
}

async fn decode_get(State(state): State<AppState>, Query(query): Query<DecodeQuery>) -> Response {
    let Some(data) = query.data else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing transaction data: pass ?data=0x...",
        );
    };
    decode_and_respond(&state, &data, query.chain_id)
}

async fn decode_post(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if body.len() > state.max_input_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "request body is {} bytes, maximum is {}",
                body.len(),
                state.max_input_bytes
            ),
        );
    }

    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let (data, chain_id) = if content_type.contains("application/json") {
        match serde_json::from_slice::<DecodeBody>(&body) {
            Ok(parsed) => (parsed.data, parsed.chain_id),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    r#"JSON body must have the shape {"data": "0x...", "chainId"?: 1337}"#,
                );
            }
        }
    } else {
        // Raw hex posted as text/plain or without a content type.
        match std::str::from_utf8(&body) {
            Ok(text) => (text.to_string(), None),
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "request body is not valid UTF-8");
            }
        }
    };

    decode_and_respond(&state, &data, chain_id)
}

fn decode_and_respond(state: &AppState, data: &str, chain_id: Option<u64>) -> Response {
    if data.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "missing transaction data");
    }
    if data.len() > state.max_input_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "input is {} bytes, maximum is {}",
                data.len(),
                state.max_input_bytes
            ),
        );
    }

    let chain_id = chain_id.unwrap_or(state.default_chain_id);
    let started = Instant::now();

    match decode_input(data, chain_id, &state.extra_trusted) {
        Ok(decoded) => {
            let mut value = serde_json::to_value(&decoded).expect("decoded transaction serializes");
            if let Value::Object(map) = &mut value {
                map.insert("ok".to_string(), Value::Bool(true));
                map.insert("chainId".to_string(), json!(chain_id));
            }
            println!(
                "{}",
                json!({
                    "message": "decoded transaction",
                    "operationCount": decoded.operation_count,
                    "chainId": chain_id,
                    "latencyMs": started.elapsed().as_millis().to_string(),
                })
            );
            (
                StatusCode::OK,
                [
                    ("content-type", "application/json"),
                    ("cache-control", "no-cache"),
                ],
                Json(value),
            )
                .into_response()
        }
        Err(DecodeError(message)) => error_response(StatusCode::BAD_REQUEST, message),
    }
}

async fn not_found_handler() -> Response {
    error_response(StatusCode::NOT_FOUND, "Not found")
}

fn error_response<S>(status: StatusCode, message: S) -> Response
where
    S: AsRef<str>,
{
    (
        status,
        Json(json!({ "ok": false, "error": { "message": message.as_ref() } })),
    )
        .into_response()
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState {
            html_title: Arc::new("Atlas Transaction Decoder".to_string()),
            max_input_bytes: 1024 * 1024,
            default_chain_id: DEV_CHAIN_ID,
            rpc_url: Arc::new(Some("https://rpc.example".to_string())),
            extra_trusted: Arc::new(Vec::new()),
        }
    }

    async fn body_string(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        (
            status,
            String::from_utf8(bytes.to_vec()).expect("utf8 body"),
        )
    }

    #[tokio::test]
    async fn index_handler_serves_escaped_title() {
        let mut state = state();
        state.html_title = Arc::new("Decoder <x> & \"y\"".to_string());
        let (status, body) = body_string(index_handler(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Decoder &lt;x&gt; &amp; &quot;y&quot;"));
    }

    #[tokio::test]
    async fn status_reports_configured_rpc_url() {
        let Json(status) = status_handler(State(state())).await;
        assert_eq!(status["rpcUrl"], "https://rpc.example");
    }

    #[tokio::test]
    async fn decode_get_requires_data() {
        let response = decode_get(
            State(state()),
            Query(DecodeQuery {
                data: None,
                chain_id: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn decode_get_rejects_non_execute_data() {
        let response = decode_get(
            State(state()),
            Query(DecodeQuery {
                data: Some("0xdeadbeef".to_string()),
                chain_id: None,
            }),
        )
        .await;
        let (status, body) = body_string(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("execute"));
    }

    #[tokio::test]
    async fn decode_post_reads_json_body() {
        let body = Bytes::from(r#"{"data":"0xdeadbeef"}"#);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let response = decode_post(State(state()), headers, body).await;
        // 0xdeadbeef is valid hex but not an execute() call.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn decode_post_rejects_malformed_json() {
        let body = Bytes::from(r#"{"nope":true}"#);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let response = decode_post(State(state()), headers, body).await;
        let (status, text) = body_string(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(text.contains("shape"));
    }
}
