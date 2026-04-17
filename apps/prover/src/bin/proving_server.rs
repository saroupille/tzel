//! HTTP wrapper around the tzel reprover library.
//!
//! POST /prove  { "circuit": "run_shield", "args": ["0x09", ...] }
//!              → ProofBundle JSON
//! GET  /healthz → 200 "ok"

use std::io::Write as _;
use std::path::PathBuf;

use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use tempfile::NamedTempFile;
use tzel_reprover::custom_circuit::ProofBundle;

#[derive(Deserialize)]
struct ProveRequest {
    circuit: String,
    args: Vec<String>,
}

async fn prove_handler(
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProofBundle>, (StatusCode, String)> {
    let cairo_dir = std::env::var("REPROVE_CAIRO_DIR").unwrap_or_else(|_| ".".to_string());

    tokio::task::spawn_blocking(move || {
        let executable =
            PathBuf::from(format!("{}/{}.executable.json", cairo_dir, req.circuit));

        let args_json = serde_json::to_string(&req.args)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let mut args_file = NamedTempFile::new()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        args_file
            .write_all(args_json.as_bytes())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        args_file
            .flush()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let output =
            tzel_reprover::prove_with_args_file(&executable, Some(args_file.path().to_path_buf()))
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(ProofBundle::from_output(&output)))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

async fn healthz() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let port: u16 = std::env::var("PROVING_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);

    let app = Router::new()
        .route("/prove", post(prove_handler))
        .route("/healthz", get(healthz));

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("proving-server listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
