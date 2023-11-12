use axum::{response::IntoResponse, routing::get, Json, Router};

pub async fn health_check_handler() -> impl IntoResponse {
    const MESSAGE: &str = "User Authentication service with axum Rust Framework";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

#[tokio::main]
async fn main () {
    let app = Router::new().route("/api/healthchecker", get(health_check_handler));

    println!("🚀 Server started successfully");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}