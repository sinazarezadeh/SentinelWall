use std::sync::Arc;
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::StatusCode,
    Extension,
};
use serde_json::json;

use crate::auth::AuthManager;

pub async fn require_auth(
    Extension(auth): Extension<Arc<AuthManager>>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    let token = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").map(|t| t.to_string()));

    match token {
        Some(t) => {
            match auth.validate_token(&t) {
                Ok(_) => Ok(next.run(req).await),
                Err(_) => Err((
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({ "error": "Invalid or expired token" })),
                )),
            }
        }
        None => Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({ "error": "Authorization required" })),
        )),
    }
}

pub async fn require_admin(
    Extension(auth): Extension<Arc<AuthManager>>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    let token = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").map(|t| t.to_string()));

    match token {
        Some(t) => {
            match auth.validate_token(&t) {
                Ok(claims) if claims.role == "admin" => Ok(next.run(req).await),
                Ok(_) => Err((
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({ "error": "Admin access required" })),
                )),
                Err(_) => Err((
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({ "error": "Invalid or expired token" })),
                )),
            }
        }
        None => Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({ "error": "Authorization required" })),
        )),
    }
}
