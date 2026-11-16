//! The hosted API's errors: one JSON shape (`{"error": "<plain words>", "code": "<machine code>"}`) and a status each.
//! Internal details (SQL, provider bodies) are logged, never returned.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("sign in first")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("not found")]
    NotFound,
    /// No route has this path and method (the routers' fallback).
    #[error("no such route")]
    NoRoute,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Unprocessable(String),
    /// Validation problems with the page document, by path.
    #[error("the page document has problems")]
    Issues(Vec<link_in_bio_core::Issue>),
    #[error("{0}")]
    Unavailable(&'static str),
    #[error("something went wrong; try again")]
    Internal,
}

impl ApiError {
    fn status_code(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::NoRoute => (StatusCode::NOT_FOUND, "no_route"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            ApiError::Unprocessable(_) => (StatusCode::UNPROCESSABLE_ENTITY, "unprocessable"),
            ApiError::Issues(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_page"),
            ApiError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_code();
        let mut body = json!({ "error": self.to_string(), "code": code });
        if let ApiError::Issues(issues) = &self {
            body["issues"] = serde_json::to_value(issues).unwrap_or_default();
        }
        let mut r = (status, Json(body)).into_response();
        r.headers_mut().insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
        r
    }
}

impl From<link_in_bio_store::DbError> for ApiError {
    fn from(e: link_in_bio_store::DbError) -> Self {
        tracing::error!(error = %e, "database");
        ApiError::Unavailable("the database is unavailable; try again shortly")
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
