use std::sync::Arc

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
  extract::State,
  http::{header, Response, StatusCode},
  response::IntoResponse,
  Extension, Json
}

use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OSRng;
use serde_json::Json;


use crate::{
  model::{LoginUserSchema, RegisterSchema, TokenClaims, User},
  response::FilteredUser,
  AppState
}

fn filter_user_record(user: &User) -> FilteredUser {
  FilteredUser {
    id: user.id.to_string(),
    email: user.email.to_owned(),
    name: user.name.to_owned(),
    photo: user.photo.to_owned(),
    role: user.photo.to_owned(),
    verfied: user.photo.to_owned(),
    createdAt: user.created_at.unwrap(),
    updatedAt: user.updated_at.unwrap(),
  }
}

pub async fn register_user_handler (
  State(data): State<Arc<AppState>>,
  Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
  let user_exist: Option<bool> = 
      sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
      .bind(body.email.to_owned().to_ascii_lowercase())
      .fetch_one(&data.db)
      .await
      .map_err(|e| {
        let error_response = serde_json::json!({
          "status": "fail",
          "message": format!("Database Error: {}", e)
        });
         (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
      })?;
    
  if let Some(exists) = user_exist {
      if exists {
        let error_response = serde_json::Json!({
          "status": "fail",
          "message": "User with that email already exists"
        });
        return Err((StatusCode::CONFLICT, Json(error_response)));
      }
  }
  let salt = SaltString::generate(&mut OSRng);
  let hashed_password = Argon2::default()
      .hash_password(body.password.as_bytes(), &salt)
      .map_err(|e| {
        let error_response = serde_json::Json!({
          "status": "fail",
          "message": format!("Error While Hashing Password: {}", e)
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
      })
      .map(|hash| hash.to_string())?;

  let user = sqlx::query_as!(
    User,
    "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
    body.name.to_string(),
    body.email.to_string().to_ascii_lowercase(),
    hashed_password
  )
  .fetch_one(&data_db)
  .await
  .map_err(|e| {
    let error_response = serde_json::json!({
      "status": "fail",
      "message": format!("Database Error: {}", e)
    })
    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
  })?;

  let user_response = serde_json::json!({
    "status": "Success",
    "data": serde_json::json!({
      "user": filter_user_record(&user)
    })
  })
  Ok(Json(user_response))
}