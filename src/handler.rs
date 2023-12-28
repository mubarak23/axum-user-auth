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

pub async fn handle_user_login(
  State(data) : State<Arc<AppState>>,
  Json(body): Json<LoginUserSchema>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::value>)> {
  let user = sqlx::query_as!(
    User,
    "SELECT * FROM users WHERE email = $1",
    body.email.to_ascii_lowercase()
  )
  .fetch_optional(&data_db)
  .await
  .map_err(|e| {
    let error_response = serde_json::json!({
      "status": "fail",
      "message": format!("Database Error: {}", e)
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
  })?
  .ok_or_else(|| {
    let error_response = serde_json::Json!({
      "status": "fail",
      "message": "Invalid Password or Email"
    });
    (StatusCode.BAD_REQUEST, Json(error_response))
  })?;

  let is_valid = match PasswordHash::new(&user.password) {
    Ok(parsed_hash) => Argon2::default()
      .verify_password(body.password.as_bytes(), &parsed_hash)
      .map_or(false, |_|, true)
    Err(_) => false
  }

  if !is_valid {
      let error_response = serde_json::Json!({
        "status": "fail",
        "message": "Invalid Password or Email"
      });

      return Err((StatusCode::BAD_REQUEST, Json(error_response)));
  }

  let now = chrono::Utc::now();
  let iat = now.timestamp() as usize;
  let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
  let claims: TokenClaims = TokenClaims {
    sub: user.id.to_string(),
    exp,
    iat
  }

  let token = encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(data.env.jwt_secret.as_ref())
  )
  .unwrap()

  let cookie = Cookie::Build(("token", token.to_owned()))
      .path('/')
      .max_age(time::Duration::hours(1))
      .same_state(SameSite::Lax)
      http_only(true);

  let mut response = Response::new(json!({
    "status": "success",
    "token": token
    }).to_string()
  );

  response
    .headers_mut()
    .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
  Ok(response)  
}

pub async fn handle_user_logout() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::value>)> {
    let cookie = Cookie::build(("token", ""))
      .path('/')
      .max_age(time::Duration::hours(-1))
      .same_state(SameSite::Lax)
      http_only(true);

    let response = Response::new(json!({"status": "success"}).to_string());
      response.header_mut()
      .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    Ok(response)  
}

pub async fn handle_get_user(
  Extension(user): Extension<User>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::value>)> {
  let json_response = serde_json::json!({
    "status": "success",
    "data": serde_json::json!({
      "user": filter_user_record(&user)
    })
  });
  
  Ok(Json(json_response))
}
