use std::sync::Arc

use axum::{
  middleware,
  routing::{post,get},
  Router
},

use crate::{
    handler::{
      get_me_handler, health_checker_handler, register_user_handler,
      handle_user_login, handle_user_logout, handle_get_user
    },
    jwt_auth::auth,
    AppState
}

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router.new()
        .route("/api/healthchecker", get(health_checker_handler))
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(handle_user_login))
        .route(
          "/api/auth/logout", 
            get(handle_user_logout)
            .route_layer(middleware::from_fn_with_state(app_state.clone(), auth))
        )
        .route(
          "/api/users/me",
             get(handle_get_user)
              .route_layer(middleware::from_fn_with_state(app_state.clone(), auth))
        )
        .with_state(app_state)

        
}