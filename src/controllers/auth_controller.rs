// src/controllers/auth_controller.rs

use actix_web::{post, web, Error, HttpRequest, HttpResponse};
use chrono::Duration;
use mongodb::bson::oid::ObjectId;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;

use crate::models::user::UserModel;
use crate::services::auth_service;
use crate::services::auth_service::Claims;
use crate::state::AppState; // AppState is defined in src/state.rs

/// Constant representing the token expiration time in minutes.
const ACCESS_TOKEN_EXPIRE_MINUTES: i64 = 1440;

/// Request structure for the registration endpoint.
#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirmation: String,
}

/// Response structure for endpoints that return an access token.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
}

/// Request structure for the verify-email endpoint.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailForm {
    pub email: String,
    pub code: String,
}

/// Request structure for the resend-verification endpoint.
#[derive(Debug, Deserialize)]
pub struct ResendVerificationForm {
    pub email: String,
}

/// Request structure for the login endpoint.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

/// Request structure for the forgot-password endpoint.
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordForm {
    pub email: String,
}

/// Request structure for the reset-password endpoint.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordForm {
    pub email: String,
    pub token: String,
    pub new_password: String,
    pub password_confirmation: String,
}

/// POST /register
/// Registers a new user. This endpoint:
/// - Validates the passwords.
/// - Checks if the email is already registered.
/// - Calls an external agent-creation API.
/// - Creates a new user (with password hashing in the service layer).
/// - Sends a verification email (spawned as a background task).
/// - Returns a JWT access token.
#[post("/register")]
pub async fn register(
    form: web::Form<RegisterForm>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    // Validate password confirmation.
    if form.password != form.password_confirmation {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Passwords do not match"
        })));
    }

    // Check if a user with this email already exists.
    let existing_user = auth_service::get_user(&data.users_collection, &form.email)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    if existing_user.is_some() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Email already registered"
        })));
    }

    let client = Client::new();

    // Build the request body
    let request_body = json!({
        "name": form.username,
        "from_template": "askyla_template:latest"
    });

    // Send POST request
    let agent_resp = client
        .post("https://api.letta.com/v1/agents/")
        .header("Authorization", "Bearer N2RmODBkNzctY2E1YS00ODA5LWEyYWItMTUxODI1YTg4OWViOjAxZmU3YTJlLTNjOWMtNDM1Ni05MzYxLThlZDQ5ODE1YWQ5Mg==") // <-- Add token after Bearer
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to send request: {}", e)))?;

    // Print full response
    let resp_text = agent_resp
        .text()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read response: {}", e)))?;

    println!("API Response: {}", resp_text);

    // Parse the response again as JSON to extract agent_id
    let agent_json: Value = serde_json::from_str(&resp_text)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Invalid JSON: {}", e)))?;

    let agent_id = agent_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            actix_web::error::ErrorInternalServerError("Agent ID missing in response")
        })?;


    // Create the new user.
    let new_user = UserModel {
        id: ObjectId::new().to_hex(),
        username: form.username.clone(),
        email: form.email.clone(),
        agent_id: agent_id.to_string(),
        // The service will hash this password.
        hashed_password: form.password.clone(),
        email_verified: false,
    };

    auth_service::create_user(&data.users_collection, new_user)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Send verification email in a background task.
    let users_collection_clone = data.users_collection.clone();
    let email_clone = form.email.clone();
    actix_web::rt::spawn(async move {
        let _ = auth_service::send_verification_email(&users_collection_clone, &email_clone).await;
    });

    // Create an access token.
    let claims = Claims {
        sub: form.email.clone(),
        exp: 0, // This field will be set in the service.
    };
    let token = auth_service::create_access_token(
        claims,
        Some(Duration::minutes(ACCESS_TOKEN_EXPIRE_MINUTES)),
    )
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token: token,
        token_type: "bearer".into(),
    }))
}

/// POST /protected-check
/// Checks that the request is authenticated by extracting and verifying a JWT token.
#[post("/protected-check")]
pub async fn protected_check(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|hv| hv.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return Ok(HttpResponse::Unauthorized().json(json!({
                "detail": "Invalid or missing Authorization header"
            })))
        }
    };

    let claims = auth_service::verify_jwt_token(token)
        .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?;
    let user_email = claims.sub;

    let user = auth_service::get_user(&data.users_collection, &user_email)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if user.is_none() {
        return Ok(HttpResponse::NotFound().json(json!({ "detail": "User not found" })));
    }

    Ok(HttpResponse::Ok().json(json!({
        "message": "User is authenticated",
        "user": user.unwrap()
    })))
}

/// POST /verify-email
/// Verifies a user's email using a code.
#[post("/verify-email")]
pub async fn verify_email(
    form: web::Form<VerifyEmailForm>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let verified = auth_service::verify_email_code(&data.users_collection, &form.email, &form.code)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if !verified {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Invalid verification code"
        })));
    }

    Ok(HttpResponse::Ok().json(json!({ "message": "Email verified successfully" })))
}

/// POST /resend-verification
/// Resends the verification email.
#[post("/resend-verification")]
pub async fn resend_verification(
    form: web::Form<ResendVerificationForm>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let existing_user = auth_service::get_user(&data.users_collection, &form.email)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    if existing_user.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Email not registered"
        })));
    }

    let users_collection_clone = data.users_collection.clone();
    let email_clone = form.email.clone();
    actix_web::rt::spawn(async move {
        let _ = auth_service::send_verification_email(&users_collection_clone, &email_clone).await;
    });

    Ok(HttpResponse::Ok().json(json!({ "message": "Verification email resent successfully" })))
}

/// POST /login
/// Logs in a user and returns a JWT token.
#[post("/login")]
pub async fn login(
    form: web::Form<LoginForm>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let user = auth_service::get_user(&data.users_collection, &form.email)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let user = match user {
        Some(u) => u,
        None => {
            return Ok(HttpResponse::BadRequest().json(json!({
                "detail": "Invalid credentials"
            })))
        }
    };

    if !auth_service::verify_password(&form.password, &user.hashed_password) {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Invalid credentials"
        })));
    }

    if !user.email_verified {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Email not verified"
        })));
    }

    let claims = Claims {
        sub: form.email.clone(),
        exp: 0,
    };

    let token = auth_service::create_access_token(
        claims,
        Some(Duration::minutes(ACCESS_TOKEN_EXPIRE_MINUTES)),
    )
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token: token,
        token_type: "bearer".into(),
    }))
}

/// POST /forgot-password
/// Sends a password reset email.
#[post("/forgot-password")]
pub async fn forgot_password(
    form: web::Form<ForgotPasswordForm>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let user = auth_service::get_user(&data.users_collection, &form.email)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    if user.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Email not found"
        })));
    }

    let _reset_token = auth_service::reset_password_email(&data.users_collection, &form.email)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "Password reset link sent to your email"
    })))
}

/// POST /reset-password
/// Resets the user's password after validating the reset token.
#[post("/reset-password")]
pub async fn reset_password(
    form: web::Form<ResetPasswordForm>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if form.new_password != form.password_confirmation {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Passwords do not match"
        })));
    }

    let is_valid =
        auth_service::verify_password_reset_token(&data.users_collection, &form.email, &form.token)
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if !is_valid {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Invalid or expired reset token"
        })));
    }

    let updated = auth_service::update_password(
        &data.users_collection,
        &form.email,
        &form.new_password,
        &form.token,
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if !updated {
        return Ok(HttpResponse::BadRequest().json(json!({
            "detail": "Password update failed"
        })));
    }

    Ok(HttpResponse::Ok().json(json!({ "message": "Password has been reset successfully" })))
}
