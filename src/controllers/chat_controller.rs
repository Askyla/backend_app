// src/controllers/chat_controller.rs

use crate::services::auth_service;
use crate::state::AppState;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use futures::StreamExt;
use reqwest;
use serde::Deserialize;
use serde_json::json; // Your shared state, e.g. containing a users_collection

/// Query parameters for GET /messages endpoint.
#[derive(Debug, Deserialize)]
pub struct GetMessagesQuery {
    pub agent_id: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default = "default_msg_object")]
    pub msg_object: bool,
}

fn default_limit() -> u32 {
    1000
}

fn default_msg_object() -> bool {
    true
}

/// GET /messages
/// This endpoint:
/// 1. Extracts and verifies the JWT token from the Authorization header.
/// 2. Checks that the user exists in the database.
/// 3. Calls the external API to fetch messages and returns the JSON response.
#[get("/messages")]
pub async fn get_messages(
    req: HttpRequest,
    query: web::Query<GetMessagesQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    // Extract Authorization header.
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|hv| hv.to_str().ok());
    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return HttpResponse::Unauthorized().json(json!({
                "detail": "Authorization header missing or invalid"
            }))
        }
    };

    // Verify the JWT token.
    let claims = match auth_service::verify_jwt_token(token) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::Unauthorized().json(json!({
                "detail": format!("Invalid token: {}", e)
            }))
        }
    };

    let user_email = claims.sub;
    // Check that the user exists.
    let user = match auth_service::get_user(&data.users_collection, &user_email).await {
        Ok(u) => u,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({
                "detail": format!("Database error: {}", e)
            }))
        }
    };
    if user.is_none() {
        return HttpResponse::NotFound().json(json!({ "detail": "User not found" }));
    }

    // Build the URL for the external API.
    let url = format!(
        "https://api.letta.com/v1/agents/{}/messages?limit={}&msg_object={}",
        query.agent_id, query.limit, query.msg_object
    );

    // Make a GET request to the external API.
    let client = reqwest::Client::new();
    let external_response = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", "N2RmODBkNzctY2E1YS00ODA5LWEyYWItMTUxODI1YTg4OWViOjAxZmU3YTJlLTNjOWMtNDM1Ni05MzYxLThlZDQ5ODE1YWQ5Mg=="))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({
                "detail": format!("Error fetching messages: {}", e)
            }))
        }
    };

    if !external_response.status().is_success() {
        return HttpResponse::InternalServerError().json(json!({
            "detail": "External API error"
        }));
    }

    // Parse the JSON response from the external API.
    let json_value = match external_response.json::<serde_json::Value>().await {
        Ok(val) => val,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({
                "detail": format!("Error parsing response: {}", e)
            }))
        }
    };

    HttpResponse::Ok().json(json_value)
}

/// POST /send_messages/{agent_id}
/// This endpoint:
/// 1. Extracts the token from the header.
/// 2. Reads and validates the JSON payload (ensuring required fields are present).
/// 3. Forwards the payload to an external API and streams the response back.
#[post("/send_messages/{agent_id}")]
pub async fn send_messages(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let agent_id = path.into_inner();

    // Extract Authorization header
    let auth_header = req.headers().get("Authorization").and_then(|hv| hv.to_str().ok());
    let _token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return HttpResponse::Unauthorized().json(json!({
                "detail": "Authorization header missing or invalid"
            }))
        }
    };

    // Validate request body
    let body_json = body.into_inner();
    if !body_json.get("messages").is_some()
        || !body_json.get("stream_steps").is_some()
        || !body_json.get("stream_tokens").is_some()
    {
        return HttpResponse::BadRequest().json(json!({
            "detail": "Missing required fields in the request body"
        }));
    }

    // External API URL
    let url = format!("https://api.letta.com/v1/agents/{}/messages", agent_id);
    let client = reqwest::Client::new();

    // Send POST request to external API
    let external_response = match client
        .post(&url)
        .header("Authorization", format!("Bearer {}", "N2RmODBkNzctY2E1YS00ODA5LWEyYWItMTUxODI1YTg4OWViOjAxZmU3YTJlLTNjOWMtNDM1Ni05MzYxLThlZDQ5ODE1YWQ5Mg=="))
        .header("Content-Type", "application/json")
        .json(&body_json)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({
                "detail": format!("Error sending messages: {}", e)
            }));
        }
    };
    
    println!("Response Status {}", external_response.status());
    if !external_response.status().is_success() {
        let status_code = external_response.status().as_u16();
        let error_body = external_response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return HttpResponse::InternalServerError().json(json!({
            "detail": "External API error",
            "status": status_code,
            "external_error": error_body,
            "data": body_json
        }));
    }

    // Stream response back to the client
    let byte_stream = external_response
        .bytes_stream()
        .map(|result| result.map_err(|e| actix_web::error::ErrorInternalServerError(e)));

    HttpResponse::Ok()
        .content_type("text/event-stream")
        .streaming(byte_stream)
}