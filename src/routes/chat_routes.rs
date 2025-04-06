// src/routes/chat_routes.rs

use actix_web::web;
use crate::controllers::chat_controller::{ get_messages, send_messages };

/// Initializes the chat routes by registering each endpoint within the `/chat` scope.
/// For example, the endpoints will be available at `/chat/messages` and `/chat/send_messages/{agent_id}`.
pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/chat")
            .service(get_messages)
            .service(send_messages)
    );
}
