use actix_web::web;

mod user_routes;  // Module for user endpoints
mod chat_routes;  // Module for chat endpoints

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(user_routes::init) // Register user routes
            .configure(chat_routes::init) // Register chat routes
    );
}
