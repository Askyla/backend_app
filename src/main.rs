use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use dotenv::dotenv;
use env_logger;

mod config;
mod controllers;
mod db;
mod models;
mod routes;
mod services;
mod state;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file (if exists)
    dotenv().ok();
    env_logger::init();

    // Read configuration (e.g., server host, port, MongoDB URI, and database name)
    let config = config::Config::from_env();

    // Initialize MongoDB client
    let db_client = db::init_db(&config.mongo_uri)
        .await
        .expect("Failed to connect to MongoDB");

    // Get a handle to the desired database and collection
    let db = db_client.database(&config.mongo_db_name);
    let users_collection = db.collection::<models::user::UserModel>("users");

    // Create the shared application state.
    let app_state = state::AppState { 
        users_collection,
    };

    // Build and run the HTTP server.
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default()) // Logging middleware
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600),
            ) // CORS setup
            .app_data(web::Data::new(app_state.clone()))
            .configure(routes::init) // Registers your routes from routes/mod.rs
    })
    .bind((config.server_host, config.server_port))?
    .run()
    .await
}
