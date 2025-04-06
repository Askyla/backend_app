pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub mongo_uri: String,
    pub mongo_db_name: String
}
// In your config.rs file

impl Config {
    pub fn from_env() -> Self {
        use std::env;
        Self {
            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: env::var("SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            mongo_uri: env::var("MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            mongo_db_name: env::var("MONGO_DB_NAME").unwrap_or_else(|_| "my_database".to_string()),
        }
    }
}
