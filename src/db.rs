use mongodb::{options::ClientOptions, Client};
use mongodb::error::Error;

pub async fn init_db(uri: &str) -> Result<Client, Error> {
    let mut client_options = ClientOptions::parse(uri).await?;
    // Optionally, set more options (e.g., connection pool settings)
    client_options.app_name = Some("Ask".to_string());
    Client::with_options(client_options)
}
