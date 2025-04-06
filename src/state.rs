// src/state.rs

use mongodb::Collection;
use crate::models::user::UserModel; // Adjust this path if needed

#[derive(Clone)]
pub struct AppState {
    pub users_collection: Collection<UserModel>,
    // Add more shared state fields as necessary.
}
