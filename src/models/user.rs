use serde::{Deserialize, Serialize};
use mongodb::bson::oid::ObjectId;

/// Returns a new ObjectId as a hex string. This is used as the default for the `id` field.
fn default_id() -> String {
    ObjectId::new().to_hex()
}

/// A model representing a user, analogous to your Pydantic model.
///
/// Note:
/// - The `_id` field is renamed to `id` here, stored as a `String` (hex representation of ObjectId).
/// - `email_verified` will default to `false` if not provided.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserModel {
    /// Unique identifier for the user.
    /// We rename the field to `_id` when (de)serializing to match MongoDB’s default.
    #[serde(rename = "_id", default = "default_id")]
    pub id: String,

    /// The username for the user.
    pub username: String,

    /// The user’s email address.
    pub email: String,

    /// The associated agent id.
    pub agent_id: String,

    /// The user’s hashed password.
    pub hashed_password: String,

    /// Whether the user’s email has been verified.
    /// Defaults to `false` if omitted.
    #[serde(default)]
    pub email_verified: bool,
}
