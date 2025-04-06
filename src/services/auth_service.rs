// src/services/auth_service.rs

use std::env;
use mongodb::{
    bson:: doc,
    Collection,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, errors::Error as JwtError};
use chrono::{Utc, Duration};
use rand::{distributions::Alphanumeric, Rng};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use serde::{Serialize, Deserialize};

use crate::models::user::UserModel;

/// JWT Claims structure – you can customize this to include other fields if needed.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (e.g. user id or email)
    pub sub: String,
    /// Expiration time (as UTC timestamp)
    pub exp: usize,
}

/// Verifies a plain password against a hashed password.
pub fn verify_password(plain_password: &str, hashed_password: &str) -> bool {
    verify(plain_password, hashed_password).unwrap_or(false)
}

/// Hashes a password using bcrypt.
pub fn get_password_hash(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

/// Creates an access token (JWT) with the provided claims and optional expiration duration.
/// If no expiration delta is provided, the token will expire in 15 minutes.
pub fn create_access_token(mut claims: Claims, expires_delta: Option<Duration>) -> Result<String, JwtError> {
    let expire = match expires_delta {
        Some(delta) => Utc::now() + delta,
        None => Utc::now() + Duration::minutes(15),
    };
    claims.exp = expire.timestamp() as usize;

    let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    // Here we assume HS256; you can customize the header if you need a different algorithm.
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key.as_ref()))?;
    Ok(token)
}

/// Verifies a JWT token and returns the decoded claims if valid.
pub fn verify_jwt_token(token: &str) -> Result<Claims, JwtError> {
    let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    let validation = Validation::default();
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret_key.as_ref()), &validation)?;
    Ok(token_data.claims)
}

/// Retrieves a user from the MongoDB collection by email.
pub async fn get_user(collection: &Collection<UserModel>, email: &str) -> mongodb::error::Result<Option<UserModel>> {
    collection.find_one(doc! { "email": email }, None).await
}

/// Creates a new user by hashing the provided password and inserting the user into MongoDB.
/// The user's email_verified field is set to false.
pub async fn create_user(collection: &Collection<UserModel>, mut user: UserModel) -> mongodb::error::Result<UserModel> {
    // Hash the password.
    let hashed = get_password_hash(&user.hashed_password)
        .map_err(|e| mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    user.hashed_password = hashed;
    user.email_verified = false;

    // Insert the user into the database.
    collection.insert_one(&user, None).await?;
    Ok(user)
}

/// Sends an email containing a verification code to the specified email address.
/// The code is saved in the database (added to the user document) for later verification.
pub async fn send_verification_email(
    collection: &Collection<UserModel>,
    email: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Generate a random 6-character verification code.
    let verification_code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    // Update the user document with the verification code.
    collection
        .update_one(
            doc! { "email": email },
            doc! { "$set": { "verification_code": &verification_code } },
            None,
        )
        .await?;

    // Load SMTP configuration from environment variables.
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER must be set");
    let smtp_port: u16 = env::var("SMTP_PORT")
        .unwrap_or_else(|_| "587".to_string())
        .parse()?;
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    let email_from = env::var("EMAIL_FROM").expect("EMAIL_FROM must be set");

    // Build the email message.
    let email_message = Message::builder()
        .from(email_from.parse()?)
        .to(email.parse()?)
        .subject("Verify Your Email")
        .body(format!("Your verification code is: {}", verification_code))?;

    // Configure the SMTP mailer using STARTTLS.
    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::starttls_relay(&smtp_server)?
        .port(smtp_port)
        .credentials(creds)
        .build();

    // Send the email and handle the result.
    match mailer.send(&email_message) {
        Ok(response) => {
            println!("Email sent successfully to {}: {:?}", email, response);
        }
        Err(e) => {
            println!("Failed to send email to {}: {:?}", email, e);
            return Err(Box::new(e));
        }
    }

    Ok(verification_code)
}

/// Verifies the email by comparing the provided code with the one stored in the database.
/// If the code matches, the user's email_verified status is set to true and the code is removed.
pub async fn verify_email_code(collection: &Collection<UserModel>, email: &str, code: &str) -> mongodb::error::Result<bool> {
    let filter = doc! { "email": email, "verification_code": code };
    let update = doc! {
        "$set": { "email_verified": true },
        "$unset": { "verification_code": "" }
    };

    let update_result = collection.update_one(filter, update, None).await?;
    Ok(update_result.modified_count > 0)
}

/// Sends a password reset email with a randomly generated reset token to the specified email address.
/// The token is saved in the database so that it can be verified later.
pub async fn reset_password_email(collection: &Collection<UserModel>, email: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Generate a random 8-character reset token.
    let reset_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    // Update the user document with the reset token.
    collection.update_one(
        doc! { "email": email },
        doc! { "$set": { "reset_token": &reset_token } },
        None
    ).await?;

    // Load SMTP configuration from environment variables.
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER must be set");
    let smtp_port: u16 = env::var("SMTP_PORT").unwrap_or_else(|_| "587".to_string()).parse()?;
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    let email_from = env::var("EMAIL_FROM").expect("EMAIL_FROM must be set");

    // Build the email message.
    let email_message = Message::builder()
        .from(email_from.parse()?)
        .to(email.parse()?)
        .subject("Password Reset Request")
        .body(format!("Your password reset token is: {}", reset_token))?;

    // Configure the SMTP mailer.
    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::relay(&smtp_server)?
        .port(smtp_port)
        .credentials(creds)
        .build();

    // Send the email.
    mailer.send(&email_message)?;
    Ok(reset_token)
}

/// Verifies whether the provided password reset token matches the token stored in the user's record.
pub async fn verify_password_reset_token(collection: &Collection<UserModel>, email: &str, token: &str) -> mongodb::error::Result<bool> {
    let filter = doc! { "email": email, "reset_token": token };
    let user = collection.find_one(filter, None).await?;
    Ok(user.is_some())
}

/// Updates the user's password if the provided reset token is valid.
/// The new password is hashed before being saved, and the reset token is removed.
pub async fn update_password(collection: &Collection<UserModel>, email: &str, new_password: &str, token: &str) -> mongodb::error::Result<bool> {
    if verify_password_reset_token(collection, email, token).await? {
        let hashed_password = get_password_hash(new_password)
            .map_err(|e| mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        let update = doc! {
            "$set": { "hashed_password": hashed_password },
            "$unset": { "reset_token": "" }
        };
        let update_result = collection.update_one(doc! { "email": email }, update, None).await?;
        return Ok(update_result.modified_count > 0);
    }
    Ok(false)
}
