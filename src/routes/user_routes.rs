// src/routes/user_routes.rs

use actix_web::web;
use crate::controllers::auth_controller::{
    register, login, protected_check, verify_email, resend_verification,
    forgot_password, reset_password,
};

/// Initializes the user routes by registering each endpoint within the `/users` scope.
pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .service(register)
            .service(login)
            .service(protected_check)
            .service(verify_email)
            .service(resend_verification)
            .service(forgot_password)
            .service(reset_password)
    );
}
