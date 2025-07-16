use argon2::password_hash::{rand_core::OsRng, PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use std::collections::HashMap;

pub struct Auth {
    users: HashMap<String, String>, // store username -> hashed password
}

impl Auth {
    pub fn new() -> Self {
        Auth {
            users: HashMap::new(),
        }
    }

    pub fn signup(&mut self, username: &str, password: &str) -> Result<(), String> {
        if self.users.contains_key(username) {
            return Err("Username already exists".into());
        }

        let hash = Self::hash_password(password)?;
        self.users.insert(username.to_string(), hash);
        Ok(())
    }

    pub fn login(&self, username: &str, password: &str) -> Result<(), String> {
        match self.users.get(username) {
            Some(stored_hash) => {
                let parsed_hash =
                    PasswordHash::new(stored_hash).map_err(|_| "Stored hash format invalid")?;

                if Argon2::default()
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    Ok(())
                } else {
                    Err("Invalid password".into())
                }
            }
            None => Err("Username not found".into()),
        }
    }

    fn hash_password(password: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|ph| ph.to_string())
            .map_err(|e| e.to_string())
    }
}
