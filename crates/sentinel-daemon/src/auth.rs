use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString};
use rand::rngs::OsRng;
use chrono::{Utc, Duration};
use uuid::Uuid;
use anyhow::{Result, bail};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

impl Role {
    pub fn can_write(&self) -> bool {
        matches!(self, Role::Admin | Role::Operator)
    }

    pub fn can_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub last_login: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub role: Role,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub last_used: Option<chrono::DateTime<Utc>>,
}

pub struct AuthManager {
    secret: Vec<u8>,
    users: Arc<RwLock<HashMap<String, User>>>,
    api_tokens: Arc<RwLock<HashMap<String, ApiToken>>>,
    revoked_tokens: Arc<RwLock<std::collections::HashSet<String>>>,
    token_expiry_hours: i64,
}

impl AuthManager {
    pub fn new(secret: Option<String>) -> Self {
        let secret = secret
            .unwrap_or_else(|| {
                let s: String = (0..32).map(|_| rand::random::<char>()).collect();
                tracing::warn!("No JWT secret configured — using random secret (tokens will not survive restart)");
                s
            })
            .into_bytes();

        let mut manager = Self {
            secret,
            users: Arc::new(RwLock::new(HashMap::new())),
            api_tokens: Arc::new(RwLock::new(HashMap::new())),
            revoked_tokens: Arc::new(RwLock::new(std::collections::HashSet::new())),
            token_expiry_hours: 24,
        };

        // Create default admin user
        manager.create_default_admin();
        manager
    }

    fn create_default_admin(&mut self) {
        let password = std::env::var("SENTINEL_ADMIN_PASSWORD")
            .unwrap_or_else(|_| "changeme123".to_string());

        let hash = self.hash_password(&password)
            .unwrap_or_else(|_| "$argon2id$v=19$m=65536,t=3,p=4$placeholder".to_string());

        let admin = User {
            id: Uuid::new_v4(),
            username: "admin".to_string(),
            password_hash: hash,
            role: Role::Admin,
            enabled: true,
            created_at: Utc::now(),
            last_login: None,
        };

        self.users.write().insert("admin".to_string(), admin);
        tracing::info!("Default admin user created (change password immediately in production!)");
    }

    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
        Ok(hash.to_string())
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> bool {
        let argon2 = Argon2::default();
        match PasswordHash::new(hash) {
            Ok(parsed_hash) => argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok(),
            Err(_) => false,
        }
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<User> {
        let users = self.users.read();
        let user = users.get(username)?;

        if !user.enabled {
            return None;
        }

        if self.verify_password(password, &user.password_hash) {
            Some(user.clone())
        } else {
            None
        }
    }

    pub fn generate_token(&self, user: &User) -> Result<(String, chrono::DateTime<Utc>)> {
        let now = Utc::now();
        let expires = now + Duration::hours(self.token_expiry_hours);

        let claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            role: format!("{:?}", user.role).to_lowercase(),
            exp: expires.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&self.secret),
        )?;

        Ok((token, expires))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        // Check revocation list
        if self.revoked_tokens.read().contains(token) {
            bail!("Token has been revoked");
        }

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&self.secret),
            &Validation::new(Algorithm::HS256),
        )?;

        Ok(token_data.claims)
    }

    pub fn revoke_token(&self, jti: &str) {
        self.revoked_tokens.write().insert(jti.to_string());
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        self.users.read().get(username).cloned()
    }

    pub fn create_user(&self, username: String, password: String, role: Role) -> Result<User> {
        let hash = self.hash_password(&password)?;
        let user = User {
            id: Uuid::new_v4(),
            username: username.clone(),
            password_hash: hash,
            role,
            enabled: true,
            created_at: Utc::now(),
            last_login: None,
        };
        self.users.write().insert(username, user.clone());
        Ok(user)
    }

    pub fn list_users(&self) -> Vec<UserInfo> {
        self.users.read().values().map(|u| UserInfo {
            id: u.id,
            username: u.username.clone(),
            role: u.role.clone(),
        }).collect()
    }

    pub fn create_api_token(&self, name: String, role: Role, expires_in_days: Option<u64>) -> Result<(String, ApiToken)> {
        let raw_token = format!("sntl_{}", Uuid::new_v4().to_string().replace('-', ""));
        let token_hash = {
            use sha2::{Sha256, Digest};
            hex::encode(Sha256::digest(raw_token.as_bytes()))
        };

        let api_token = ApiToken {
            id: Uuid::new_v4(),
            name,
            token_hash: token_hash.clone(),
            role,
            created_at: Utc::now(),
            expires_at: expires_in_days.map(|d| Utc::now() + Duration::days(d as i64)),
            last_used: None,
        };

        self.api_tokens.write().insert(token_hash, api_token.clone());
        Ok((raw_token, api_token))
    }

    pub fn validate_api_token(&self, token: &str) -> Option<ApiToken> {
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(token.as_bytes()));

        let tokens = self.api_tokens.read();
        let api_token = tokens.get(&hash)?;

        if let Some(expires) = api_token.expires_at {
            if Utc::now() > expires {
                return None;
            }
        }

        Some(api_token.clone())
    }
}
