use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    pub fn err(msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(msg.into()),
            timestamp: Utc::now(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Serialize, Deserialize)]
pub struct BanRequest {
    pub ip: IpAddr,
    pub reason: String,
    pub duration_secs: Option<u64>,
    pub permanent: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: i64,
    pub rules_count: u64,
    pub bans_count: u64,
    pub threats_today: u64,
    pub backend: String,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub features: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct GeoLookupResponse {
    pub ip: IpAddr,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub is_tor: bool,
    pub is_banned: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub search: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

impl Default for QueryParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            per_page: Some(50),
            search: None,
            sort: None,
            order: None,
        }
    }
}
