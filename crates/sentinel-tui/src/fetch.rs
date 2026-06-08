use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

pub struct ApiClient {
    pub base_url: String,
    pub token: Option<String>,
    client: Client,
}

impl ApiClient {
    pub fn new(base_url: String, token: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .user_agent(format!("sentinel-tui/{}", sentinel_core::VERSION))
            .build()
            .unwrap_or_default();
        Self { base_url, token, client }
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await?;
        let json = resp.json::<Value>().await?;
        Ok(json)
    }

    pub async fn get_status(&self) -> Result<Value> {
        self.get("/api/v1/status").await
    }

    pub async fn get_rules(&self) -> Result<Vec<Value>> {
        let resp = self.get("/api/v1/rules").await?;
        Ok(resp["data"].as_array().cloned().unwrap_or_default())
    }

    pub async fn get_bans(&self) -> Result<Vec<Value>> {
        let resp = self.get("/api/v1/bans").await?;
        Ok(resp["data"].as_array().cloned().unwrap_or_default())
    }

    pub async fn check_connection(&self) -> bool {
        self.get("/health").await.is_ok()
    }
}
