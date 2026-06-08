use anyhow::{Result, bail};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::debug;

#[derive(Clone)]
pub struct Context {
    pub api: String,
    pub token: Option<String>,
    pub json_output: bool,
    pub dry_run: bool,
    client: Client,
}

impl Context {
    pub fn new(api: String, token: Option<String>, json_output: bool, dry_run: bool) -> Self {
        let client = Client::builder()
            .user_agent(format!("sentinel-cli/{}", sentinel_core::VERSION))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { api, token, json_output, dry_run, client }
    }

    pub fn get(&self, path: &str) -> RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    pub fn post(&self, path: &str) -> RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    pub fn put(&self, path: &str) -> RequestBuilder {
        self.request(reqwest::Method::PUT, path)
    }

    pub fn delete(&self, path: &str) -> RequestBuilder {
        self.request(reqwest::Method::DELETE, path)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.api, path);
        debug!("{} {}", method, url);

        let mut req = self.client.request(method, &url);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        req
    }

    pub async fn send_and_parse<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T> {
        let response = req.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let error: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let msg = error.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or(&body);
            bail!("API error {}: {}", status, msg);
        }

        let json = response.json::<T>().await?;
        Ok(json)
    }

    pub async fn send(&self, req: RequestBuilder) -> Result<Value> {
        self.send_and_parse::<Value>(req).await
    }
}
