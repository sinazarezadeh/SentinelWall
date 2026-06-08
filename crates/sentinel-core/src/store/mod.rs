use std::path::Path;
use anyhow::Result;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use tracing::info;
use std::str::FromStr;

pub struct StateStore {
    pool: SqlitePool,
}

impl StateStore {
    pub async fn new(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let url = format!("sqlite://{}?mode=rwc", db_path.display());
        let opts = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        let pool = SqlitePool::connect_with(opts).await?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                banned_at TEXT NOT NULL,
                expires_at TEXT,
                ban_count INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS threat_events (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '[]'
            );

            CREATE INDEX IF NOT EXISTS idx_banned_ips_expires ON banned_ips(expires_at);
            CREATE INDEX IF NOT EXISTS idx_threat_events_ip ON threat_events(ip);
            CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp ON threat_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
        "#)
        .execute(&self.pool)
        .await?;

        info!("Database migrations applied");
        Ok(())
    }

    pub async fn save_rule(&self, id: &str, name: &str, data: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(r#"
            INSERT INTO rules (id, name, data, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                data = excluded.data,
                updated_at = excluded.updated_at
        "#)
        .bind(id)
        .bind(name)
        .bind(data)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_rules(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT id, data FROM rules ORDER BY rowid"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete_rule(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM rules WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn save_ban(&self, ip: &str, reason: &str, banned_at: &str, expires_at: Option<&str>, ban_count: i32, source: &str, evidence: &str) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO banned_ips (ip, reason, banned_at, expires_at, ban_count, source, evidence)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason,
                banned_at = excluded.banned_at,
                expires_at = excluded.expires_at,
                ban_count = excluded.ban_count,
                source = excluded.source,
                evidence = excluded.evidence
        "#)
        .bind(ip)
        .bind(reason)
        .bind(banned_at)
        .bind(expires_at)
        .bind(ban_count)
        .bind(source)
        .bind(evidence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_active_bans(&self) -> Result<Vec<serde_json::Value>> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = sqlx::query_as::<_, (String, String, String, Option<String>, i32, String, String)>(r#"
            SELECT ip, reason, banned_at, expires_at, ban_count, source, evidence
            FROM banned_ips
            WHERE expires_at IS NULL OR expires_at > ?1
        "#)
        .bind(&now)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(ip, reason, banned_at, expires_at, ban_count, source, evidence)| {
            serde_json::json!({
                "ip": ip,
                "reason": reason,
                "banned_at": banned_at,
                "expires_at": expires_at,
                "ban_count": ban_count,
                "source": source,
                "evidence": serde_json::from_str::<serde_json::Value>(&evidence).unwrap_or_default()
            })
        }).collect())
    }

    pub async fn remove_ban(&self, ip: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM banned_ips WHERE ip = ?1")
            .bind(ip)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn audit(&self, action: &str, actor: &str, target: Option<&str>, details: Option<&str>) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(r#"
            INSERT INTO audit_log (timestamp, action, actor, target, details)
            VALUES (?1, ?2, ?3, ?4, ?5)
        "#)
        .bind(&now)
        .bind(action)
        .bind(actor)
        .bind(target)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn save_threat_event(&self, id: &str, ip: &str, threat_type: &str, severity: &str, confidence: f64, timestamp: &str, description: &str, evidence: &str) -> Result<()> {
        sqlx::query(r#"
            INSERT OR IGNORE INTO threat_events (id, ip, threat_type, severity, confidence, timestamp, description, evidence)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#)
        .bind(id)
        .bind(ip)
        .bind(threat_type)
        .bind(severity)
        .bind(confidence)
        .bind(timestamp)
        .bind(description)
        .bind(evidence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
