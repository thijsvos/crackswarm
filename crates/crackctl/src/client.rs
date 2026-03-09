use std::path::Path;

use anyhow::{Context, Result};
use crack_common::models::*;
use serde::{Deserialize, Serialize};

// ── Types local to the CLI client ──

#[derive(Debug, Deserialize)]
pub struct TaskDetail {
    #[serde(flatten)]
    pub task: Task,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Deserialize)]
pub struct PotfileStats {
    pub total_cracked: u64,
    pub unique_hashes: u64,
    pub unique_plaintexts: u64,
}

/// Mirrors `CreateTaskRequest` but with Serialize so we can send JSON.
#[derive(Debug, Serialize)]
pub struct CreateTaskPayload {
    pub name: String,
    pub hash_mode: u32,
    pub hash_file_id: String,
    pub attack_config: AttackConfig,
    pub priority: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AuthorizeWorkerPayload {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
struct UpdateTaskPayload {
    pub status: TaskStatus,
}

/// Error body returned by the coordinator API.
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

// ── Client ──

pub struct Client {
    http: reqwest::Client,
    base_url: String,
}

impl Client {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Check for HTTP error status and attempt to parse a JSON error body.
    async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
        if resp.status().is_success() {
            return Ok(resp);
        }

        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<failed to read response body>"));

        let message = serde_json::from_str::<ErrorResponse>(&body)
            .map(|e| e.error)
            .unwrap_or(body);

        anyhow::bail!("HTTP {status}: {message}");
    }

    // ── Tasks ──

    pub async fn create_task(&self, req: CreateTaskPayload) -> Result<Task> {
        let resp = self
            .http
            .post(self.url("/api/v1/tasks"))
            .json(&req)
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let task: Task = resp.json().await.context("failed to parse task response")?;
        Ok(task)
    }

    pub async fn list_tasks(&self) -> Result<Vec<Task>> {
        let resp = self
            .http
            .get(self.url("/api/v1/tasks"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let tasks: Vec<Task> = resp.json().await.context("failed to parse tasks")?;
        Ok(tasks)
    }

    pub async fn get_task(&self, id: &str) -> Result<TaskDetail> {
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/tasks/{id}")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let detail: TaskDetail = resp.json().await.context("failed to parse task detail")?;
        Ok(detail)
    }

    pub async fn cancel_task(&self, id: &str) -> Result<()> {
        let payload = UpdateTaskPayload {
            status: TaskStatus::Cancelled,
        };

        let resp = self
            .http
            .patch(self.url(&format!("/api/v1/tasks/{id}")))
            .json(&payload)
            .send()
            .await
            .context("failed to reach coordinator")?;

        Self::check(resp).await?;
        Ok(())
    }

    pub async fn delete_task(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.url(&format!("/api/v1/tasks/{id}")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        Self::check(resp).await?;
        Ok(())
    }

    pub async fn get_task_results(&self, id: &str) -> Result<Vec<CrackedHash>> {
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/tasks/{id}/results")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let results: Vec<CrackedHash> = resp.json().await.context("failed to parse results")?;
        Ok(results)
    }

    // ── Files ──

    pub async fn upload_file(&self, path: &Path, file_type: &str) -> Result<FileRecord> {
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "upload".to_string());

        let file_bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read file: {}", path.display()))?;

        let file_part = reqwest::multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("application/octet-stream")
            .context("invalid MIME")?;

        let form = reqwest::multipart::Form::new()
            .part("file", file_part)
            .text("file_type", file_type.to_string());

        let resp = self
            .http
            .post(self.url("/api/v1/files"))
            .multipart(form)
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let record: FileRecord = resp.json().await.context("failed to parse file record")?;
        Ok(record)
    }

    pub async fn list_files(&self) -> Result<Vec<FileRecord>> {
        let resp = self
            .http
            .get(self.url("/api/v1/files"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let files: Vec<FileRecord> = resp.json().await.context("failed to parse files")?;
        Ok(files)
    }

    // ── Workers ──

    pub async fn list_workers(&self) -> Result<Vec<Worker>> {
        let resp = self
            .http
            .get(self.url("/api/v1/workers"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let workers: Vec<Worker> = resp.json().await.context("failed to parse workers")?;
        Ok(workers)
    }

    pub async fn authorize_worker(&self, pubkey: &str, name: &str) -> Result<()> {
        let payload = AuthorizeWorkerPayload {
            public_key: pubkey.to_string(),
            name: name.to_string(),
        };

        let resp = self
            .http
            .post(self.url("/api/v1/workers/authorize"))
            .json(&payload)
            .send()
            .await
            .context("failed to reach coordinator")?;

        Self::check(resp).await?;
        Ok(())
    }

    // ── System / Potfile ──

    pub async fn get_status(&self) -> Result<SystemStatus> {
        let resp = self
            .http
            .get(self.url("/api/v1/status"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let status: SystemStatus = resp.json().await.context("failed to parse status")?;
        Ok(status)
    }

    pub async fn get_potfile_stats(&self) -> Result<PotfileStats> {
        let resp = self
            .http
            .get(self.url("/api/v1/potfile/stats"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let stats: PotfileStats = resp.json().await.context("failed to parse potfile stats")?;
        Ok(stats)
    }

    pub async fn export_potfile(&self) -> Result<Vec<String>> {
        let resp = self
            .http
            .get(self.url("/api/v1/potfile/plaintexts"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let body = resp.text().await.context("failed to read potfile body")?;

        let plaintexts: Vec<String> = body
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();

        Ok(plaintexts)
    }
}
