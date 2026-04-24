use std::path::Path;

use anyhow::{Context, Result};
use crack_common::models::*;
use futures_util::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

/// Files this size or larger get a live progress bar on upload. Smaller
/// files stream silently — same behaviour as before, just without the
/// full-file-in-RAM read.
const PROGRESS_THRESHOLD_BYTES: u64 = 100 * 1024 * 1024;

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

#[derive(Debug, Deserialize)]
pub struct CampaignDetailResponse {
    #[serde(flatten)]
    pub campaign: Campaign,
    pub phases: Vec<CampaignPhase>,
}

#[derive(Debug, Serialize)]
pub struct CreateCampaignPayload {
    pub name: String,
    pub hash_mode: u32,
    pub hash_file_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    pub priority: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wordlist_file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_file_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpdateCampaignPayload {
    pub status: CampaignStatus,
}

#[derive(Debug, Serialize)]
struct AuthorizeWorkerPayload {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct ServerInfo {
    #[allow(dead_code)]
    pub files_dir: String,
    pub device_id: u64,
}

#[derive(Debug, Serialize)]
struct HardlinkPayload {
    pub source_path: String,
    pub file_type: String,
    pub filename: String,
}

#[derive(Debug, Serialize)]
struct EnrollWorkerPayload {
    pub name: String,
    pub expires_minutes: u64,
}

#[derive(Debug, Deserialize)]
pub struct EnrollWorkerResponse {
    pub token: String,
    #[allow(dead_code)]
    pub message: String,
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

    // ── Campaigns ──

    pub async fn create_campaign(&self, req: CreateCampaignPayload) -> Result<Campaign> {
        let resp = self
            .http
            .post(self.url("/api/v1/campaigns"))
            .json(&req)
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let campaign: Campaign = resp
            .json()
            .await
            .context("failed to parse campaign response")?;
        Ok(campaign)
    }

    pub async fn list_campaigns(&self) -> Result<Vec<Campaign>> {
        let resp = self
            .http
            .get(self.url("/api/v1/campaigns"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let campaigns: Vec<Campaign> = resp.json().await.context("failed to parse campaigns")?;
        Ok(campaigns)
    }

    pub async fn get_campaign(&self, id: &str) -> Result<CampaignDetailResponse> {
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/campaigns/{id}")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let detail: CampaignDetailResponse = resp
            .json()
            .await
            .context("failed to parse campaign detail")?;
        Ok(detail)
    }

    pub async fn start_campaign(&self, id: &str) -> Result<Campaign> {
        let resp = self
            .http
            .post(self.url(&format!("/api/v1/campaigns/{id}/start")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let campaign: Campaign = resp.json().await.context("failed to parse campaign")?;
        Ok(campaign)
    }

    pub async fn cancel_campaign(&self, id: &str) -> Result<()> {
        let payload = UpdateCampaignPayload {
            status: CampaignStatus::Cancelled,
        };

        let resp = self
            .http
            .patch(self.url(&format!("/api/v1/campaigns/{id}")))
            .json(&payload)
            .send()
            .await
            .context("failed to reach coordinator")?;

        Self::check(resp).await?;
        Ok(())
    }

    pub async fn delete_campaign(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.url(&format!("/api/v1/campaigns/{id}")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        Self::check(resp).await?;
        Ok(())
    }

    pub async fn get_campaign_results(&self, id: &str) -> Result<Vec<CrackedHash>> {
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/campaigns/{id}/results")))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let results: Vec<CrackedHash> = resp.json().await.context("failed to parse results")?;
        Ok(results)
    }

    pub async fn list_templates(&self) -> Result<Vec<CampaignTemplate>> {
        let resp = self
            .http
            .get(self.url("/api/v1/campaigns/templates"))
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let templates: Vec<CampaignTemplate> =
            resp.json().await.context("failed to parse templates")?;
        Ok(templates)
    }

    // ── Files ──

    pub async fn upload_file(&self, path: &Path, file_type: &str) -> Result<FileRecord> {
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "upload".to_string());

        // Same-host fast path: if the source file lives on the same
        // filesystem as the coord's files_dir, ask the coord to hard-link
        // it in place instead of transferring bytes.
        #[cfg(unix)]
        if let Some(record) = self.try_hardlink_upload(path, &file_name, file_type).await {
            return Ok(record);
        }

        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("failed to open file: {}", path.display()))?;
        let size = file
            .metadata()
            .await
            .with_context(|| format!("stat failed for {}", path.display()))?
            .len();

        // A hidden progress bar still accepts `.inc(n)` calls without any
        // output, so we can wire the stream once and let the threshold
        // decide whether anything shows up on-screen.
        let pb = if size >= PROGRESS_THRESHOLD_BYTES {
            let bar = ProgressBar::new(size);
            bar.set_style(
                ProgressStyle::with_template(
                    "{msg} [{bar:30.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
                )
                .unwrap()
                .progress_chars("=>-"),
            );
            bar.set_message(format!("Uploading {file_name}"));
            bar
        } else {
            ProgressBar::hidden()
        };

        let pb_for_stream = pb.clone();
        let stream = ReaderStream::new(file).map(move |result| {
            if let Ok(ref chunk) = result {
                pb_for_stream.inc(chunk.len() as u64);
            }
            result
        });

        let body = reqwest::Body::wrap_stream(stream);
        let file_part = reqwest::multipart::Part::stream_with_length(body, size)
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

        pb.finish_and_clear();

        let resp = Self::check(resp).await?;
        let record: FileRecord = resp.json().await.context("failed to parse file record")?;
        Ok(record)
    }

    /// Attempt the same-host fast path: if our local source file lives on
    /// the same filesystem as the coord's files_dir, ask the coord to
    /// hard-link it into the store instead of transferring bytes.
    ///
    /// Returns `Some(record)` on success, `None` on any failure —
    /// non-success is always safe to interpret as "fall back to streaming
    /// upload." This covers older coords (404 on server-info), non-Unix
    /// clients, different filesystems, missing/unreadable files,
    /// permission denied on hard-link, etc.
    #[cfg(unix)]
    async fn try_hardlink_upload(
        &self,
        path: &Path,
        filename: &str,
        file_type: &str,
    ) -> Option<FileRecord> {
        use std::os::unix::fs::MetadataExt;

        let absolute = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => return None,
        };
        let source_meta = match tokio::fs::metadata(&absolute).await {
            Ok(m) => m,
            Err(_) => return None,
        };
        if !source_meta.is_file() {
            return None;
        }
        let source_dev = source_meta.dev();

        // Ask coord for its files_dir device id. If this endpoint doesn't
        // exist (older coord), fall through to streaming.
        let resp = self
            .http
            .get(self.url("/api/v1/server-info"))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let server_info: ServerInfo = resp.json().await.ok()?;

        // `device_id == 0` is the "not supported" sentinel the coord
        // returns on non-Unix hosts, and is also extremely unlikely to
        // coincidentally match a real device. Either way: skip the fast
        // path.
        if server_info.device_id == 0 || source_dev != server_info.device_id {
            return None;
        }

        let payload = HardlinkPayload {
            source_path: absolute.to_string_lossy().to_string(),
            file_type: file_type.to_string(),
            filename: filename.to_string(),
        };

        let resp = self
            .http
            .post(self.url("/api/v1/files/hardlink"))
            .json(&payload)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<FileRecord>().await.ok()
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

    pub async fn enroll_worker(
        &self,
        name: &str,
        expires_minutes: u64,
    ) -> Result<EnrollWorkerResponse> {
        let payload = EnrollWorkerPayload {
            name: name.to_string(),
            expires_minutes,
        };

        let resp = self
            .http
            .post(self.url("/api/v1/workers/enroll"))
            .json(&payload)
            .send()
            .await
            .context("failed to reach coordinator")?;

        let resp = Self::check(resp).await?;
        let enroll_resp: EnrollWorkerResponse = resp
            .json()
            .await
            .context("failed to parse enroll response")?;
        Ok(enroll_resp)
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
