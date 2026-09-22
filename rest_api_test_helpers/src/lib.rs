use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::Result;
use common::fs::names::{
    metadata_path_for, metadata_signatures_path_for, pending_signatures_path_for,
    signatures_path_for,
};
use constants::{SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSecretKeys, AsfaloadSignatureTrait,
    SignaturesFile, TaggedSignature, sha512_for_content,
};
use rest_api::server::run_server;
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_types::SubmitSignatureResponse;
use rest_api_types::errors::ApiError;
use serde_json::Value;
use signers_file_types::SignersConfig;
use tempfile::TempDir;
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, timeout},
};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

/// Read the git backend from the ASFALOAD_GIT_BACKEND environment variable.
/// Only recognises sha256 and rejects other values since sha1 backend was removed.
fn configured_backend() -> rest_api::config::GitBackendConfig {
    match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
        Ok("sha256") => rest_api::config::GitBackendConfig::Sha256,
        Ok(other) => panic!("unrecognised git ASFALOAD_GIT_BACKEND {other}"),
        Err(_e) => rest_api::config::GitBackendConfig::Sha256,
    }
}

//
// Helper function to initialize a git repository in a temporary directory
pub fn init_git_repo(repo_path: &Path) -> Result<(), ApiError> {
    fs::create_dir_all(repo_path).map_err(ApiError::ServerSetupError)?;

    if configured_backend() == rest_api::config::GitBackendConfig::Sha256 {
        run_git(repo_path, &["init", "--object-format=sha256"])?;
    } else {
        run_git(repo_path, &["init"])?;
    }
    run_git(repo_path, &["config", "user.name", "Test User"])?;
    run_git(repo_path, &["config", "user.email", "test@example.com"])?;

    Ok(())
}

// Helper function to get the latest commit message
pub fn get_latest_commit(repo_path: &Path) -> Result<String, ApiError> {
    run_git(repo_path, &["log", "--oneline", "-1"])
}

/// Check if a file exists in the latest git commit
pub fn file_exists_in_latest_commit(repo_path: &Path, file_path: &str) -> Result<bool, ApiError> {
    let output = Command::new("git")
        .args(["-C", &repo_path.to_string_lossy(), "cat-file", "-e"])
        .arg(format!("HEAD:{}", file_path))
        .output()
        .map_err(ApiError::ServerSetupError)?;
    Ok(output.status.success())
}

/// Check if a file is tracked in git (in the index)
pub fn file_is_tracked_in_git(repo_path: &Path, file_path: &str) -> Result<bool, ApiError> {
    let output = Command::new("git")
        .args([
            "-C",
            &repo_path.to_string_lossy(),
            "ls-files",
            "--error-unmatch",
            "--",
            file_path,
        ])
        .output()
        .map_err(ApiError::ServerSetupError)?;
    Ok(output.status.success())
}

// Helper function to check if a file exists in the repo
pub fn file_exists_in_repo(repo_path: &Path, file_path: &str) -> bool {
    repo_path.join(file_path).exists()
}

// Helper function to read file content
pub fn read_file_content(repo_path: &Path, file_path: &str) -> Result<String, ApiError> {
    let content = fs::read_to_string(repo_path.join(file_path))?;
    Ok(content)
}

pub async fn get_random_port() -> Result<u16, ApiError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // We must drop the listener to release the port for our server.
    drop(listener);
    Ok(port)
}

pub fn url_for(action: &str, port: u16) -> String {
    format!("http://localhost:{port}/v1/{action}")
}

/// Helper function to build a test config
pub fn build_test_config(git_repo_path: &Path, server_port: u16) -> rest_api::config::AppConfig {
    let git_backend = configured_backend();
    rest_api::config::AppConfig {
        git_repo_path: git_repo_path.to_path_buf(),
        server_port,
        server_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        log_level: "info".to_string(),
        git_backend,
        git_signing_pub_key_path: test_helpers::git_signing_pub_key_path(),
        github_api_key: None,
        gitlab_api_key: None,
    }
}

/// Stage the given paths and create a commit in a test git repo.
pub fn git_commit(repo_path: &Path, paths: &[&str], message: &str) -> Result<(), ApiError> {
    for path in paths {
        run_git(repo_path, &["add", path])?;
    }
    run_git(repo_path, &["commit", "-m", message])?;
    Ok(())
}

fn run_git(repo_path: &Path, args: &[&str]) -> Result<String, ApiError> {
    let output = Command::new("git")
        .args(["-C", &repo_path.to_string_lossy()])
        .args(args)
        .output()
        .map_err(ApiError::ServerSetupError)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::GitError(format!(
            "git {:?} failed: {}",
            args,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub async fn wait_for_server(
    config: &rest_api::config::AppConfig,
    timeout_in_sec: Option<u64>,
) -> Result<(), ApiError> {
    let address = format!("127.0.0.1:{}", config.server_port);

    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_in_sec.unwrap_or(2));

    // Attempt to connect within a 2-second timeout.
    // `timeout` returns a Result, where Err means the operation timed out.
    loop {
        match timeout(
            Duration::from_secs(timeout_in_sec.unwrap_or(2)),
            TcpStream::connect(&address),
        )
        .await
        {
            Ok(Ok(_)) => {
                // Connection succeeded before the timeout.
                return Ok(());
            }
            Ok(Err(e)) => {
                // Connection failed (e.g., connection refused).
                if tokio::time::Instant::now() > deadline {
                    return Err(ApiError::ServerSetupError(e));
                }
            }
            Err(_) => {
                // The `timeout` elapsed, so we assume the port is filtered.
                if tokio::time::Instant::now() > deadline {
                    return Err(ApiError::ServerSetupError(std::io::Error::other(
                        "Timeout connecting server",
                    )));
                }
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
pub async fn wait_for_commit(
    test_repo_path_buf: PathBuf,
    commit_message: &str,
    deadline_in: Option<Instant>,
) -> Result<()> {
    let deadline =
        deadline_in.unwrap_or(tokio::time::Instant::now() + tokio::time::Duration::from_secs(5));
    loop {
        if let Ok(msg) = get_latest_commit(&test_repo_path_buf)
            && msg.contains(commit_message)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() > deadline {
            return Err(anyhow::Error::msg(
                "Test timed out waiting for commit".to_string(),
            ));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

pub fn parse_log_lines(content: &str) -> Result<Vec<Value>> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).map_err(anyhow::Error::from))
        .collect()
}
pub async fn wait_for_log_entry_with_request_id<P: AsRef<Path>>(
    log_path: P,
    request_id: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(content) = fs::read_to_string(log_path.as_ref())
            && parse_log_lines(&content)?.iter().any(|entry| {
                entry
                    .get("request_id")
                    .or_else(|| entry.get("fields").and_then(|f| f.get("request_id")))
                    .and_then(|v| v.as_str())
                    == Some(request_id)
            })
        {
            return Ok(());
        }

        if tokio::time::Instant::now() > deadline {
            anyhow::bail!(
                "Timed out waiting for log entry with request_id. Log content: {}",
                fs::read_to_string(log_path).unwrap_or_default()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn write_git_hook(
    repo_path_buf: PathBuf,
    name: &str,
    code: &str,
) -> Result<(), ApiError> {
    // Create a pre-commit hook that will fail
    let hooks_dir = repo_path_buf.join(".git").join("hooks");
    fs::create_dir_all(&hooks_dir).unwrap();

    let hook_path = hooks_dir.join(name);
    let mut hook_file = File::create(&hook_path).await?;
    hook_file.write_all(code.as_bytes()).await?;
    hook_file.flush().await?;

    // Make the hook executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    Ok(())
}

pub async fn make_git_commit_fail(repo_path_buf: PathBuf) -> Result<(), ApiError> {
    write_git_hook(
        repo_path_buf.clone(),
        "pre-commit",
        "#!/bin/sh\necho 'Simulating commit failure'; exit 1",
    )
    .await?;
    Ok(())
}

pub struct TestAuthHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub public_key: String,
}

/// Helper function to create authentication headers for a given payload
pub async fn create_auth_headers_with_key(
    secret_key: &AsfaloadSecretKeys,
    payload: &str,
) -> TestAuthHeaders {
    // Create authentication info and signature
    let auth_info = AuthInfo::new(payload.to_string());
    let auth_signature = AuthSignature::new(&auth_info, secret_key).unwrap();

    TestAuthHeaders {
        timestamp: auth_signature.auth_info().timestamp().to_rfc3339(),
        nonce: auth_signature.auth_info().nonce(),
        signature: auth_signature.signature().to_base64(),
        public_key: auth_signature.public_key(),
    }
}

/// Helper function to create authentication headers for a given payload
pub async fn create_auth_headers(payload: &str) -> TestAuthHeaders {
    let test_keys = test_helpers::TestKeys::new(1);
    let secret_key = test_keys.sec_key(0).unwrap();
    create_auth_headers_with_key(secret_key, payload).await
}
pub async fn send_authenticated_request_with_overwrite(
    client: &reqwest::Client,
    port: u16,
    secret_key: &AsfaloadSecretKeys,
    payload: &serde_json::Value,
    overwrite: HashMap<String, String>,
) -> reqwest::Response {
    let payload_string = payload.to_string();

    let TestAuthHeaders {
        timestamp,
        nonce,
        signature,
        public_key,
    } = create_auth_headers_with_key(secret_key, &payload_string).await;

    client
        .post(url_for("revoke", port))
        .header(
            HEADER_TIMESTAMP,
            overwrite.get(HEADER_TIMESTAMP).unwrap_or(&timestamp),
        )
        .header(HEADER_NONCE, overwrite.get(HEADER_NONCE).unwrap_or(&nonce))
        .header(
            HEADER_SIGNATURE,
            overwrite.get(HEADER_SIGNATURE).unwrap_or(&signature),
        )
        .header(
            HEADER_PUBLIC_KEY,
            overwrite.get(HEADER_PUBLIC_KEY).unwrap_or(&public_key),
        )
        .json(payload)
        .send()
        .await
        .expect("Failed to send request")
}
pub async fn send_authenticated_request_with_key(
    client: &reqwest::Client,
    port: u16,
    secret_key: &AsfaloadSecretKeys,
    payload: &serde_json::Value,
) -> reqwest::Response {
    send_authenticated_request_with_overwrite(client, port, secret_key, payload, HashMap::new())
        .await
}

pub async fn send_authenticated_request(
    client: &reqwest::Client,
    port: u16,
    payload: &serde_json::Value,
) -> reqwest::Response {
    let test_keys = test_helpers::TestKeys::new(1);
    let secret_key = test_keys.sec_key(0).unwrap();
    send_authenticated_request_with_key(client, port, secret_key, payload).await
}

pub async fn send_repeated_authenticated_request(
    client: &reqwest::Client,
    port: u16,
    payload: &serde_json::Value,
) -> reqwest::Response {
    let payload_string = payload.to_string();
    let TestAuthHeaders {
        timestamp,
        nonce,
        signature,
        public_key,
    } = create_auth_headers(&payload_string).await;

    let first_response = client
        .post(url_for("revoke", port))
        .header(HEADER_TIMESTAMP, &timestamp)
        .header(HEADER_NONCE, &nonce)
        .header(HEADER_SIGNATURE, &signature)
        .header(HEADER_PUBLIC_KEY, &public_key)
        .json(payload)
        .send()
        .await
        .expect("Failed to send request");
    assert!(
        first_response.status() != reqwest::StatusCode::UNAUTHORIZED,
        "The first request in the nonce reuse test must pass auth. Status: {}",
        first_response.status()
    );

    client
        .post(url_for("revoke", port))
        .header(HEADER_TIMESTAMP, timestamp)
        .header(HEADER_NONCE, nonce)
        .header(HEADER_SIGNATURE, signature)
        .header(HEADER_PUBLIC_KEY, public_key)
        .json(payload)
        .send()
        .await
        .expect("Failed to send request")
}

pub fn print_logs() {
    // Set log level with RUST_LOG env var
    if std::env::var("RUST_LOG").is_err() {
        println!("** Set the log level with RUST_LOG env var");
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .init();
}

pub fn setup_file_logging(
    temp_dir: &Path,
) -> Result<(
    WorkerGuard,
    std::path::PathBuf,
    tracing::subscriber::DefaultGuard,
)> {
    let log_path = temp_dir.join("test.log");
    let appender = tracing_appender::rolling::never(temp_dir, "test.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);

    let subscriber = Registry::default()
        .with(EnvFilter::new("info"))
        .with(fmt::layer().json().with_writer(non_blocking));

    let default_guard = tracing::subscriber::set_default(subscriber);

    Ok((guard, log_path, default_guard))
}

pub struct TestSetup {
    _temp_dir: TempDir,
    port: u16,
    server_handle: JoinHandle<std::result::Result<(), ApiError>>,
    artifact_path: String,
    test_keys: test_helpers::TestKeys,
    repo_path: PathBuf,
    client: reqwest::Client,
}

impl TestSetup {
    /// Returns the server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the relative artifact path.
    pub fn artifact_path(&self) -> &str {
        &self.artifact_path
    }

    /// Returns the repository root path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Returns a reference to the test keys.
    pub fn test_keys(&self) -> &test_helpers::TestKeys {
        &self.test_keys
    }

    /// Returns a reference to the shared HTTP client.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Submit a signature for the artifact using the key at the given index.
    pub async fn submit_signature(&self, key_index: usize) -> Result<SubmitSignatureResponse> {
        let public_key = self
            .test_keys
            .pub_key(key_index)
            .ok_or_else(|| anyhow::anyhow!("key index {} out of range", key_index))?;
        let secret_key = self
            .test_keys
            .sec_key(key_index)
            .ok_or_else(|| anyhow::anyhow!("key index {} out of range", key_index))?;

        let artifact_abs = self.repo_path.join(&self.artifact_path);
        let content = fs::read(&artifact_abs)?;
        let hash = sha512_for_content(content)?;
        let sig = secret_key.sign(&hash)?;

        let mut signatures = std::collections::HashMap::new();
        signatures.insert(self.artifact_path.clone(), sig.to_base64());

        let submit_payload = serde_json::json!({
            "pending_file": {
                "path": self.artifact_path,
                "digest": hash.to_string(),
            },
            "public_key": public_key.to_base64(),
            "signatures": signatures,
        });

        let submit_payload_str = submit_payload.to_string();
        let auth_info = AuthInfo::new(submit_payload_str);
        let auth_sig = AuthSignature::new(&auth_info, secret_key)?;

        let response = self
            .client
            .post(format!("http://127.0.0.1:{}/v1/signatures", self.port))
            .header(
                HEADER_TIMESTAMP,
                auth_sig.auth_info().timestamp().to_rfc3339(),
            )
            .header(HEADER_NONCE, auth_sig.auth_info().nonce())
            .header(HEADER_SIGNATURE, auth_sig.signature().to_base64())
            .header(HEADER_PUBLIC_KEY, public_key.to_base64())
            .json(&submit_payload)
            .send()
            .await?;

        let status = response.status();
        if status != 200 {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Signature submission failed with status {}: {}",
                status,
                body
            );
        }
        let body: SubmitSignatureResponse = response.json().await?;
        Ok(body)
    }

    /// Submit a signature and wait for the server to commit.
    pub async fn submit_signature_and_wait(
        &self,
        key_index: usize,
    ) -> Result<SubmitSignatureResponse> {
        let body = self.submit_signature(key_index).await?;

        let commit_prefix = if body.is_complete {
            "completed signature collection for"
        } else {
            "added partial signature for"
        };
        let expected_msg = format!("{} {}", commit_prefix, self.artifact_path);
        wait_for_commit(self.repo_path.clone(), &expected_msg, None).await?;

        Ok(body)
    }
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        self.server_handle.abort();
    }
}

/// Builder for creating configurable test setups for REST API integration tests.
pub struct TestSetupBuilder {
    num_keys: usize,
    threshold: usize,
    artifact_path: String,
    artifact_content: Vec<u8>,
    commit_signers: bool,
    print_server_logs: bool,
    history: Option<signers_file_types::HistoryFile>,
}

impl Default for TestSetupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestSetupBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            num_keys: 1,
            threshold: 1,
            artifact_path: "releases/artifact.bin".to_string(),
            artifact_content: b"artifact content".to_vec(),
            commit_signers: true,
            print_server_logs: false,
            history: None,
        }
    }

    /// Set the number of keys. Also sets threshold to the same value.
    pub fn with_keys(mut self, n: usize) -> Self {
        self.num_keys = n;
        self.threshold = n;
        self
    }

    /// Override the threshold independently of the number of keys.
    pub fn with_threshold(mut self, t: usize) -> Self {
        self.threshold = t;
        self
    }

    /// Override the server_logs printing
    pub fn with_server_logs(mut self) -> Self {
        self.print_server_logs = true;
        self
    }

    /// Set the relative artifact path.
    pub fn with_artifact(mut self, path: impl Into<String>) -> Self {
        self.artifact_path = path.into();
        self
    }

    /// Set the artifact file content.
    pub fn with_artifact_content(mut self, content: impl Into<Vec<u8>>) -> Self {
        self.artifact_content = content.into();
        self
    }

    /// Do not commit the signers directory during setup.
    pub fn without_signers_committed(mut self) -> Self {
        self.commit_signers = false;
        self
    }

    /// Set a history file to write during setup.
    pub fn with_history(mut self, history: signers_file_types::HistoryFile) -> Self {
        self.history = Some(history);
        self
    }

    /// Build the test setup: creates repo, signers, artifact, and starts the
    /// server, but does NOT submit any signatures.
    pub async fn build(self) -> Result<TestSetup> {
        let temp_dir = TempDir::new()?;
        let repo_path = temp_dir.path().to_path_buf();
        init_git_repo(&repo_path)?;

        let test_keys = test_helpers::TestKeys::new(self.num_keys);

        // Collect all public keys
        let pub_keys: Vec<_> = (0..self.num_keys)
            .map(|i| test_keys.pub_key(i).unwrap().clone())
            .collect();

        // Create signers config with the configured threshold
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (pub_keys, self.threshold as u32))?;
        let signers_dir = repo_path.join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&signers_dir).await?;
        tokio::fs::write(signers_dir.join(SIGNERS_FILE), signers_config.to_json()?).await?;

        // Create metadata file
        let metadata = test_helpers::test_metadata();
        let metadata_path = metadata_path_for(signers_dir.join(SIGNERS_FILE))?;
        tokio::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?).await?;

        // Create a signatures file for the signers config (sign with first key)
        let first_pub_key = test_keys.pub_key(0).unwrap();
        let first_sec_key = test_keys.sec_key(0).unwrap();
        let signers_file_content = tokio::fs::read(signers_dir.join(SIGNERS_FILE)).await?;
        let signers_hash = sha512_for_content(signers_file_content)?;
        let signers_sig = first_sec_key.sign(&signers_hash)?;
        let mut signers_signatures = SignaturesFile::new();
        signers_signatures.entries.insert(
            first_pub_key.to_base64(),
            TaggedSignature {
                format: first_pub_key.key_format(),
                signature: signers_sig.to_base64(),
            },
        );
        let signers_file_path = signers_dir.join(SIGNERS_FILE);
        let signers_sig_path = signatures_path_for(&signers_file_path)?;
        tokio::fs::write(
            &signers_sig_path,
            serde_json::to_string(&signers_signatures)?,
        )
        .await?;

        // Create a signatures file for the metadata (sign with first key)
        let metadata_content = tokio::fs::read(&metadata_path).await?;
        let metadata_hash = sha512_for_content(metadata_content)?;
        let metadata_sig = first_sec_key.sign(&metadata_hash)?;
        let mut metadata_signatures = SignaturesFile::new();
        metadata_signatures.entries.insert(
            first_pub_key.to_base64(),
            TaggedSignature {
                format: first_pub_key.key_format(),
                signature: metadata_sig.to_base64(),
            },
        );
        let metadata_sig_path = metadata_signatures_path_for(&signers_file_path)?;
        tokio::fs::write(
            &metadata_sig_path,
            serde_json::to_string(&metadata_signatures)?,
        )
        .await?;

        // Write history file if provided
        if let Some(ref history) = self.history {
            let history_path = repo_path.join(SIGNERS_HISTORY_FILE);
            history.save_to_file(&history_path)?;
        }

        // Commit the signers directory (and history file) if requested
        if self.commit_signers {
            let mut paths_to_commit: Vec<&str> = vec![SIGNERS_DIR];
            if self.history.is_some() {
                paths_to_commit.push(SIGNERS_HISTORY_FILE);
            }
            git_commit(&repo_path, &paths_to_commit, "initial signers config")?;
        }

        // Create artifact file
        let artifact_abs = repo_path.join(&self.artifact_path);
        tokio::fs::create_dir_all(artifact_abs.parent().unwrap()).await?;
        tokio::fs::write(&artifact_abs, &self.artifact_content).await?;

        // Create empty pending signatures file
        let pending_sig_path = pending_signatures_path_for(&artifact_abs)?;
        tokio::fs::write(
            &pending_sig_path,
            serde_json::to_string(&SignaturesFile::new())?,
        )
        .await?;

        // Start server
        if self.print_server_logs {
            print_logs();
        }
        let port = get_random_port().await?;
        let config = build_test_config(&repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        Ok(TestSetup {
            _temp_dir: temp_dir,
            port,
            server_handle,
            artifact_path: self.artifact_path,
            test_keys,
            repo_path,
            client: reqwest::Client::new(),
        })
    }

    /// Build the test setup and submit signatures for key indices 0..threshold,
    /// waiting for each commit.
    pub async fn build_and_sign(self) -> Result<TestSetup> {
        let threshold = self.threshold;
        let setup = self.build().await?;

        for key_index in 0..threshold {
            setup.submit_signature_and_wait(key_index).await?;
        }

        Ok(setup)
    }
}

/// Sets up a git repo with signers config+metadata, creates an artifact,
/// submits a signature to complete the signing workflow, and waits for commit.
pub async fn setup_signed_artifact() -> Result<TestSetup> {
    TestSetupBuilder::new().build_and_sign().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_git_repo_creates_repo() {
        let temp_dir = tempfile::tempdir().unwrap();
        init_git_repo(temp_dir.path()).unwrap();

        let inside = run_git(temp_dir.path(), &["rev-parse", "--is-inside-work-tree"]).unwrap();
        assert_eq!(inside, "true");
    }

    #[test]
    fn test_init_git_repo_creates_missing_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&repo_path).unwrap();

        assert!(repo_path.exists());
        let inside = run_git(&repo_path, &["rev-parse", "--is-inside-work-tree"]).unwrap();
        assert_eq!(inside, "true");
    }

    fn is_sha256_backend() -> bool {
        std::env::var("ASFALOAD_GIT_BACKEND").as_deref() == Ok("sha256")
    }

    #[test]
    fn test_init_git_repo_uses_sha256_object_format() {
        if !is_sha256_backend() {
            eprintln!("skipping: requires ASFALOAD_GIT_BACKEND=sha256");
            return;
        }
        let temp_dir = tempfile::tempdir().unwrap();
        init_git_repo(temp_dir.path()).unwrap();
        let fmt = run_git(temp_dir.path(), &["rev-parse", "--show-object-format"]).unwrap();
        assert_eq!(fmt, "sha256");
    }

    #[test]
    fn test_build_test_config_defaults_to_sha256() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg = build_test_config(temp_dir.path(), 3000);
        assert_eq!(cfg.git_backend, rest_api::config::GitBackendConfig::Sha256);
    }

    #[test]
    fn test_build_test_config_reads_sha256_env() {
        if !is_sha256_backend() {
            eprintln!("skipping: requires ASFALOAD_GIT_BACKEND=sha256");
            return;
        }
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg = build_test_config(temp_dir.path(), 3000);
        assert_eq!(cfg.git_backend, rest_api::config::GitBackendConfig::Sha256);
    }

    #[tokio::test]
    async fn test_builder_default_creates_server_and_artifact() {
        let setup = TestSetupBuilder::new().build().await.unwrap();
        assert!(setup.port() > 0);
        assert_eq!(setup.artifact_path(), "releases/artifact.bin");
        assert!(setup.repo_path().join("releases/artifact.bin").exists());
        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/v1/get_artifact_signers_chain/nonexistent",
                setup.port()
            ))
            .send()
            .await
            .unwrap();
        assert_ne!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_builder_with_keys_and_threshold() {
        let setup = TestSetupBuilder::new()
            .with_keys(2)
            .with_threshold(2)
            .build()
            .await
            .unwrap();

        // First signature should be partial (threshold is 2)
        let first = setup.submit_signature_and_wait(0).await.unwrap();
        assert!(
            !first.is_complete,
            "First signature should be partial when threshold is 2"
        );

        // Second signature should complete the signing
        let second = setup.submit_signature_and_wait(1).await.unwrap();
        assert!(
            second.is_complete,
            "Second signature should complete signing when threshold is 2"
        );
    }

    #[tokio::test]
    async fn test_builder_build_and_sign() {
        let setup = TestSetupBuilder::new().build_and_sign().await.unwrap();

        // The artifact should be fully signed; GET signers_chain should return 200
        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/v1/get_artifact_signers_chain/{}",
                setup.port(),
                setup.artifact_path()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "get_signers_chain should return 200 for a fully signed artifact"
        );
    }

    #[tokio::test]
    async fn test_builder_custom_artifact_path() {
        let setup = TestSetupBuilder::new()
            .with_artifact("custom/path/file.bin")
            .build()
            .await
            .unwrap();

        assert_eq!(setup.artifact_path(), "custom/path/file.bin");
        assert!(
            setup.repo_path().join("custom/path/file.bin").exists(),
            "Custom artifact file should exist on disk"
        );
    }
}
