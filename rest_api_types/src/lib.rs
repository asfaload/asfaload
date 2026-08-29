use url::Url;
pub mod git_backend;
pub mod path_validation;

pub mod errors {

    use axum::{Json, http::StatusCode, response::IntoResponse};
    use common::errors::SignersConfigError;
    use thiserror::Error;

    use super::models::ErrorResponse;

    // To surface the errors of Kameo actor's on_start, the error has to be
    // Clone, which is not possible for ApiError due to some errors it wraps
    // not being Clone.
    #[derive(Error, Debug, Clone)]
    pub enum ActorError {
        #[error("Sled operation error: {0}")]
        SledError(#[from] sled::Error),
    }

    #[derive(Error, Debug)]
    pub enum ApiError {
        #[error("Actor error: {0}")]
        ActorError(#[from] ActorError),

        #[error("State error: {0}")]
        StateError(String),

        #[error("Git repository path not set in environment")]
        GitRepoPathNotSet,

        #[error("Git error: {0}")]
        GitError(String),

        #[error("Failed to create directories: {0}")]
        DirectoryCreationFailed(String),

        #[error("Failed to write file: {0}")]
        FileWriteFailed(String),

        #[error("TokioJoinError: {0}")]
        TokioJoinError(#[from] tokio::task::JoinError),

        #[error("Failed to send message to git actor: {0}")]
        ActorMessageFailed(String),

        #[error("Actor encountered an error: {0}")]
        ActorOperationFailed(String),

        #[error("Invalid file path: {0}")]
        InvalidFilePath(String),

        #[error("Server setup failed: {0}")]
        ServerSetupError(#[from] std::io::Error),

        #[error("Invalid port provided: {0}")]
        PortInvalid(String),

        #[error("Missing authentication headers")]
        MissingAuthenticationHeaders,

        #[error("Invalid authentication headers")]
        InvalidAuthenticationHeaders,

        #[error("Invalid request body: {0}")]
        InvalidRequestBody(String),

        #[error("Request too big: {0}")]
        RequestTooBig(String),

        #[error("Internal server error: {0}")]
        InternalServerError(String),

        #[error("Authentication failed: {0}")]
        AuthenticationFailed(String),

        #[error("Timestamp validation failed: {0}")]
        TimestampValidationFailed(String),

        #[error("Signature verification failed")]
        SignatureVerificationFailed,

        #[error("Replay attack detected: nonce already used")]
        ReplayAttackDetected,

        #[error("Server configuration error: {0}")]
        ServerConfigError(#[from] ServerConfigError),

        #[error("Signers config error: {0}")]
        SignersConfigError(#[from] SignersConfigError),

        #[error("{0} API error: {1}")]
        ReleaseApiError(String, String),

        #[error("GitHub API error: {0}")]
        GitHubApiError(String),

        #[error("No active signers file found for repository")]
        NoActiveSignersFile,

        #[error("Invalid release URL format: {0}")]
        InvalidReleaseUrl(String),

        #[error("Unsupported release platform: {0}")]
        UnsupportedReleasePlatform(String),

        #[error("Invalid GitHub release URL format: {0}")]
        InvalidGitHubUrl(String),

        #[error("File not found: {0}")]
        FileNotFound(String),

        #[error("Signature already complete: {0}")]
        SignatureAlreadyComplete(String),

        #[error("Signers file error: {0}")]
        SignersFileError(#[from] common::errors::SignersFileError),

        #[error("Json Serialisation error: {0}")]
        SerdeJsonError(#[from] serde_json::Error),

        #[error("Revocation error: {0}")]
        RevocationError(String),

        #[error("File has not been fully signed: {0}")]
        FileNotFullySigned(String),

        #[error("Digest mismatch: {0}")]
        DigestMismatch(String),

        #[error("File is revoked: {0}")]
        FileRevoked(String),

        #[error("Not authorized: {0}")]
        NotAuthorized(String),

        #[error("Release already registered: {0}")]
        ReleaseAlreadyRegistered(String),

        #[error("Project already registered: {0}")]
        ProjectAlreadyRegistered(String),

        #[error("Signature already collected: {0}")]
        SignatureAlreadyCollected(String),

        #[error("Nonce cache error: {0}")]
        NonceCacheError(String),
    }

    #[derive(Error, Debug)]
    pub enum ServerConfigError {
        #[error("Configuration building error : {0}")]
        BuildError(#[from] config::ConfigError),

        #[error("Invalid configuration : {0}")]
        InvalidConfig(String),
    }

    impl From<hyper::header::ToStrError> for ApiError {
        fn from(_error: hyper::header::ToStrError) -> Self {
            ApiError::InvalidAuthenticationHeaders
        }
    }

    impl From<rest_api_auth::AuthError> for ApiError {
        fn from(error: rest_api_auth::AuthError) -> Self {
            match error {
                rest_api_auth::AuthError::AuthDataPreparationError(msg) => {
                    ApiError::AuthenticationFailed(msg)
                }
                rest_api_auth::AuthError::IoError(_) => {
                    ApiError::ServerSetupError(std::io::Error::other("Auth IO error"))
                }
                rest_api_auth::AuthError::SigningError(_) => {
                    ApiError::AuthenticationFailed("Signing error".to_string())
                }
                rest_api_auth::AuthError::KeyError(_) => {
                    ApiError::AuthenticationFailed("Key error".to_string())
                }
                rest_api_auth::AuthError::VerificationError(_) => {
                    ApiError::AuthenticationFailed("Signature verification failed".to_string())
                }
                rest_api_auth::AuthError::SignatureError(_) => {
                    ApiError::AuthenticationFailed("Signature error".to_string())
                }
                rest_api_auth::AuthError::MissingHeader(header) => {
                    ApiError::AuthenticationFailed(format!("Missing header: {}", header))
                }
                rest_api_auth::AuthError::InvalidTimestampFormat(_) => {
                    ApiError::AuthenticationFailed("Invalid timestamp format".to_string())
                }
                rest_api_auth::AuthError::InvalidNonceFormat(_) => {
                    ApiError::AuthenticationFailed("Invalid nonce format".to_string())
                }
                rest_api_auth::AuthError::TimestampInvalid(s) => {
                    ApiError::TimestampValidationFailed(s)
                }
                rest_api_auth::AuthError::Base64DecodeError(_) => {
                    ApiError::AuthenticationFailed("Base64 decode error".to_string())
                }
            }
        }
    }

    impl ApiError {
        pub fn to_http_status(&self) -> axum::http::StatusCode {
            match self {
                ApiError::GitRepoPathNotSet => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::DirectoryCreationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::FileWriteFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorMessageFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::InvalidFilePath(_) => StatusCode::BAD_REQUEST,
                ApiError::ServerSetupError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::PortInvalid(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::TokioJoinError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::MissingAuthenticationHeaders => StatusCode::UNAUTHORIZED,
                ApiError::InvalidAuthenticationHeaders => StatusCode::UNAUTHORIZED,
                ApiError::InvalidRequestBody(_) => StatusCode::BAD_REQUEST,
                ApiError::AuthenticationFailed(_) => StatusCode::UNAUTHORIZED,
                ApiError::TimestampValidationFailed(_) => StatusCode::UNAUTHORIZED,
                ApiError::SignatureVerificationFailed => StatusCode::UNAUTHORIZED,
                ApiError::ReplayAttackDetected => StatusCode::UNAUTHORIZED,
                ApiError::StateError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ServerConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::RequestTooBig(_) => StatusCode::PAYLOAD_TOO_LARGE,
                ApiError::GitHubApiError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ReleaseApiError(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::NoActiveSignersFile => StatusCode::BAD_REQUEST,
                ApiError::InvalidReleaseUrl(_) => StatusCode::BAD_REQUEST,
                ApiError::UnsupportedReleasePlatform(_) => StatusCode::BAD_REQUEST,
                ApiError::InvalidGitHubUrl(_) => StatusCode::BAD_REQUEST,
                ApiError::FileNotFound(_) => StatusCode::NOT_FOUND,
                ApiError::SignatureAlreadyComplete(_) => StatusCode::CONFLICT,
                ApiError::SignersFileError(_) => StatusCode::BAD_REQUEST,
                ApiError::SerdeJsonError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::RevocationError(_) => StatusCode::BAD_REQUEST,
                ApiError::FileNotFullySigned(_) => StatusCode::CONFLICT,
                ApiError::DigestMismatch(_) => StatusCode::BAD_REQUEST,
                ApiError::FileRevoked(_) => StatusCode::BAD_REQUEST,
                ApiError::NotAuthorized(_) => StatusCode::FORBIDDEN,
                ApiError::ReleaseAlreadyRegistered(_) => StatusCode::CONFLICT,
                ApiError::ProjectAlreadyRegistered(_) => StatusCode::CONFLICT,
                ApiError::SignatureAlreadyCollected(_) => StatusCode::CONFLICT,
                ApiError::GitError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::SignersConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::NonceCacheError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl IntoResponse for ApiError {
        fn into_response(self) -> axum::response::Response {
            let status = self.to_http_status();
            let error_message = self.to_string(); // Get the detailed error message from the #[error] macro

            // Create the JSON response body
            let body = Json(ErrorResponse {
                error: error_message,
            });

            // Return the response with the determined status and JSON body
            (status, body).into_response()
        }
    }
}

pub mod environment {
    use std::path::PathBuf;

    // Structure to hold environment in which the server runs.
    #[derive(Clone)]
    pub struct Environment {
        pub git_repo_path: PathBuf,
        pub server_port: u16,
    }
}

pub mod models {
    use core::fmt;
    use std::collections::HashMap;

    use common::{AsfaloadHashes, sha512_for_file};
    use serde::{Deserialize, Serialize};

    use crate::errors::ApiError;

    #[derive(Debug, Serialize)]
    pub struct ErrorResponse {
        pub error: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterRepoRequest {
        pub signers_file_url: String,
        /// Base64-encoded public key of the submitter
        pub public_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterRepoResponse {
        pub success: bool,
        pub project_id: String,
        pub message: String,
        pub required_signers: Vec<String>,
        pub signature_submission_url: String,
    }

    pub type UpdateRepoSignersRequest = RegisterRepoRequest;
    pub type UpdateRepoSignersResponse = RegisterRepoResponse;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    /// Request to submit signatures for a specific file.
    ///
    /// # Fields
    /// * `pending_file` - relative file path and digest
    /// * `public_key` - Base64-encoded public key of the signer
    /// * `signatures` - Map of file path to base64-encoded signature data
    pub struct SubmitSignatureRequest {
        pub pending_file: ClientPendingFile,
        pub public_key: String,
        pub signatures: HashMap<String, String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    /// Response to a signature submission request.
    ///
    /// # Fields
    /// * `is_complete` - Whether the aggregate signature is now complete,
    ///   meaning all required signatures have been collected
    pub struct SubmitSignatureResponse {
        pub is_complete: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    /// Response to a signature status query.
    ///
    /// # Fields
    /// * `file_path` - Path to the file
    /// * `is_complete` - Whether the aggregate signature is complete
    /// * `collected_count` - Number of individual signatures collected so far
    pub struct GetSignatureStatusResponse {
        pub file_path: String,
        pub is_complete: bool,
    }

    // This struct can be initialised by the client without access to the file on disk, but it has
    // to provide the digest of said file.
    // The PendingFile can only be built for files accessible on disk, by the server.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClientPendingFile {
        path: String,
        digest: AsfaloadHashes,
    }

    impl ClientPendingFile {
        pub fn new(path: String, digest: AsfaloadHashes) -> ClientPendingFile {
            ClientPendingFile { path, digest }
        }
        pub fn path(&self) -> &str {
            &self.path
        }
        pub fn digest(&self) -> &AsfaloadHashes {
            &self.digest
        }
    }

    impl fmt::Display for ClientPendingFile {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "path: {}\ndigest: {}\n", self.path(), self.digest())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PendingFile {
        path: String,
        digest: AsfaloadHashes,
    }

    impl fmt::Display for PendingFile {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "path: {}\ndigest: {}\n", self.path, self.digest)
        }
    }

    impl PendingFile {
        pub fn try_new(
            np: &crate::path_validation::NormalisedPaths,
        ) -> Result<PendingFile, ApiError> {
            let path = np.relative_path().to_string_lossy().to_string();
            let digest = sha512_for_file(np.absolute_path())?;
            Ok(PendingFile { path, digest })
        }

        pub fn path(&self) -> &str {
            &self.path
        }
        pub fn digest(&self) -> &AsfaloadHashes {
            &self.digest
        }

        /// Get a ClientPendingFile from self. Transitions from a verified instance
        /// (with digest computed from disk) to an untrustable instance (eg received by the server)
        pub fn unseal(&self) -> ClientPendingFile {
            ClientPendingFile {
                path: self.path().into(),
                digest: self.digest().clone(),
            }
        }
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    /// Response to a pending signatures list request.
    ///
    /// # Fields
    /// * `pending_files` - list of information (relative path and digest) of files awaiting signature
    ///   from the requesting signer
    pub struct ListPendingResponse {
        pub pending_files: Vec<PendingFile>,
    }

    impl ListPendingResponse {
        pub fn filter(&self, digest_filter: &AsfaloadHashes) -> Self {
            let filtered_list = self
                .pending_files
                .iter()
                .filter(|item| item.digest() == digest_filter)
                .cloned()
                .collect();

            ListPendingResponse {
                pending_files: filtered_list,
            }
        }
    }

    /// Authentication outcome reported by the ping endpoint.
    ///
    /// The enum makes invalid combinations unrepresentable: a success always
    /// carries the authenticated public key, a failure always carries a reason.
    /// `Failed.public_key` is `Some` when the public key header was present and
    /// was a parseable key (e.g. signature mismatch, stale timestamp, replayed
    /// nonce) and `None` when the key itself was missing or invalid.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub enum PingAuthStatus {
        Unauthenticated,
        Success {
            public_key: String,
        },
        Failed {
            public_key: Option<String>,
            reason: String,
        },
    }

    /// Response of the ping endpoint: connectivity plus auth diagnostics.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct PingResponse {
        /// Always "pong"
        pub message: String,
        pub auth: PingAuthStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FilesToSignResponse {
        pub files: HashMap<String, String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RevokeFileRequest {
        /// Relative path to the signed file being revoked
        pub file_path: String,
        /// JSON string of the revocation document (RevocationInfo)
        pub revocation_json: String,
        /// Base64-encoded signature of the sha512 of revocation_json
        pub signature: String,
        /// Base64-encoded public key of the revoker
        pub public_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RevokeFileResponse {
        pub success: bool,
        pub message: String,
    }

    /// Request to register assets — either a GitHub release URL or checksums file URLs.
    /// Exactly one of `github_release_url` or `csum_files` must be provided.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterAssetsRequest {
        /// GitHub release URL (mutually exclusive with csum_files)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub github_release_url: Option<String>,
        /// Checksums file URLs (mutually exclusive with github_release_url)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub csum_files: Option<Vec<String>>,
    }

    /// Response to an assets registration request.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterAssetsResponse {
        pub success: bool,
        pub message: String,
        pub index_file_path: Option<String>,
    }

    /// Response for the get_signers_chain endpoint.
    ///
    /// Contains the signers history chain applicable to a signed artifact,
    /// filtered to entries up to and including the active config at signing time.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetSignersChainResponse {
        pub chain: signers_file_types::SignersChain,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct GetArtifactInfoRequest {
        pub artifact_url: url::Url,
        pub forge_kind: Option<String>,
    }

    /// Response for the get_artifact_info endpoint.
    ///
    /// Bundles everything a client needs to verify a signed artifact: the raw
    /// index JSON, its signatures envelope, and the signers chain as of the
    /// artifact-signature commit. Clients validate the chain (realm + trust
    /// anchor) and verify the index signatures against the chain head.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct GetArtifactInfoResponse {
        /// Raw JSON bytes of the artifact's `asfaload.index.json`. Base64-encoded
        /// in transit so the bytes that were signed survive JSON round-trip
        /// untouched.
        #[serde(with = "signers_file_types::base64_serde")]
        pub index_json: String,
        /// Raw signatures file content. Making it opaque here is not absolutely required as
        /// it is not a signed content. It allows the server to send the content untouched to the
        /// client.
        #[serde(with = "signers_file_types::base64_serde")]
        pub index_signatures_raw: String,
        /// Signers chain as of the artifact-signature commit. Carries everything
        /// needed for client-side realm and trust-anchor validation.
        pub signers_chain: signers_file_types::SignersChain,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct GetRevocationRequest {
        pub artifact_url: url::Url,
        pub forge_kind: Option<String>,
    }

    /// Response for the get_revocation endpoint.
    ///
    /// Contains the raw revocation JSON and signatures bytes, plus the
    /// signers chain as of the revocation commit. Clients validate the
    /// chain (realm + trust anchor) and use its head as the trusted
    /// signers config for the `can_revoke` and signature checks.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct GetRevocationResponse {
        /// Raw JSON bytes of `<artifact>.revocation.json`. Base64-encoded
        /// in transit so the bytes that were signed survive JSON round-trip
        /// untouched.
        #[serde(with = "signers_file_types::base64_serde")]
        pub revocation_json: String,
        /// Parsed signatures envelope from
        /// `<artifact>.revocation.json.signatures.json`.
        #[serde(with = "signers_file_types::base64_serde")]
        pub revocation_signatures: String,
        /// Signers chain as of the revocation commit (not the artifact-signature
        /// commit). Carries everything needed for client-side realm and
        /// trust-anchor validation.
        pub signers_chain: signers_file_types::SignersChain,
    }
}

pub mod github_helpers {
    use crate::errors::ApiError;

    pub fn validate_github_url(
        url: &url::Url,
    ) -> Result<(String, String, String, String), ApiError> {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::InvalidGitHubUrl("Missing host".to_string()))?;

        if !host.ends_with("github.com") {
            return Err(ApiError::InvalidGitHubUrl(
                "Only github.com URLs are supported".to_string(),
            ));
        }

        let path_segments: Vec<_> = url
            .path_segments()
            .ok_or_else(|| ApiError::InvalidGitHubUrl("Invalid path".to_string()))?
            .collect();

        let releases_idx = path_segments
            .iter()
            .position(|&s| s == "releases")
            .ok_or_else(|| ApiError::InvalidGitHubUrl("Missing /releases/ in path".to_string()))?;

        if releases_idx < 2
            || releases_idx + 2 >= path_segments.len()
            || path_segments[releases_idx + 1] != "tag"
        {
            return Err(ApiError::InvalidGitHubUrl(
                "Invalid GitHub release URL structure trying to extract tag".to_string(),
            ));
        }

        let owner = path_segments[releases_idx - 2].to_string();
        let repo = path_segments[releases_idx - 1].to_string();
        let tag = path_segments[releases_idx + 2].to_string();

        if owner.is_empty() || repo.is_empty() || tag.is_empty() {
            return Err(ApiError::InvalidGitHubUrl(
                "Owner, repo, and tag cannot be empty".to_string(),
            ));
        }
        Ok((host.to_string(), owner, repo, tag))
    }
}
pub mod rustls {
    pub fn setup_crypto_provider() {
        use rustls::crypto::{CryptoProvider, ring};

        // Use the provider corresponding to the 'ring' feature you selected
        let provider = ring::default_provider();

        let _ = CryptoProvider::install_default(provider);
    }
}

// Re-export commonly used types at the module level
pub use models::{
    FilesToSignResponse, GetSignatureStatusResponse, GetSignersChainResponse, ListPendingResponse,
    PingAuthStatus, PingResponse, RegisterAssetsRequest, RegisterAssetsResponse,
    RegisterRepoRequest, RegisterRepoResponse, RevokeFileRequest, RevokeFileResponse,
    SubmitSignatureRequest, SubmitSignatureResponse,
};

// ********************
// Assets registration
// ********************
/// Represents a validated common base path shared by a set of URLs.
pub struct CommonBasePath {
    pub prefix: String,
    pub parent_path: String,
}

/// Errors that can occur during URL validation.
#[derive(Debug, thiserror::Error)]
pub enum UrlValidationError {
    #[error("At least one URL must be provided")]
    EmptyUrls,
    #[error("Invalid URL origin: {0}")]
    InvalidOrigin(String),
    #[error("All URLs must have the same origin (scheme, host, and port). Found '{0}' and '{1}'")]
    DifferentOrigins(String, String),
    #[error("All URLs must be in the same directory. Found '{0}' and '{1}'")]
    DifferentParents(String, String),
}

/// Extracts the parent directory from a URL path.
///
/// For example, "/releases/v1.0/SHA256SUMS" yields "/releases/v1.0/".
/// Falls back to "/" when no slash is found.
pub fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) => path[..=pos].to_string(),
        None => "/".to_string(),
    }
}

/// Validates that all URLs share the same origin (scheme, host, port) and parent directory.
///
/// Returns the common origin prefix and parent path on success.
pub fn validate_common_parent(urls: &[Url]) -> Result<CommonBasePath, UrlValidationError> {
    let first = urls.first().ok_or(UrlValidationError::EmptyUrls)?;

    let first_prefix = forge_url::path_prefix_from_url(first)
        .map_err(|e| UrlValidationError::InvalidOrigin(e.to_string()))?;

    let first_parent = parent_path(first.path());

    for url in &urls[1..] {
        let prefix = forge_url::path_prefix_from_url(url)
            .map_err(|e| UrlValidationError::InvalidOrigin(e.to_string()))?;

        if prefix != first_prefix {
            return Err(UrlValidationError::DifferentOrigins(first_prefix, prefix));
        }

        let parent = parent_path(url.path());
        if parent != first_parent {
            return Err(UrlValidationError::DifferentParents(first_parent, parent));
        }
    }

    Ok(CommonBasePath {
        prefix: first_prefix,
        parent_path: first_parent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // parent_path tests
    // -----------------

    #[test]
    fn test_parent_path_with_file() {
        assert_eq!(parent_path("/releases/v1.0/SHA256SUMS"), "/releases/v1.0/");
    }

    #[test]
    fn test_parent_path_root_file() {
        assert_eq!(parent_path("/SHA256SUMS"), "/");
    }

    #[test]
    fn test_parent_path_no_slash() {
        assert_eq!(parent_path("SHA256SUMS"), "/");
    }

    // validate_common_parent tests
    // ----------------------------

    #[test]
    fn test_validate_single_url() -> anyhow::Result<()> {
        let urls = vec![Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?];
        let result = validate_common_parent(&urls)?;
        assert_eq!(result.prefix, "https/example.com/443");
        assert_eq!(result.parent_path, "/releases/v1.0/");
        Ok(())
    }

    #[test]
    fn test_validate_multiple_same_parent() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com/releases/v1.0/archive.tar.gz")?,
        ];
        let result = validate_common_parent(&urls)?;
        assert_eq!(result.prefix, "https/example.com/443");
        assert_eq!(result.parent_path, "/releases/v1.0/");
        Ok(())
    }

    #[test]
    fn test_validate_different_origins() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://other.com/releases/v1.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentOrigins(a, b)) => {
                assert_eq!(a, "https/example.com/443");
                assert_eq!(b, "https/other.com/443");
            }
            Err(e) => panic!("Expected DifferentOrigins error, got: {e}"),
            Ok(_) => panic!("Expected DifferentOrigins error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_same_host_different_scheme() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("http://example.com/releases/v1.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentOrigins(a, b)) => {
                assert_eq!(a, "https/example.com/443");
                assert_eq!(b, "http/example.com/80");
            }
            Err(e) => panic!("Expected DifferentOrigins error, got: {e}"),
            Ok(_) => panic!("Expected DifferentOrigins error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_same_host_different_port() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com:8443/releases/v1.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentOrigins(a, b)) => {
                assert_eq!(a, "https/example.com/443");
                assert_eq!(b, "https/example.com/8443");
            }
            Err(e) => panic!("Expected DifferentOrigins error, got: {e}"),
            Ok(_) => panic!("Expected DifferentOrigins error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_different_parents() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com/releases/v2.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentParents(a, b)) => {
                assert_eq!(a, "/releases/v1.0/");
                assert_eq!(b, "/releases/v2.0/");
            }
            Err(e) => panic!("Expected DifferentParents error, got: {e}"),
            Ok(_) => panic!("Expected DifferentParents error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_empty_urls() {
        let urls: Vec<Url> = vec![];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::EmptyUrls) => {}
            Err(e) => panic!("Expected EmptyUrls error, got: {e}"),
            Ok(_) => panic!("Expected EmptyUrls error, got Ok"),
        }
    }

    #[test]
    fn test_validate_invalid_origin() -> anyhow::Result<()> {
        // file:// URLs have an unsupported scheme
        let urls = vec![Url::parse("file:///tmp/test.txt")?];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::InvalidOrigin(msg)) => {
                assert!(msg.contains("Unsupported URL scheme"));
            }
            Err(e) => panic!("Expected InvalidOrigin error, got: {e}"),
            Ok(_) => panic!("Expected InvalidOrigin error, got Ok"),
        }
        Ok(())
    }

    // PingResponse serialization tests
    // --------------------------------

    #[test]
    fn test_ping_response_json_shape_unauthenticated() -> anyhow::Result<()> {
        let response = models::PingResponse {
            message: "pong".to_string(),
            auth: models::PingAuthStatus::Unauthenticated,
        };
        let value = serde_json::to_value(&response)?;
        assert_eq!(
            value,
            serde_json::json!({
                "message": "pong",
                "auth": {"status": "unauthenticated"}
            })
        );
        let parsed: models::PingResponse = serde_json::from_value(value)?;
        assert_eq!(parsed, response);
        Ok(())
    }

    #[test]
    fn test_ping_response_json_shape_success() -> anyhow::Result<()> {
        let response = models::PingResponse {
            message: "pong".to_string(),
            auth: models::PingAuthStatus::Success {
                public_key: "base64pk".to_string(),
            },
        };
        let value = serde_json::to_value(&response)?;
        assert_eq!(
            value,
            serde_json::json!({
                "message": "pong",
                "auth": {"status": "success", "public_key": "base64pk"}
            })
        );
        let parsed: models::PingResponse = serde_json::from_value(value)?;
        assert_eq!(parsed, response);
        Ok(())
    }

    #[test]
    fn test_ping_response_json_shape_failed() -> anyhow::Result<()> {
        let response = models::PingResponse {
            message: "pong".to_string(),
            auth: models::PingAuthStatus::Failed {
                public_key: Some("base64pk".to_string()),
                reason: "Replay attack detected: nonce already used".to_string(),
            },
        };
        let value = serde_json::to_value(&response)?;
        assert_eq!(
            value,
            serde_json::json!({
                "message": "pong",
                "auth": {
                    "status": "failed",
                    "public_key": "base64pk",
                    "reason": "Replay attack detected: nonce already used"
                }
            })
        );
        let parsed: models::PingResponse = serde_json::from_value(value)?;
        assert_eq!(parsed, response);
        Ok(())
    }

    #[test]
    fn test_ping_response_json_shape_failed_without_public_key() -> anyhow::Result<()> {
        let response = models::PingResponse {
            message: "pong".to_string(),
            auth: models::PingAuthStatus::Failed {
                public_key: None,
                reason: "Missing authentication headers".to_string(),
            },
        };
        let value = serde_json::to_value(&response)?;
        assert_eq!(
            value,
            serde_json::json!({
                "message": "pong",
                "auth": {
                    "status": "failed",
                    "public_key": null,
                    "reason": "Missing authentication headers"
                }
            })
        );
        let parsed: models::PingResponse = serde_json::from_value(value)?;
        assert_eq!(parsed, response);
        Ok(())
    }
}
