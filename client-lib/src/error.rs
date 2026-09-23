use features_lib::errors::{AggregateSignatureError, SignersFileError};
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientLibError {
    #[error("HTTP {status}: {url}")]
    HttpError { status: u16, url: String },

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Signers config parse error: {0}")]
    SignersConfigParse(String),

    #[error("Revocation parse error: {0}")]
    RevocationParse(String),

    #[error("Failed to fetch revocation: {0}")]
    RevocationFetchError(String),

    #[error("Unsupported forge: {0}")]
    UnsupportedForge(String),

    #[error("No artifact_signers group defined in signers config")]
    MissingArtifactSigners,

    #[error("Signature parse error: {0}")]
    SignaturesParseError(String),

    #[error("Signature threshold not met: required {required}, found {found}")]
    SignatureThresholdNotMet { required: usize, found: usize },

    #[error("File '{0}' not found in index")]
    FileNotInIndex(String),

    #[error("Unsupported hash algorithm: {:?}", .0)]
    UnsupportedHashAlgorithm(features_lib::HashAlgorithm),

    #[error("Hash mismatch: expected '{expected}', got '{computed}'")]
    HashMismatch { expected: String, computed: String },

    #[error("Hash algorithm mismatch: expected {expected:?}, got {computed:?}")]
    HashAlgorithmMismatch {
        expected: features_lib::HashAlgorithm,
        computed: features_lib::HashAlgorithm,
    },

    #[error("File has been revoked at {timestamp} by {initiator}")]
    FileRevoked {
        timestamp: String,
        initiator: String,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to persist file: {0}")]
    PersistError(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Forge URL error: {0}")]
    ForgeUrl(#[from] forge_url::ForgeUrlError),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] Utf8Error),

    #[error("Aggregate signature error: {0}")]
    AggregateSignature(#[from] AggregateSignatureError),

    #[error("Signers file error: {0}")]
    SignersFile(#[from] SignersFileError),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Revocation invalid: {0}")]
    RevocationInvalid(String),

    #[error("Revocation signers chain invalid: {0}")]
    RevocationChainInvalid(String),

    #[error("Revocation initiator is not authorized to revoke")]
    RevocationUnauthorized,

    #[error("Revocation signature threshold not met: found {found} valid signatures")]
    RevocationThresholdNotMet { found: usize },

    #[error(
        "Revocation subject digest '{subject_digest}' does not match index digest '{index_digest}'"
    )]
    RevocationSubjectMismatch {
        subject_digest: String,
        index_digest: String,
    },

    #[error("An error occured: {0}")]
    GenericError(String),

    #[error("Failed to fetch signers chain: {0}")]
    SignersChainFetchError(String),

    #[error("Failed to fetch artifact info: {0}")]
    ArtifactInfoFetchError(String),

    #[error("Failed to fetch signers file from forge: {0}")]
    SignersChainForgeFetchError(String),

    #[error("Failed to fetch signers source: {0}")]
    SignersMetadataSourceFetchError(String),

    #[error("Signers chain is empty")]
    SignersChainEmpty,

    #[error("First entry content does not match forge source")]
    SignersChainFirstEntryMismatch,

    #[error("First entry validation failed: {0}")]
    SignersChainFirstEntryInvalid(String),

    #[error("Trust anchor realm '{anchor_realm}' does not contain download path '{artifact_path}'")]
    SignersChainTrustAnchorOutsideRealm {
        artifact_path: String,
        anchor_realm: String,
    },

    #[error("Signers chain transition is invalid")]
    SignersChainTransitionInvalid,

    #[error("Metadata source '{url}' does not match path '{path}'")]
    UrlOutsideRealm { path: String, url: String },
}

pub type AsfaloadLibResult<T> = std::result::Result<T, ClientLibError>;
