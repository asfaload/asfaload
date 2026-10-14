//! Tests for `RegisterAssetsPayload`.
//!
//! `RegisterAssetsPayload` is the request type for `POST /v1/assets`, shared by
//! the client (`admin-lib`) and the server (`rest-api`). It uses serde's
//! externally tagged representation, so each variant maps to a JSON object
//! keyed by the variant name:
//!
//! - `GithubRelease` -> `{"GithubRelease": {"github_release_url": ..., "index": ..., "signature": ...}}`
//! - `ChecksumFiles` -> `{"ChecksumFiles": {"csum_files": [...]}}`
//!
//! The enum makes the two registration modes mutually exclusive: exactly one
//! variant is selected on deserialization.

use rest_api_types::RegisterAssetsPayload;
use rest_api_types::models::{ChecksumFilesPayload, GithubReleasePayload};

const RELEASE_URL: &str = "https://github.com/owner/repo/releases/tag/v1.0.0";
const INDEX: &str = "eyJ2ZXJzaW9uIjoxfQ==";
const SIGNATURE: &str = "c2lnbmF0dXJl";
const CHECKSUM_URL_SHA256: &str = "https://files.example.com/releases/v1.0/SHA256SUMS";
const CHECKSUM_URL_SHA512: &str = "https://files.example.com/releases/v1.0/SHA512SUMS";

fn github_release_json() -> String {
    serde_json::json!({
        "GithubRelease": {
            "github_release_url": RELEASE_URL,
            "index": INDEX,
            "signature": SIGNATURE,
        }
    })
    .to_string()
}

fn checksum_files_json(urls: &[&str]) -> String {
    serde_json::json!({
        "ChecksumFiles": { "csum_files": urls }
    })
    .to_string()
}

#[test]
fn test_deserialize_github_release() {
    let payload: RegisterAssetsPayload = serde_json::from_str(&github_release_json()).unwrap();

    match payload {
        RegisterAssetsPayload::GithubRelease(p) => {
            assert_eq!(p.github_release_url, RELEASE_URL);
            assert_eq!(p.index, INDEX);
            assert_eq!(p.signature, SIGNATURE);
        }
        other => panic!("expected GithubRelease variant, got {other:?}"),
    }
}

#[test]
fn test_deserialize_checksum_files() {
    let payload: RegisterAssetsPayload = serde_json::from_str(&checksum_files_json(&[
        CHECKSUM_URL_SHA256,
        CHECKSUM_URL_SHA512,
    ]))
    .unwrap();

    match payload {
        RegisterAssetsPayload::ChecksumFiles(p) => {
            assert_eq!(p.csum_files, vec![CHECKSUM_URL_SHA256, CHECKSUM_URL_SHA512]);
        }
        other => panic!("expected ChecksumFiles variant, got {other:?}"),
    }
}

#[test]
fn test_deserialize_single_checksum_file() {
    let payload: RegisterAssetsPayload =
        serde_json::from_str(&checksum_files_json(&[CHECKSUM_URL_SHA256])).unwrap();

    match payload {
        RegisterAssetsPayload::ChecksumFiles(p) => {
            assert_eq!(p.csum_files, vec![CHECKSUM_URL_SHA256]);
        }
        other => panic!("expected ChecksumFiles variant, got {other:?}"),
    }
}

#[test]
fn test_deserialize_empty_checksum_files() {
    let payload: RegisterAssetsPayload = serde_json::from_str(&checksum_files_json(&[])).unwrap();

    match payload {
        RegisterAssetsPayload::ChecksumFiles(p) => assert!(p.csum_files.is_empty()),
        other => panic!("expected ChecksumFiles variant, got {other:?}"),
    }
}

#[test]
fn test_deserialize_empty_object_is_rejected() {
    // An empty object carries no variant tag, so the type itself enforces that
    // one of the two modes is selected.
    assert!(serde_json::from_str::<RegisterAssetsPayload>("{}").is_err());
}

#[test]
fn test_deserialize_github_release_without_index_is_rejected() {
    let json = serde_json::json!({
        "GithubRelease": { "github_release_url": RELEASE_URL }
    })
    .to_string();
    assert!(serde_json::from_str::<RegisterAssetsPayload>(&json).is_err());
}

#[test]
fn test_deserialize_github_release_without_signature_is_rejected() {
    let json = serde_json::json!({
        "GithubRelease": { "github_release_url": RELEASE_URL, "index": INDEX }
    })
    .to_string();
    assert!(serde_json::from_str::<RegisterAssetsPayload>(&json).is_err());
}

#[test]
fn test_deserialize_unknown_variant_is_rejected() {
    let json = serde_json::json!({
        "UnknownVariant": { "csum_files": [CHECKSUM_URL_SHA256] }
    })
    .to_string();
    assert!(serde_json::from_str::<RegisterAssetsPayload>(&json).is_err());
}

#[test]
fn test_serialize_github_release_is_tagged() {
    let payload = RegisterAssetsPayload::GithubRelease(GithubReleasePayload {
        github_release_url: RELEASE_URL.to_string(),
        index: INDEX.to_string(),
        signature: SIGNATURE.to_string(),
    });

    assert_eq!(
        serde_json::to_value(&payload).unwrap(),
        serde_json::json!({
            "GithubRelease": {
                "github_release_url": RELEASE_URL,
                "index": INDEX,
                "signature": SIGNATURE,
            }
        })
    );
}

#[test]
fn test_serialize_checksum_files_is_tagged() {
    let payload = RegisterAssetsPayload::ChecksumFiles(ChecksumFilesPayload {
        csum_files: vec![CHECKSUM_URL_SHA256.to_string()],
    });

    assert_eq!(
        serde_json::to_value(&payload).unwrap(),
        serde_json::json!({
            "ChecksumFiles": { "csum_files": [CHECKSUM_URL_SHA256] }
        })
    );
}

#[test]
fn test_roundtrip_github_release() {
    let original = RegisterAssetsPayload::GithubRelease(GithubReleasePayload {
        github_release_url: RELEASE_URL.to_string(),
        index: INDEX.to_string(),
        signature: SIGNATURE.to_string(),
    });

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RegisterAssetsPayload = serde_json::from_str(&json).unwrap();

    assert_eq!(
        serde_json::to_value(&original).unwrap(),
        serde_json::to_value(&deserialized).unwrap()
    );
}

#[test]
fn test_roundtrip_checksum_files() {
    let original = RegisterAssetsPayload::ChecksumFiles(ChecksumFilesPayload {
        csum_files: vec![
            CHECKSUM_URL_SHA256.to_string(),
            CHECKSUM_URL_SHA512.to_string(),
        ],
    });

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RegisterAssetsPayload = serde_json::from_str(&json).unwrap();

    assert_eq!(
        serde_json::to_value(&original).unwrap(),
        serde_json::to_value(&deserialized).unwrap()
    );
}
