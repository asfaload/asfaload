use std::collections::HashMap;

use crate::cli::DEFAULT_BACKEND;
use crate::commands::release_download_output::{
    is_release_index_path, print_release_download_next_step,
};
use crate::commands::revocation_output::revocation_note;
use crate::commands::signature_status::signature_status_hint;
use crate::commands::signers_submission_output::{
    ReleaseExample, print_activation_next_step, release_example_for,
};
use crate::error::{Result, is_signature_already_collected};
use crate::utils::executable_name;
use common::fs::names::{is_pending_signers_file_path, metadata_path_for};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    AsfaloadSignatures, SignersConfigMetadata, sha512_for_content, to_posix_json,
};
use rest_api_types::{SubmitSignatureResponse, models::ClientPendingFile};

/// Handle the sign-pending command.
///
/// Translates a file path from list-pending into a signed submission to the backend.
/// This is a one-step command for the user that:
/// 1. Fetches all files that need signing from backend
/// 2. Computes hash and signs each file with user's key
/// 3. Submits all signatures to backend in one request
///
/// # Arguments
/// * `file_path` - Path to the file (as returned by list-pending)
/// * `backend_url` - Backend API URL
/// * `secret_key_path` - Path to the user's secret key file
/// * `password` - Password to unlock secret key
///
/// # Workflow
/// * Load secret key and derive public key
/// * Fetch all files to sign from backend
/// * Compute SHA512 hash and sign each file
/// * Submit all signatures to backend
/// * Display result (whether signature is now complete)
pub async fn handle_sign_pending_command(
    pending_file: ClientPendingFile,
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<SubmitSignatureResponse> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    handle_sign_pending_sec_key(pending_file, backend_url, &secret_key, json).await
}

pub async fn handle_sign_pending_sec_key(
    pending_file: ClientPendingFile,
    backend_url: &str,
    secret_key: &AsfaloadSecretKeys,
    json: bool,
) -> Result<SubmitSignatureResponse> {
    let public_key = AsfaloadPublicKeys::from_secret_key(secret_key)?;
    // Create REST client
    let client = admin_lib::v1::Client::new(backend_url);

    // Fetch all files that need signing
    let files_to_sign = match client
        .fetch_files_to_sign(pending_file.path(), secret_key)
        .await
    {
        Ok(files) => files,
        // The backend gives this refusal only for a pending signers file that was
        // activated with a signature of this key.
        Err(e) if is_signature_already_collected(&e) => {
            let response = SubmitSignatureResponse { is_complete: true };
            if json {
                println!("{}", serde_json::to_string(&response)?);
            } else {
                println!(
                    "The signers file {} was activated. Your signature was collected. You do not need to sign it again.",
                    pending_file.path()
                );
                // The backend does not give the metadata of an activated
                // signers file, so the forge is not known. The checksums files
                // example applies to all forges.
                println!();
                print_activation_next_step(&ReleaseExample::ChecksumsFiles, backend_url);
            }
            return Ok(response);
        }
        Err(e) => return Err(e.into()),
    };
    check_files_to_sign_paths(pending_file.path(), &files_to_sign)?;

    // A pending signers file must be byte-identical to the forge source its
    // metadata points at. A compromised backend could otherwise have us sign a
    // config that differs from the one the forge URL serves. The source is
    // fetched from the retrieval URL recorded in the metadata and compared by
    // SHA-512.
    let signers_metadata = if is_pending_signers_file_path(pending_file.path()) {
        let metadata_key = metadata_path_for(pending_file.path())?
            .to_string_lossy()
            .to_string();
        // We get both the signers file and its metadata file (their respective paths are the keys
        // of the HashMap)
        let signers_content = files_to_sign.get(pending_file.path()).ok_or_else(|| {
            crate::error::ClientCliError::InvalidInput(format!(
                "Missing content for pending signers file: {}",
                pending_file.path()
            ))
        })?;
        // Extract the metadata json from the HashMap
        let metadata_content = files_to_sign.get(&metadata_key).ok_or_else(|| {
            crate::error::ClientCliError::InvalidInput(format!(
                "Missing metadata required to validate pending signers file: {}",
                metadata_key
            ))
        })?;

        let metadata = parse_canonical_metadata(metadata_content)?;
        // Retrieves file from publishing platform to assess validity.
        client_lib::verify_signers_file_matches_metadata_source(
            signers_content,
            pending_file.path(),
            &metadata,
        )
        .await
        .map_err(|e| crate::error::signers_metadata_verification_error(&metadata, e))?;
        Some(metadata)
    } else {
        None
    };

    // Sign each file
    let mut signatures: HashMap<String, AsfaloadSignatures> = HashMap::new();
    for (path, content) in &files_to_sign {
        // content is &Vec<u8>, as_slice() give a &[u8] and avoids cloning
        let hash = sha512_for_content(content.as_slice())?;
        // Only verify the digest for the primary file; associated files (e.g. metadata)
        // are signed without digest pre-verification since pending_file.digest() covers
        // only the primary file.
        if *path == pending_file.path() && hash != *pending_file.digest() {
            return Err(crate::error::ClientCliError::ServerDigestError(
                hash.to_string(),
                pending_file.digest().clone(),
            ));
        }
        let signature = secret_key.sign(&hash)?;
        signatures.insert(path.clone(), signature);
    }

    // Submit all signatures to backend
    let file_path = pending_file.path().to_string();
    let response = client
        .submit_signatures(pending_file, &public_key, &signatures, secret_key)
        .await
        .map_err(|e| crate::error::submit_signature_error(e, &file_path))?;

    // Display result
    let revocation_note = revocation_note(&file_path, response.is_complete);
    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.is_complete {
        println!(
            "Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature."
        );
        // A complete pending signers file is now the active signers file, so
        // releases can be registered.
        if let Some(metadata) = &signers_metadata {
            println!();
            print_activation_next_step(&release_example_for(metadata), backend_url);
        }
        // A complete release index lets users download the artifacts with
        // verification.
        if is_release_index_path(&file_path) {
            println!();
            print_release_download_next_step(
                &file_path,
                files_to_sign.get(&file_path).map(Vec::as_slice),
                backend_url,
            );
        }
        if let Some(note) = revocation_note {
            println!();
            println!("{note}");
        }
    } else {
        println!(
            "Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures."
        );
        if let Some(note) = revocation_note {
            println!("{note}");
        }
        let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
        println!();
        print!(
            "{}",
            signature_status_hint(&file_path, non_default_backend, &executable_name())
        );
    }

    Ok(response)
}

/// Parse signers metadata, and accept it only in its canonical form.
///
/// The metadata is signed without a digest given by the user, so its bytes
/// must contain nothing more than the metadata itself. Without this check, a
/// compromised backend could add fields of another file type, for example an
/// index, and the signature of the metadata would also be valid for that
/// other file. Clients always write metadata with `to_posix_json`, so
/// legitimate metadata is always in that form.
///
/// # Errors
/// * `BackendDataError` when the content is not valid metadata, or when it is
///   not in its canonical form
fn parse_canonical_metadata(content: &[u8]) -> Result<SignersConfigMetadata> {
    let metadata: SignersConfigMetadata =
        serde_json::from_slice(content).map_err(crate::error::signers_metadata_parse_error)?;
    if to_posix_json(&metadata)?.as_bytes() == content {
        Ok(metadata)
    } else {
        Err(crate::error::ClientCliError::BackendDataError(
            "Metadata is not in its canonical form".to_string(),
        ))
    }
}

/// Make sure the backend sends exactly the files the user agreed to sign.
///
/// The signature covers only the hash of a content, not its path, so it is
/// valid for that content wherever it is used. A compromised backend that adds
/// a file to the set would get a signature for content the user never checked.
/// A backend that removes the requested file would bypass the digest check,
/// which applies to the requested file only.
/// The only file accepted next to the requested file is the metadata of a
/// pending signers file, as it is needed to validate that signers file.
///
/// # Errors
/// * `BackendDataError` when the requested file is missing, or when an
///   unexpected file is present
fn check_files_to_sign_paths(
    requested_path: &str,
    files_to_sign: &HashMap<String, Vec<u8>>,
) -> Result<()> {
    if !files_to_sign.contains_key(requested_path) {
        return Err(crate::error::ClientCliError::BackendDataError(format!(
            "Backend did not send the requested file {requested_path}"
        )));
    }

    let metadata_path = if is_pending_signers_file_path(requested_path) {
        Some(
            metadata_path_for(requested_path)?
                .to_string_lossy()
                .to_string(),
        )
    } else {
        None
    };

    let mut unexpected_paths: Vec<&str> = files_to_sign
        .keys()
        .map(String::as_str)
        .filter(|path| *path != requested_path && Some(*path) != metadata_path.as_deref())
        .collect();
    if unexpected_paths.is_empty() {
        Ok(())
    } else {
        // Sorted to give a stable error message, as HashMap order is random.
        unexpected_paths.sort_unstable();
        Err(crate::error::ClientCliError::BackendDataError(format!(
            "Backend sent unexpected files to sign for {requested_path}: {}",
            unexpected_paths.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ClientCliError;
    use features_lib::constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE};

    fn files(paths: &[&str]) -> HashMap<String, Vec<u8>> {
        paths
            .iter()
            .map(|path| (path.to_string(), b"content".to_vec()))
            .collect()
    }

    #[test]
    fn check_files_to_sign_paths_cases() {
        let index = "github.com/acme/tool/releases/v1/asfaload.index.json";
        let other_index = "github.com/acme/tool/releases/v2/asfaload.index.json";
        let pending_signers = format!("github.com/acme/tool/{PENDING_SIGNERS_DIR}/{SIGNERS_FILE}");
        let pending_metadata = metadata_path_for(&pending_signers)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let active_signers = format!("github.com/acme/tool/{SIGNERS_DIR}/{SIGNERS_FILE}");
        let active_metadata = metadata_path_for(&active_signers)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let index_metadata = metadata_path_for(index)
            .unwrap()
            .to_string_lossy()
            .to_string();

        // (requested path, paths sent by the backend, expected error message fragment)
        let cases: Vec<(&str, Vec<&str>, Option<&str>)> = vec![
            (index, vec![index], None),
            (&pending_signers, vec![&pending_signers], None),
            (
                &pending_signers,
                vec![&pending_signers, &pending_metadata],
                None,
            ),
            (index, vec![], Some("did not send the requested file")),
            (
                index,
                vec![other_index],
                Some("did not send the requested file"),
            ),
            (index, vec![index, other_index], Some(other_index)),
            // Metadata is only accepted next to a pending signers file.
            (index, vec![index, &index_metadata], Some(&index_metadata)),
            (
                &active_signers,
                vec![&active_signers, &active_metadata],
                Some(&active_metadata),
            ),
            (
                &pending_signers,
                vec![&pending_signers, &pending_metadata, index],
                Some(index),
            ),
            // Metadata of another file than the requested one is rejected.
            (
                &pending_signers,
                vec![&pending_signers, &active_metadata],
                Some(&active_metadata),
            ),
        ];

        for (requested, sent, expected_error) in cases {
            let result = check_files_to_sign_paths(requested, &files(&sent));
            match (result, expected_error) {
                (Ok(()), None) => {}
                (Err(ClientCliError::BackendDataError(msg)), Some(fragment)) => assert!(
                    msg.contains(fragment),
                    "requested {requested}, sent {sent:?}: message {msg:?} does not contain {fragment:?}"
                ),
                (Err(e), _) => panic!("requested {requested}, sent {sent:?}: unexpected error {e}"),
                (Ok(()), Some(fragment)) => panic!(
                    "requested {requested}, sent {sent:?}: expected error containing {fragment:?}, got Ok"
                ),
            }
        }
    }

    #[test]
    fn parse_canonical_metadata_cases() {
        let canonical = test_helpers::signers_metadata_json(
            "https://github.com/acme/tool/raw/main/asfaload.signers/index.json",
            "https://github.com/acme/tool/raw/main/asfaload.signers/index.json",
            br#"{"version":1}"#,
        );
        let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        let mut with_extra_field = value.clone();
        with_extra_field
            .as_object_mut()
            .unwrap()
            .insert("publishedFiles".to_string(), serde_json::json!([]));
        let with_extra_field = to_posix_json(&with_extra_field).unwrap();
        let without_final_newline = canonical.trim_end().to_string();

        // (description, content, expected error message fragment)
        let cases: Vec<(&str, &str, Option<&str>)> = vec![
            ("canonical", &canonical, None),
            ("pretty printed", &pretty, Some("canonical form")),
            ("extra field", &with_extra_field, Some("unknown field")),
            (
                "without final newline",
                &without_final_newline,
                Some("canonical form"),
            ),
            ("not json", "not json", Some("Failed to parse metadata")),
        ];

        for (description, content, expected_error) in cases {
            match (parse_canonical_metadata(content.as_bytes()), expected_error) {
                (Ok(_), None) => {}
                (Err(ClientCliError::BackendDataError(msg)), Some(fragment)) => assert!(
                    msg.contains(fragment),
                    "{description}: message {msg:?} does not contain {fragment:?}"
                ),
                (Err(e), _) => panic!("{description}: unexpected error {e}"),
                (Ok(_), Some(fragment)) => {
                    panic!("{description}: expected error containing {fragment:?}, got Ok")
                }
            }
        }
    }

    #[test]
    fn check_files_to_sign_paths_lists_unexpected_paths_sorted() {
        let index = "releases/v1/asfaload.index.json";
        let result = check_files_to_sign_paths(index, &files(&[index, "z/file", "a/file"]));
        match result {
            Err(ClientCliError::BackendDataError(msg)) => {
                assert!(
                    msg.ends_with("a/file, z/file"),
                    "unexpected message {msg:?}"
                )
            }
            Err(e) => panic!("Expected BackendDataError but got {e}"),
            Ok(()) => panic!("Expected BackendDataError, got Ok"),
        }
    }
}
