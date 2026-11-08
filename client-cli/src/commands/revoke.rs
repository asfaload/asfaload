use crate::commands::revocation_output::print_revocation_overview;
use crate::error::{ClientCliError, Result};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    sha512_for_content,
};
use rest_api_types::RevokeFileResponse;

/// Handle the revoke command.
///
/// Builds a revocation document, signs it, and submits to the backend.
///
/// # Workflow
/// 1. Load secret key and derive public key
/// 2. Fetch the file content from backend
/// 3. Compute sha512 of the fetched content
/// 4. Build RevocationInfo JSON (timestamp, subject_digest, initiator)
/// 5. Sign the sha512 of the revocation JSON
/// 6. Submit to backend via POST /v1/revoke
/// 7. Fail when the backend reports a failed revocation
/// 8. Display result
pub async fn handle_revoke_command(
    backend_url: &str,
    file_path: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<RevokeFileResponse> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    let public_key = AsfaloadPublicKeys::from_secret_key(&secret_key)?;

    // Create REST client
    let client = admin_lib::v1::Client::new(backend_url);

    // Fetch file content from backend to compute its digest
    let file_content = client.fetch_file(file_path).await?;

    // Compute sha512 of the file content
    let subject_digest = sha512_for_content(file_content)?;

    // Build the revocation document
    let revocation = signers_file_types::revocation::RevocationInfo {
        timestamp: chrono::Utc::now(),
        subject_digest,
        initiator: public_key.clone(),
    };
    let revocation_json = features_lib::to_posix_json(&revocation)?;

    // Sign the sha512 of the revocation JSON
    let revocation_hash = sha512_for_content(revocation_json.as_bytes().to_vec())?;
    let signature = secret_key.sign(&revocation_hash)?;

    // Submit revocation to backend
    let response = client
        .revoke_file(
            file_path,
            &revocation_json,
            &signature,
            &public_key,
            &secret_key,
        )
        .await?;

    ensure_revocation_succeeded(&response)?;

    // Display result
    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        print_revocation_overview(&response, file_path, &revocation_hash, backend_url);
    }

    Ok(response)
}

/// Return an error when the backend reports a failed revocation, so that the
/// process exits with a non-zero code.
fn ensure_revocation_succeeded(response: &RevokeFileResponse) -> Result<()> {
    if response.success {
        Ok(())
    } else {
        Err(ClientCliError::RevocationFailed(response.message.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_revocation_succeeded;
    use crate::error::ClientCliError;
    use features_lib::{sha512_for_content, to_posix_json};
    use rest_api_types::RevokeFileResponse;
    use signers_file_types::revocation::RevocationInfo;
    use test_helpers::TestKeys;

    #[test]
    fn revocation_json_ends_with_exactly_one_newline() {
        let test_keys = TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();

        let subject_digest = sha512_for_content(b"something".to_vec()).unwrap();
        let revocation = RevocationInfo {
            timestamp: chrono::Utc::now(),
            subject_digest,
            initiator: public_key,
        };

        let json = to_posix_json(&revocation).unwrap();
        assert!(json.ends_with("}\n"), "revocation JSON must end with }}\\n");
        assert!(
            !json.ends_with("\n\n"),
            "revocation JSON must not end with double newline"
        );
    }

    #[test]
    fn failed_revocation_response_is_an_error() {
        let response = RevokeFileResponse {
            success: false,
            message: "backend refused".to_string(),
            required_signers: vec![],
        };
        match ensure_revocation_succeeded(&response) {
            Err(ClientCliError::RevocationFailed(message)) => {
                assert_eq!(message, "backend refused")
            }
            other => panic!("expected RevocationFailed, got {other:?}"),
        }
    }

    #[test]
    fn successful_revocation_response_is_ok() {
        let response = RevokeFileResponse {
            success: true,
            message: "unused".to_string(),
            required_signers: vec![],
        };
        assert!(ensure_revocation_succeeded(&response).is_ok());
    }
}
