use crate::commands::revocation_output::{RevocationJsonOutput, print_revocation_overview};
use crate::error::{ClientCliError, Result, ensure_backend_success};
use common::AsfaloadHashes;
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
    expected_digest: &AsfaloadHashes,
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

    if subject_digest != *expected_digest {
        return Err(ClientCliError::ExpectedDigestMismatch(
            subject_digest.to_string(),
            expected_digest.clone(),
        ));
    }

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

    ensure_backend_success(
        response.success,
        &response.message,
        ClientCliError::RevocationFailed,
    )?;

    // Display result
    if json {
        let output = RevocationJsonOutput {
            response: &response,
            revocation_digest: &revocation_hash,
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        print_revocation_overview(&response, file_path, &revocation_hash, backend_url);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use features_lib::{sha512_for_content, to_posix_json};
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
}
