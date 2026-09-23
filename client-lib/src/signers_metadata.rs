use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::{SignersConfigMetadata, SignersConfigOrigin, sha512_for_content};
use forge_url::{ForgeInfo, ForgeTrait};

/// Verify that a file's bytes are identical to the source content served by the
/// forge URL recorded in its metadata.
///
/// The source is fetched from the metadata's `retrieval_url` and its SHA-512 is
/// compared to the SHA-512 of the file's bytes.
pub async fn verify_signers_file_matches_metadata_source(
    file_content: &[u8],
    _backend_path: &str,
    metadata: &SignersConfigMetadata,
) -> AsfaloadLibResult<()> {
    let SignersConfigOrigin::Forge(origin) = metadata.origin();
    let source_url = origin.retrieval_url();

    let response = reqwest::Client::new()
        .get(source_url)
        .send()
        .await
        .map_err(|e| ClientLibError::SignersMetadataSourceFetchError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(ClientLibError::SignersMetadataSourceFetchError(format!(
            "HTTP {} fetching {}",
            response.status(),
            source_url
        )));
    }

    let source_content = response
        .bytes()
        .await
        .map_err(|e| ClientLibError::SignersMetadataSourceFetchError(e.to_string()))?;

    let source_hash = sha512_for_content(source_content.as_ref())?.to_hex();
    let file_hash = sha512_for_content(file_content)?.to_hex();

    if file_hash == source_hash {
        Ok(())
    } else {
        Err(ClientLibError::HashMismatch {
            expected: source_hash,
            computed: file_hash,
        })
    }
}

/// Validates that the url can be used as a source for the path on the backend.
pub fn verify_remote_url_in_path_realm(path: &str, url: &str) -> AsfaloadLibResult<()> {
    let reject = |url: String, project_id: Option<String>| ClientLibError::UrlOutsideRealm {
        path: path.to_string(),
        url,
        project_id,
    };

    let parsed = url::Url::parse(url).map_err(|_| reject(url.to_string(), None))?;
    let project_id = ForgeInfo::new(&parsed)
        .map(|info| info.project_id())
        .map_err(|_| reject(url.to_string(), None))?;

    // Important to test against a '/'-ending string, to prevent issues with repo names prefix of
    // the one we work with.
    if path == project_id || path.starts_with(&format!("{}/", project_id)) {
        Ok(())
    } else {
        Err(reject(url.to_string(), Some(project_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::{Forge, ForgeOrigin, SignersConfigMetadata, VerifiedForgeContent};

    const SOURCE_CONTENT: &str = r#"{"version":1}"#;

    fn metadata_with_source_url(source_url: &str, source_content: &str) -> SignersConfigMetadata {
        SignersConfigMetadata::from_forge(ForgeOrigin::new(
            Forge::Github,
            // Thi sis the url passed in by the user, by we use the actual retrieval url, which
            // might be different.
            "https://github.com/acme/tool/raw/main/asfaload.signers/index.json".to_string(),
            VerifiedForgeContent::new_for_test(source_url.to_string(), source_content.to_string()),
            chrono::Utc::now(),
        ))
    }

    async fn serve_source(
        source_content: &str,
    ) -> (mockito::ServerGuard, mockito::Mock, SignersConfigMetadata) {
        let mut server = mockito::Server::new_async().await;
        let source_mock = server
            .mock("GET", "/source")
            .with_status(200)
            .with_body(source_content)
            .create_async()
            .await;
        let metadata =
            metadata_with_source_url(&format!("{}/source", server.url()), source_content);
        (server, source_mock, metadata)
    }

    #[tokio::test]
    async fn matching_content_is_accepted() {
        let (_server, source_mock, metadata) = serve_source(SOURCE_CONTENT).await;

        let result = super::verify_signers_file_matches_metadata_source(
            SOURCE_CONTENT.as_bytes(),
            &metadata,
        )
        .await;

        assert!(result.is_ok(), "{result:?}");
        source_mock.assert_async().await;
    }

    #[tokio::test]
    async fn changed_byte_is_rejected() {
        let (_server, _source_mock, metadata) = serve_source(SOURCE_CONTENT).await;

        let result = super::verify_signers_file_matches_metadata_source(
            br#"{"version":2}"#.as_slice(),
            &metadata,
        )
        .await;

        match result {
            Err(ClientLibError::HashMismatch { .. }) => {}
            Err(e) => panic!("Expected HashMismatch, got: {e:?}"),
            Ok(_) => panic!("Expected HashMismatch error, got Ok"),
        }
    }

    #[tokio::test]
    async fn trailing_whitespace_is_rejected() {
        let (_server, _source_mock, metadata) = serve_source(SOURCE_CONTENT).await;
        let content = format!("{SOURCE_CONTENT}\n");

        let result =
            super::verify_signers_file_matches_metadata_source(content.as_bytes(), &metadata).await;

        match result {
            Err(ClientLibError::HashMismatch { .. }) => {}
            Err(e) => panic!("Expected HashMismatch, got: {e:?}"),
            Ok(_) => panic!("Expected HashMismatch error, got Ok"),
        }
    }

    #[tokio::test]
    async fn source_fetch_failure_is_reported() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/source")
            .with_status(500)
            .create_async()
            .await;
        let metadata =
            metadata_with_source_url(&format!("{}/source", server.url()), SOURCE_CONTENT);

        let result = super::verify_signers_file_matches_metadata_source(
            SOURCE_CONTENT.as_bytes(),
            &metadata,
        )
        .await;

        match result {
            Err(ClientLibError::SignersMetadataSourceFetchError(_)) => {}
            Err(e) => panic!("Expected SignersMetadataSourceFetchError, got: {e:?}"),
            Ok(_) => panic!("Expected source fetch error, got Ok"),
        }
    }

    // -- Unit tests for the realm check itself --

    #[test]
    fn realm_check_accepts_artifact_inside_fileserver_project() {
        // Anchor signers file lives in acme/tool/asfaload.signers; the file
        // server strips the signers dir, so the project root is acme/tool.
        // A non-ambiguous host: under the test-utils feature, localhost and
        // 127.0.0.1 are GitHub test hosts, and would make this URL parse as
        // GitHub instead of FileServer.
        let res = verify_remote_url_in_path_realm(
            "http/files.example.com/8080/acme/tool/releases/v1.0.0/asfaload.index.json",
            "http://files.example.com:8080/acme/tool/asfaload.signers/signers.json",
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn realm_check_accepts_path_equal_to_project_id() {
        // A non-ambiguous host: under the test-utils feature, localhost and
        // 127.0.0.1 are GitHub test hosts, and would make this URL parse as
        // GitHub instead of FileServer.
        let res = verify_remote_url_in_path_realm(
            "http/files.example.com/8080/project",
            "http://files.example.com:8080/project/signers.json",
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn realm_check_accepts_github_blob_url() {
        let res = verify_remote_url_in_path_realm(
            "https/github.com/443/acme/tool/asfaload.signers/index.json",
            "https://github.com/acme/tool/blob/main/asfaload.signers/index.json",
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn realm_check_accepts_raw_github_url_canonicalised_to_github_project() {
        // raw.githubusercontent.com URLs canonicalise to the github.com
        // project, so a signers file served by the raw host matches a backend
        // path rooted at https/github.com/443.
        let res = verify_remote_url_in_path_realm(
            "https/github.com/443/asfaload/repo_for_e2e_tests/asfaload.signers/index.json",
            "https://raw.githubusercontent.com/asfaload/repo_for_e2e_tests/master/basic_flow/signers_file_1_asfaload.json",
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn realm_check_rejects_url_from_other_github_repo() {
        let url =
            "https://raw.githubusercontent.com/attacker/evil/master/asfaload.signers/index.json";
        let res = verify_remote_url_in_path_realm(
            "https/github.com/443/acme/tool/asfaload.signers/index.json",
            url,
        );
        match res {
            Err(ClientLibError::UrlOutsideRealm {
                url: error_url,
                project_id,
                ..
            }) => {
                assert_eq!(error_url, url);
                assert_eq!(
                    project_id.as_deref(),
                    Some("https/github.com/443/attacker/evil")
                );
            }
            Err(e) => panic!("Expected UrlOutsideRealm, got {e}"),
            Ok(_) => panic!("Expected UrlOutsideRealm error, got Ok"),
        }
    }

    #[test]
    fn realm_check_rejects_different_repo_same_host() {
        let res = verify_remote_url_in_path_realm(
            "http/127.0.0.1/8080/acme/tool/releases/v1.0.0/asfaload.index.json",
            "http://127.0.0.1:8080/attacker/evil/asfaload.signers/signers.json",
        );
        assert!(matches!(res, Err(ClientLibError::UrlOutsideRealm { .. })));
    }

    #[test]
    fn realm_check_rejects_prefix_collision_repo() {
        // The anchor repo "acme/to" is a STRING prefix of the download's
        // "acme/tool" but a different project. A naive `starts_with(project_id)`
        // would wrongly accept it; the `/`-boundary check must reject it.
        let res = verify_remote_url_in_path_realm(
            "http/127.0.0.1/8080/acme/tool/releases/v1.0.0/asfaload.index.json",
            "http://127.0.0.1:8080/acme/to/asfaload.signers/signers.json",
        );
        assert!(matches!(res, Err(ClientLibError::UrlOutsideRealm { .. })));
    }

    #[test]
    fn realm_check_rejects_unparseable_anchor_url() {
        // Host-only URL has no project path -> fail closed.
        let res = verify_remote_url_in_path_realm(
            "http/127.0.0.1/8080/acme/tool/releases/v1.0.0/asfaload.index.json",
            "http://127.0.0.1:8080",
        );
        match res {
            Err(ClientLibError::UrlOutsideRealm { project_id, .. }) => {
                assert_eq!(project_id, None);
            }
            Err(e) => panic!("Expected UrlOutsideRealm, got {e}"),
            Ok(_) => panic!("Expected UrlOutsideRealm error, got Ok"),
        }
    }

    #[test]
    fn realm_check_rejects_different_host() {
        let res = verify_remote_url_in_path_realm(
            "http/127.0.0.1/8080/acme/tool/releases/v1.0.0/asfaload.index.json",
            "http://evil.example.com/acme/tool/asfaload.signers/signers.json",
        );
        assert!(matches!(res, Err(ClientLibError::UrlOutsideRealm { .. })));
    }
}
