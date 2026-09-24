use crate::{AsfaloadLibResult, ClientLibError, signers_metadata::verify_remote_url_in_path_realm};
use features_lib::{SignersChain, SignersConfig, SignersInfoTrait};
use rest_api_types::GetSignersChainResponse;

/// Result of a successful signers chain validation.
#[derive(Debug)]
pub struct SignersChainResult {
    /// Number of entries in the validated chain.
    pub entries_count: usize,
    /// Current signers config extracted from the validated chain so it can be used immediately by
    /// downloading code.
    pub current_signers_config: SignersConfig,
}

/// Fetch the signers chain for a signed artifact from the backend.
///
/// Makes an unauthenticated GET request to `/v1/get_artifact_signers_chain/{artifact_path}`.
async fn get_artifact_signers_chain(
    client: &reqwest::Client,
    backend_url: &str,
    artifact_path: &str,
) -> AsfaloadLibResult<GetSignersChainResponse> {
    let url = format!(
        "{}/v1/get_artifact_signers_chain/{}",
        backend_url, artifact_path
    );
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ClientLibError::SignersChainFetchError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "(failed to read response body)".to_string());
        return Err(ClientLibError::SignersChainFetchError(format!(
            "{}: {}",
            status, body
        )));
    }

    response
        .json::<GetSignersChainResponse>()
        .await
        .map_err(|e| ClientLibError::SignersChainFetchError(e.to_string()))
}

/// Cryptographic + realm + trust-anchor validation of an already-fetched
/// chain. Both `verify_signers_chain` (which fetches first) and the download
/// flow (which gets the chain bundled in the artifact-info response) feed
/// their chain through this function. Returns the chain-head signers config.
pub(crate) async fn validate_fetched_chain(
    chain: SignersChain,
    artifact_path: &str,
) -> AsfaloadLibResult<SignersChainResult> {
    let http_client = reqwest::Client::new();

    if chain.entries().is_empty() {
        return Err(ClientLibError::SignersChainEmpty);
    }

    // Cryptographic validation of the entire chain (incl. first-entry all-signers).
    if let Err(e) = features_lib::validate_chain(&chain) {
        return Err(ClientLibError::SignersChainFirstEntryInvalid(format!(
            "signers chain validation failed: {e}"
        )));
    }

    // Trust-anchor check: first entry's forge content must match.
    let first = chain
        .first_entry()
        .ok_or(ClientLibError::SignersChainFirstEntryMismatch)?;

    // Realm binding: the anchor must be served from within the download's
    // origin. Checked before the content fetch so we never contact an
    // out-of-realm host.
    let retrieval_url = {
        let metadata = first
            .metadata()
            .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;
        match metadata.origin() {
            features_lib::SignersConfigOrigin::Forge(forge) => forge.retrieval_url().to_string(),
        }
    };
    assert_anchor_within_realm(artifact_path, &retrieval_url)?;

    validate_trust_anchor(&http_client, &first).await?;

    // The chain-head config is the trust-rooted active signers set.
    let current_signers_config = chain
        .current_signers_info()
        .ok_or(ClientLibError::SignersChainEmpty)?
        .signers_config()
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    Ok(SignersChainResult {
        entries_count: chain.entries().len(),
        current_signers_config,
    })
}

/// Validate the signers chain for a signed artifact.
///
/// Fetches the chain from the backend API, then runs the cryptographic,
/// realm, and trust-anchor validation via `validate_fetched_chain`.
pub async fn verify_signers_chain(
    backend_url: &str,
    artifact_path: &str,
) -> AsfaloadLibResult<SignersChainResult> {
    let http_client = reqwest::Client::new();
    let chain_response =
        get_artifact_signers_chain(&http_client, backend_url, artifact_path).await?;
    validate_fetched_chain(chain_response.chain, artifact_path).await
}

/// Assert that the trust anchor's fetched URL falls within the download's realm.
fn assert_anchor_within_realm(artifact_path: &str, retrieval_url: &str) -> AsfaloadLibResult<()> {
    match verify_remote_url_in_path_realm(artifact_path, retrieval_url) {
        Err(ClientLibError::UrlOutsideRealm {
            path,
            url,
            project_id,
        }) => Err(ClientLibError::SignersChainTrustAnchorOutsideRealm {
            artifact_path: path,
            anchor_realm: project_id.unwrap_or(url),
        }),
        other => other,
    }
}

/// Validate that a history entry's signers_file matches the content
/// served by the forge URL recorded in its metadata.
///
/// Signature validity is assumed to have already been checked by
/// `validate_chain`. This function only performs the forge fetch and
/// content comparison.
pub(crate) async fn validate_trust_anchor(
    client: &reqwest::Client,
    entry: &features_lib::SignersChainEntry,
) -> AsfaloadLibResult<()> {
    let metadata = entry
        .metadata()
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    let forge_url = match metadata.origin() {
        features_lib::SignersConfigOrigin::Forge(forge) => forge.retrieval_url(),
    };

    let response = client
        .get(forge_url)
        .send()
        .await
        .map_err(|e| ClientLibError::SignersChainForgeFetchError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(ClientLibError::SignersChainForgeFetchError(format!(
            "HTTP {}",
            response.status()
        )));
    }

    let forge_content = response
        .text()
        .await
        .map_err(|e| ClientLibError::SignersChainForgeFetchError(e.to_string()))?;

    if forge_content != entry.signers_file() {
        return Err(ClientLibError::SignersChainFirstEntryMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use features_lib::SignersConfig;
    use test_helpers::TestKeys;
    use test_helpers::history_helpers::make_history_entry;

    #[tokio::test]
    async fn verify_signers_chain_returns_error_when_api_unreachable() {
        // Use a port that nothing listens on
        let result = verify_signers_chain("http://127.0.0.1:1", "some/path").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::SignersChainFetchError(_) => {}
            other => panic!("Expected SignersChainFetchError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn verify_signers_chain_returns_error_on_empty_chain() {
        let mut server = mockito::Server::new_async().await;
        let response_body = GetSignersChainResponse {
            chain: features_lib::SignersChain::default(),
        };

        let _mock = server
            .mock("GET", "/v1/get_artifact_signers_chain/test/path")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&response_body).unwrap())
            .create_async()
            .await;

        let result = verify_signers_chain(&server.url(), "test/path").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::SignersChainEmpty => {}
            other => panic!("Expected SignersChainEmpty, got: {:?}", other),
        }
    }

    // -- Tests for validate_trust_anchor --

    #[tokio::test]
    async fn validate_trust_anchor_passes_when_forge_content_matches() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body(entry.signers_file.clone())
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_returns_500() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(500)
            .with_body("server error")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainForgeFetchError(_))
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_returns_404() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(404)
            .with_body("not found")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainForgeFetchError(_))
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_content_differs() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body("completely different content")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainFirstEntryMismatch)
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_whitespace_diff() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let body = format!("{}\n", entry.signers_file);
        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainFirstEntryMismatch)
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_unreachable() {
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry =
            make_history_entry(&config, &keys, &[0], "http://127.0.0.1:1", timestamp).unwrap();

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainForgeFetchError(_))
        ));
    }

    // -- Trust anchor must lie within the download's realm --

    // Scenario: a user downloads an artifact published on github.com/acme/tool.
    // A compromised asfaload backend answers the signers-chain request with a
    // chain that is internally flawless — self-signed, passes `validate_chain`,
    // and its genesis trust anchor matches the content served by the anchor
    // host. The single defect is that the genesis trust anchor is hosted on a
    // server with nothing to do with github.com/acme/tool, i.e. it lies OUTSIDE
    // the realm of the URL being downloaded. A correct client must reject it.
    //
    // Three distinct actors:
    //   - github_artifact_path : where the user downloads from (defines the realm)
    //   - asfaload_backend     : serves the (malicious) signers chain (so supposed breached)
    //   - attacker_anchor_host : serves the genesis trust anchor, at an origin
    //                            unrelated to github_artifact_path
    #[tokio::test]
    async fn verify_signers_chain_rejects_trust_anchor_outside_download_origin() {
        // The artifact the user asked for lives on github.com/acme/tool; this is
        // the realm the trust anchor is required to fall within.
        let github_artifact_path =
            "https/github.com/443/acme/tool/releases/tag/v1.0.0/asfaload.index.json";

        let mut asfaload_backend = mockito::Server::new_async().await;
        let mut attacker_anchor_host = mockito::Server::new_async().await;

        // Build a genesis entry whose recorded trust-anchor URL is the
        // attacker_anchor_host — deliberately NOT the github origin above.
        let signer_keys = TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![signer_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let genesis_entry = make_history_entry(
            &signers_config,
            &signer_keys,
            &[0],
            &attacker_anchor_host.url(),
            timestamp,
        )
        .unwrap();

        // Wrap the genesis entry into a single-entry chain (it is the current info).
        let current_info = features_lib::CurrentSignersInfo {
            signers_file: genesis_entry.signers_file.clone(),
            signatures: genesis_entry.signatures.clone(),
            metadata: genesis_entry.metadata.clone(),
            metadata_signatures: genesis_entry.metadata_signatures.clone(),
        };
        let mut signers_chain = features_lib::SignersChain::default();
        signers_chain.set_current_info(current_info);

        // The attacker's anchor host serves content matching the chain's signers file, so
        // the content comparison inside validate_trust_anchor passes — meaning
        // the rejection must come from the realm check, not a content mismatch.
        // The mock implements Drop and is torn down at end of test.
        let _attacker_anchor_mock = attacker_anchor_host
            .mock("GET", "/")
            .with_status(200)
            .with_body(genesis_entry.signers_file.clone())
            .create_async()
            .await;

        // The compromised backend returns the malicious chain for the github path.
        let chain_response = GetSignersChainResponse {
            chain: signers_chain,
        };
        let _backend_chain_mock = asfaload_backend
            .mock(
                "GET",
                format!("/v1/get_artifact_signers_chain/{}", github_artifact_path).as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&chain_response).unwrap())
            .create_async()
            .await;

        // If we look only at the data served by the (breached) asfaload backend, everything looks
        // fine: signers file activated, index file signed according to signers file, trust anchor
        // available and correct. BUT: the trust anchor is outside of the download url's realm. So
        // it must be rejected.
        let result = verify_signers_chain(&asfaload_backend.url(), github_artifact_path).await;

        assert!(
            result.is_err(),
            "trust anchor outside the download origin must be rejected, but verification succeeded: {:?}",
            result
        );
    }

    // Mirror of the rejection test, but the trust anchor is served from a URL
    // INSIDE the download's realm (same origin + acme/tool project). A correct
    // client must accept it: realm check passes and content matches.
    #[tokio::test]
    async fn verify_signers_chain_accepts_trust_anchor_inside_download_origin() {
        let mut backend = mockito::Server::new_async().await;

        let signer_keys = TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![signer_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();

        // Anchor lives under acme/tool on the SAME origin as the download.
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let genesis_entry =
            make_history_entry(&signers_config, &signer_keys, &[0], &anchor_url, timestamp)
                .unwrap();

        let current_info = features_lib::CurrentSignersInfo {
            signers_file: genesis_entry.signers_file.clone(),
            signatures: genesis_entry.signatures.clone(),
            metadata: genesis_entry.metadata.clone(),
            metadata_signatures: genesis_entry.metadata_signatures.clone(),
        };
        let mut signers_chain = features_lib::SignersChain::default();
        signers_chain.set_current_info(current_info);

        // The anchor host serves content matching the signers file.
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(genesis_entry.signers_file.clone())
            .create_async()
            .await;

        // Build an artifact path inside the same origin/realm (acme/tool).
        let parsed = url::Url::parse(&backend.url()).unwrap();
        let artifact_path = format!(
            "http/{}/{}/acme/tool/releases/v1.0.0/asfaload.index.json",
            parsed.host_str().unwrap(),
            parsed.port().unwrap(),
        );

        let chain_response = GetSignersChainResponse {
            chain: signers_chain,
        };
        let _chain_mock = backend
            .mock(
                "GET",
                format!("/v1/get_artifact_signers_chain/{}", artifact_path).as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&chain_response).unwrap())
            .create_async()
            .await;

        let result = verify_signers_chain(&backend.url(), &artifact_path).await;
        assert!(
            result.is_ok(),
            "in-realm trust anchor must be accepted: {:?}",
            result
        );
    }
}
