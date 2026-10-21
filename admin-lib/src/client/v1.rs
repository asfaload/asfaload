use std::collections::HashMap;

use crate::auth::create_auth_headers;
use crate::error::{AdminLibError, AdminLibResult};
use common::{base64_for_string, sha512_for_content};
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatureTrait,
    AsfaloadSignatures,
};
use forge_release::checksums::index_from_shasums_urls;
use forge_release::common::ReleaseFetcher;
#[cfg(not(feature = "test-utils"))]
use forge_release::github::GithubReleaseFetcher;
#[cfg(feature = "test-utils")]
use forge_release::github::test_utils::MockGithubReleaseFetcher;
use reqwest::header::CONTENT_TYPE;
use rest_api_types::models::{
    ChecksumFilesPayload, ClientPendingFile, GithubReleasePayload, UpdateRepoSignersRequest,
    UpdateRepoSignersResponse,
};
use rest_api_types::{
    FilesToSignResponse, GetSignatureStatusResponse, ListPendingResponse, PingResponse,
    RegisterAssetsPayload, RegisterRepoRequest, RegisterRepoResponse, RevokeFileRequest,
    RevokeFileResponse, SubmitSignatureRequest, SubmitSignatureResponse,
};
use serde::de::DeserializeOwned;

/// A client for interacting with the v1 REST API.
///
/// Holds a single `reqwest::Client` for connection pooling and reuse
/// across multiple endpoint calls.
pub struct Client {
    client: reqwest::Client,
    base_url: String,
}

/// Registration mode for the register-assets command.
pub enum RegistrationMode {
    GithubRelease { url: String },
    ChecksumFiles { urls: Vec<String> },
}

// The fetcher type depends on the build mode: the real fetcher in
// production, one returning a fixed response when building tests.
#[cfg(not(feature = "test-utils"))]
fn create_github_fetcher() -> GithubReleaseFetcher {
    GithubReleaseFetcher::new(None)
}

#[cfg(feature = "test-utils")]
fn create_github_fetcher() -> MockGithubReleaseFetcher {
    MockGithubReleaseFetcher::new()
}

/// Build the payload for registering assets, for the given registration mode.
///
/// Downloads and indexes the release content (a GitHub release or shasums
/// files), signs the index with the secret key, and encodes both index and
/// signature in base64, with the same conventions the server expects when
/// handling the payload.
async fn build_register_assets_payload(
    mode: &RegistrationMode,
    secret_key: &AsfaloadSecretKeys,
) -> AdminLibResult<RegisterAssetsPayload> {
    match mode {
        RegistrationMode::GithubRelease { url } => {
            let fetcher = create_github_fetcher();
            let release = fetcher.fetch(&[url.as_str()]).await?;
            let index = release.generate_index_json()?;
            let hash = sha512_for_content(index.as_bytes())?;
            let signature = secret_key.sign(&hash)?;
            Ok(RegisterAssetsPayload::GithubRelease(GithubReleasePayload {
                github_release_url: url.clone(),
                index: base64_for_string(index),
                signature: signature.to_base64(),
            }))
        }
        RegistrationMode::ChecksumFiles { urls } => {
            let client = reqwest::Client::new();
            let index = index_from_shasums_urls(&client, urls).await?;
            let json = index.to_json()?;
            let hash = sha512_for_content(json.as_bytes())?;
            let signature = secret_key.sign(&hash)?.to_base64();
            Ok(RegisterAssetsPayload::ChecksumFiles(ChecksumFilesPayload {
                csum_files: urls.clone(),
                index: base64_for_string(json),
                signature,
            }))
        }
    }
}

impl Client {
    /// Create a new REST client.
    pub fn new(base_url: impl Into<String>) -> Self {
        Client {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Check response status. On failure, read error body and return `RequestFailed`.
    async fn check_response_status(
        response: reqwest::Response,
    ) -> AdminLibResult<reqwest::Response> {
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "(failed to read response body)".to_string());
            return Err(AdminLibError::RequestFailed(format!(
                "{}: {}",
                status, error_text
            )));
        }
        Ok(response)
    }

    /// Parse JSON response body into a typed value.
    async fn parse_json_response<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> AdminLibResult<T> {
        // Do it in two steps so we can return both a reqwest error
        // and a serde_json error. It is possible to do it in one step
        // (let r = response.json::<T>().await?;) but in that case
        // we always return a reqwest error.
        let text = response.text().await?;
        let r = serde_json::from_str::<T>(&text)?;
        Ok(r)
    }

    /// List pending signature files from the backend.
    ///
    /// Makes an authenticated GET request to `/v1/pending_signatures`.
    pub async fn get_pending_signatures(
        &self,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<ListPendingResponse> {
        let url = format!("{}/v1/pending_signatures", self.base_url);
        let headers = create_auth_headers("", secret_key)?;

        let response = self.client.get(&url).headers(headers).send().await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Ping the backend, optionally authenticating the request.
    ///
    /// Makes a GET request to `/v1/ping`. When a secret key is given, the
    /// request carries authentication headers; the server reports in the
    /// response whether their validation succeeded (it answers 200 even on
    /// failed authentication).
    pub async fn ping(
        &self,
        secret_key: Option<&AsfaloadSecretKeys>,
    ) -> AdminLibResult<PingResponse> {
        let url = format!("{}/v1/ping", self.base_url);

        let mut request = self.client.get(&url);
        if let Some(key) = secret_key {
            let headers = create_auth_headers("", key)?;
            request = request.headers(headers);
        }

        let response = request.send().await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Get signature collection status for a specific file.
    ///
    /// Makes an authenticated GET request to `/v1/signatures/{file_path}`.
    /// The caller must be an authorized signer for the file.
    pub async fn get_signature_status(
        &self,
        file_path: &str,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<GetSignatureStatusResponse> {
        let url = format!("{}/v1/signatures/{}", self.base_url, file_path);
        let headers = create_auth_headers("", secret_key)?;

        let response = self.client.get(&url).headers(headers).send().await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Fetch file content from the backend.
    ///
    /// Makes an unauthenticated GET request to `/v1/files/{file_path}`.
    pub async fn fetch_file(&self, file_path: &str) -> AdminLibResult<Vec<u8>> {
        let url = format!("{}/v1/files/{}", self.base_url, file_path);

        let response = self.client.get(&url).send().await?;

        let response = Self::check_response_status(response).await?;

        let content = response.bytes().await?;

        Ok(content.to_vec())
    }

    /// Fetch all files that need signing for a given file path.
    ///
    /// Makes an authenticated GET request to `/v1/files-to-sign/{file_path}`.
    /// Returns a map of file paths to their raw content bytes.
    pub async fn fetch_files_to_sign(
        &self,
        file_path: &str,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<HashMap<String, Vec<u8>>> {
        use base64::Engine;

        let url = format!("{}/v1/files-to-sign/{}", self.base_url, file_path);
        let headers = create_auth_headers("", secret_key)?;
        let response = self.client.get(&url).headers(headers).send().await?;
        let response = Self::check_response_status(response).await?;

        let files_response: FilesToSignResponse = Self::parse_json_response(response).await?;

        let mut result = HashMap::new();
        for (path, b64_content) in files_response.files {
            let content = base64::engine::general_purpose::STANDARD
                .decode(&b64_content)
                .map_err(|e| {
                    AdminLibError::InvalidInput(format!("Failed to decode file content: {}", e))
                })?;
            result.insert(path, content);
        }
        Ok(result)
    }

    /// Submit signatures for a file to the backend.
    ///
    /// Makes an authenticated POST request to `/v1/signatures`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn submit_signatures(
        &self,
        pending_file: ClientPendingFile,
        public_key: &AsfaloadPublicKeys,
        signatures: &HashMap<String, AsfaloadSignatures>,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<SubmitSignatureResponse> {
        let url = format!("{}/v1/signatures", self.base_url);

        let sig_map: HashMap<String, String> = signatures
            .iter()
            .map(|(path, sig)| (path.clone(), sig.to_base64()))
            .collect();

        let request = SubmitSignatureRequest {
            pending_file,
            public_key: public_key.to_base64(),
            signatures: sig_map,
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Register assets with the backend.
    ///
    /// Makes an authenticated POST request to `/v1/assets`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn register_assets(
        &self,
        mode: &RegistrationMode,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<rest_api_types::RegisterAssetsResponse> {
        let url = format!("{}/v1/assets", self.base_url);

        let payload = build_register_assets_payload(mode, secret_key).await?;

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&payload)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Register a repository with the backend.
    ///
    /// Makes an authenticated POST request to `/v1/register_repo`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn register_repo(
        &self,
        signers_file_url: &str,
        public_key: &AsfaloadPublicKeys,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<RegisterRepoResponse> {
        let url = format!("{}/v1/register_repo", self.base_url);

        let request = RegisterRepoRequest {
            signers_file_url: signers_file_url.to_string(),
            public_key: public_key.to_base64(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Propose a signers file update to the backend.
    ///
    /// Makes an authenticated POST request to `/v1/update_signers`.
    pub async fn update_signers(
        &self,
        signers_file_url: &str,
        public_key: &AsfaloadPublicKeys,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<UpdateRepoSignersResponse> {
        let url = format!("{}/v1/update_signers", self.base_url);

        let request = UpdateRepoSignersRequest {
            signers_file_url: signers_file_url.to_string(),
            public_key: public_key.to_base64(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Revoke a signed file on the backend.
    ///
    /// Makes an authenticated POST request to `/v1/revoke`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn revoke_file(
        &self,
        file_path: &str,
        revocation_json: &str,
        signature: &AsfaloadSignatures,
        public_key: &AsfaloadPublicKeys,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<RevokeFileResponse> {
        let url = format!("{}/v1/revoke", self.base_url);

        let request = RevokeFileRequest {
            file_path: file_path.to_string(),
            revocation_json: revocation_json.to_string(),
            signature: signature.to_base64(),
            public_key: public_key.to_base64(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Fetch content from an external URL.
    ///
    /// Uses `common::http::fetch_with_retry` for resilient fetching with
    /// retry-on-429. Returns text as bytes to match the server's content
    /// handling, ensuring consistent hash computation (avoids BOM/encoding
    /// mismatches).
    pub async fn fetch_external_url(&self, url: &str) -> AdminLibResult<Vec<u8>> {
        let content = common::http::fetch_with_retry(url)
            .await
            .map_err(|e| AdminLibError::RequestFailed(e.to_string()))?;

        Ok(content.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_response_status_passes_through_on_success() {
        let response = http::Response::builder().status(200).body("ok").unwrap();
        let reqwest_response = reqwest::Response::from(response);

        let result = Client::check_response_status(reqwest_response).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_response_status_returns_error_on_4xx() {
        let response = http::Response::builder()
            .status(404)
            .body("Not Found")
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        let result = Client::check_response_status(reqwest_response).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            AdminLibError::RequestFailed(msg) => {
                assert!(msg.contains("404"), "Error should contain status code");
                assert!(msg.contains("Not Found"), "Error should contain body text");
            }
            other => panic!("Expected RequestFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_response_status_returns_error_on_5xx() {
        let response = http::Response::builder()
            .status(500)
            .body("Internal Server Error")
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        let result = Client::check_response_status(reqwest_response).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            AdminLibError::RequestFailed(msg) => {
                assert!(msg.contains("500"));
                assert!(msg.contains("Internal Server Error"));
            }
            other => panic!("Expected RequestFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn parse_json_response_deserializes_valid_json() {
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(r#"{"value": 42}"#)
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct TestPayload {
            value: u32,
        }

        let result: AdminLibResult<TestPayload> =
            Client::parse_json_response(reqwest_response).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TestPayload { value: 42 });
    }

    #[tokio::test]
    async fn fetch_external_url_returns_body_bytes() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/test-file.json")
            .with_status(200)
            .with_body(b"hello world")
            .create_async()
            .await;

        let client = Client::new(server.url());
        let result = client
            .fetch_external_url(&format!("{}/test-file.json", server.url()))
            .await;

        mock.assert_async().await;
        let bytes = result.unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[tokio::test]
    async fn fetch_external_url_returns_error_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/missing")
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = Client::new(server.url());
        let result = client
            .fetch_external_url(&format!("{}/missing", server.url()))
            .await;

        mock.assert_async().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AdminLibError::RequestFailed(msg) => {
                assert!(msg.contains("404"));
            }
            other => panic!("Expected RequestFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn parse_json_response_returns_error_on_invalid_json() {
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body("not valid json")
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        #[derive(serde::Deserialize, Debug)]
        struct TestPayload {
            #[allow(dead_code)]
            value: u32,
        }

        let result: AdminLibResult<TestPayload> =
            Client::parse_json_response(reqwest_response).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            AdminLibError::JsonError(_) => {}
            other => panic!("Expected JsonError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ping_unauthenticated_sends_no_auth_headers() {
        use rest_api_types::PingAuthStatus;

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/ping")
            .match_header(rest_api_auth::HEADER_PUBLIC_KEY, mockito::Matcher::Missing)
            .match_header(rest_api_auth::HEADER_TIMESTAMP, mockito::Matcher::Missing)
            .match_header(rest_api_auth::HEADER_NONCE, mockito::Matcher::Missing)
            .match_header(rest_api_auth::HEADER_SIGNATURE, mockito::Matcher::Missing)
            .with_status(200)
            .with_body(r#"{"message":"pong","auth":{"status":"unauthenticated"}}"#)
            .create_async()
            .await;

        let client = Client::new(server.url());
        let response = client.ping(None).await.unwrap();

        mock.assert_async().await;
        assert_eq!(response.message, "pong");
        assert_eq!(response.auth, PingAuthStatus::Unauthenticated);
    }

    #[tokio::test]
    async fn ping_authenticated_sends_auth_headers() {
        use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
        use rest_api_types::PingAuthStatus;

        let key_pair = AsfaloadKeyPairs::new("test_password").unwrap();
        let secret_key = key_pair.secret_key("test_password").unwrap();

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/ping")
            .match_header(rest_api_auth::HEADER_TIMESTAMP, mockito::Matcher::Any)
            .match_header(rest_api_auth::HEADER_NONCE, mockito::Matcher::Any)
            .match_header(rest_api_auth::HEADER_SIGNATURE, mockito::Matcher::Any)
            .match_header(rest_api_auth::HEADER_PUBLIC_KEY, mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"message":"pong","auth":{"status":"success","public_key":"base64pk"}}"#)
            .create_async()
            .await;

        let client = Client::new(server.url());
        let response = client.ping(Some(&secret_key)).await.unwrap();

        mock.assert_async().await;
        assert_eq!(response.message, "pong");
        assert_eq!(
            response.auth,
            PingAuthStatus::Success {
                public_key: "base64pk".to_string()
            }
        );
    }

    /// A checksums registration payload must survive the round trip the
    /// server applies in `VerifiedClientData::new`: it base64-decodes the
    /// index it received, recomputes the sha512 of the decoded bytes, and
    /// verifies the signature against that digest.
    #[tokio::test]
    async fn checksum_files_payload_round_trips_and_verifies_server_side() {
        use common::string_from_base64;
        use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};

        let key_pair = AsfaloadKeyPairs::new("test_password").unwrap();
        let secret_key = key_pair.secret_key("test_password").unwrap();

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/SHA256SUMS")
            .with_status(200)
            .with_body(
                "1111111111111111111111111111111111111111111111111111111111111111  app.tar.gz\n",
            )
            .create_async()
            .await;

        let urls = vec![format!("{}/SHA256SUMS", server.url())];
        let payload = build_register_assets_payload(
            &RegistrationMode::ChecksumFiles { urls: urls.clone() },
            &secret_key,
        )
        .await
        .unwrap();

        mock.assert_async().await;

        let RegisterAssetsPayload::ChecksumFiles(ChecksumFilesPayload {
            csum_files,
            index,
            signature,
        }) = payload
        else {
            panic!("expected a ChecksumFiles payload, got: {payload:?}");
        };
        assert_eq!(csum_files, urls, "the shasums urls must be sent as sent");

        // Decode the index the way the server does (`string_from_base64`).
        // An unencoded JSON body fails here, as it starts with '{'.
        let decoded_index = string_from_base64(&index)
            .unwrap_or_else(|e| panic!("server could not decode the index: {e}"));
        let hash = sha512_for_content(decoded_index.as_bytes()).expect("index is not empty");

        // Parse the key and the signature the way the server does.
        let pub_key = AsfaloadPublicKeys::from_base64(&key_pair.public_key().to_base64())
            .expect("public key should parse");
        let signature =
            AsfaloadSignatures::from_base64(&signature).expect("signature should parse");

        pub_key
            .verify(&signature, &hash)
            .expect("signature must verify against the decoded index bytes");
    }
}
