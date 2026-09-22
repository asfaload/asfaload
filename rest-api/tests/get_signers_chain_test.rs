use anyhow::Result;
use chrono::Utc;
use common::fs::names::{metadata_path_for, signatures_path_for};
use constants::{SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, SignaturesFile,
    TaggedSignature, sha512_for_content,
};
use rest_api::server::run_server;
use rest_api_test_helpers::{
    TestSetupBuilder, build_test_config, get_random_port, git_commit, init_git_repo,
    wait_for_server,
};
use rest_api_types::GetSignersChainResponse;
use signers_file_types::{
    Forge, ForgeOrigin, HistoryEntry, HistoryFile, SignersConfig, SignersConfigMetadata,
    VerifiedForgeContent,
};
use std::fs;
use tempfile::TempDir;

/// Test get_signers_chain for a signed artifact with no signers rotation.
/// The chain should contain exactly one entry: the active signers config.
#[tokio::test]
async fn test_get_signers_chain_no_history() -> Result<()> {
    let setup = TestSetupBuilder::new().build_and_sign().await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_artifact_signers_chain/{}",
            setup.port(),
            setup.artifact_path()
        ))
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 200,
        "Expected 200 OK, got {}. Body: {}",
        status, body_text
    );

    let body: GetSignersChainResponse = serde_json::from_str(&body_text)?;

    // With no history (no signers rotation), the chain should have exactly 1 entry:
    // the active signers config at signing time
    assert_eq!(
        body.chain.entries().len(),
        1,
        "Chain should have exactly 1 entry when no signers rotation occurred"
    );

    // Verify the entry contains a valid signers config
    let entry = &body.chain.entries()[0];
    let signers_config = entry
        .signers_config()
        .expect("Entry should contain valid signers config");
    // Our test setup uses 1-of-1 threshold
    assert_eq!(signers_config.version(), 1);

    Ok(())
}

/// Test get_signers_chain returns an error for a nonexistent artifact path.
#[tokio::test]
async fn test_get_signers_chain_nonexistent_artifact() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_artifact_signers_chain/nonexistent/file.bin",
            port
        ))
        .send()
        .await?;

    assert_ne!(
        response.status(),
        200,
        "Should fail for nonexistent artifact"
    );

    server_handle.abort();
    Ok(())
}

/// Test get_signers_chain returns an error for an artifact that exists but was never signed.
#[tokio::test]
async fn test_get_signers_chain_unsigned_artifact() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    // Create an artifact file but don't sign it
    let artifact_rel = "releases/unsigned.bin";
    let artifact_abs = repo_path.join(artifact_rel);
    fs::create_dir_all(artifact_abs.parent().unwrap())?;
    fs::write(&artifact_abs, "unsigned content")?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_artifact_signers_chain/{}",
            port, artifact_rel
        ))
        .send()
        .await?;

    assert_ne!(response.status(), 200, "Should fail for unsigned artifact");

    server_handle.abort();
    Ok(())
}

/// Test get_signers_chain blocks path traversal attempts.
#[tokio::test]
async fn test_get_signers_chain_path_traversal() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_artifact_signers_chain/../../../etc/passwd",
            port
        ))
        .send()
        .await?;

    assert_ne!(response.status(), 200, "Path traversal should be blocked");

    server_handle.abort();
    Ok(())
}

/// Test get_signers_chain for a signed artifact when the signers config has been rotated.
/// The chain should contain 2 entries: 1 historical + 1 active.
/// Additionally validates that a post-signing signers rotation does NOT affect the chain
/// returned for the artifact (the chain is pinned to the signing time).
#[tokio::test]
async fn test_get_signers_chain_with_history() -> Result<()> {
    // We use 3 keys: key 0 is the "old" signer (in history), key 1 is the "current" signer,
    // key 2 is used for a post-signing rotation.
    // First, build the history entry manually (test-specific, complex logic).
    let history_keys = test_helpers::TestKeys::new(1);
    let old_public_key = history_keys.pub_key(0).unwrap();
    let old_secret_key = history_keys.sec_key(0).unwrap();

    // Build the "old" signers config for the history entry
    let old_signers_config =
        SignersConfig::with_artifact_signers_only(1, (vec![old_public_key.clone()], 1))?;
    let old_signers_json = old_signers_config.to_json()?;
    let old_signers_hash = sha512_for_content(old_signers_json.as_bytes().to_vec())?;
    let old_signers_sig = old_secret_key.sign(&old_signers_hash)?;
    let mut old_signatures = SignaturesFile::new();
    old_signatures.entries.insert(
        old_public_key.to_base64(),
        TaggedSignature {
            format: old_public_key.key_format(),
            signature: old_signers_sig.to_base64(),
        },
    );
    let old_metadata = SignersConfigMetadata::from_forge(ForgeOrigin::new(
        Forge::Github,
        "https://example.com/old".to_string(),
        VerifiedForgeContent::new_for_test(
            "https://example.com/old".to_string(),
            "test_hash_placeholder".to_string(),
        ),
        Utc::now(),
    ));

    let (old_metadata_json, old_metadata_sigs) =
        test_helpers::history_helpers::sign_metadata(&old_metadata, &history_keys, &[0]).unwrap();

    // Create the history file with the old entry.
    // Use a time clearly in the past so the cutoff filter in signers_chain_for_artifact
    // always includes this entry (cutoff is the git commit time, which has second precision).
    let past_time = Utc::now() - chrono::Duration::hours(1);
    let mut history_file = HistoryFile::new();
    history_file.add_entry(HistoryEntry {
        obsoleted_at: past_time,
        signers_file: old_signers_json,
        signatures: old_signatures,
        metadata: old_metadata_json,
        metadata_signatures: old_metadata_sigs,
    });

    // Use the builder: 3 keys (all available via test_keys), threshold 1,
    // with the history file we just constructed.
    let setup = TestSetupBuilder::new()
        .with_keys(3)
        .with_threshold(1)
        .with_history(history_file)
        .build()
        .await?;

    // Submit signature from key 1 (the "current" signer) and wait for commit
    let body = setup.submit_signature_and_wait(1).await?;
    assert!(body.is_complete, "Signature collection should be complete");

    // --- Phase 1: First chain retrieval + validation ---
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_artifact_signers_chain/{}",
            setup.port(),
            setup.artifact_path()
        ))
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 200,
        "Expected 200 OK, got {}. Body: {}",
        status, body_text
    );

    let chain_before_rotation = body_text.clone();
    let body: GetSignersChainResponse = serde_json::from_str(&body_text)?;

    // Validate chain has 2 entries
    assert_eq!(
        body.chain.entries().len(),
        2,
        "Chain should have exactly 2 entries (1 historical + 1 active)"
    );

    // First entry: the old signers config (key 0)
    let historical_entry = &body.chain.entries()[0];
    let historical_config = historical_entry
        .signers_config()
        .expect("Historical entry should contain valid signers config");
    let old_key_base64 = old_public_key.to_base64();
    assert!(
        historical_config
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == old_key_base64),
        "Historical entry should contain the old public key"
    );

    // Second entry: the current/active signers config (should contain key 1)
    let active_entry = &body.chain.entries()[1];
    let active_config = active_entry
        .signers_config()
        .expect("Active entry should contain valid signers config");
    let current_public_key = setup.test_keys().pub_key(1).unwrap();
    let current_key_base64 = current_public_key.to_base64();
    assert!(
        active_config
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == current_key_base64),
        "Active entry should contain the current public key"
    );

    // --- Phase 2: Simulate a post-signing signers rotation ---
    let repo_path = setup.repo_path();
    let signers_dir = repo_path.join(SIGNERS_DIR);

    // Use a separate key (not part of the builder's config) for post-rotation,
    // so we can assert it does NOT appear in the signing-time chain.
    let rotation_keys = test_helpers::TestKeys::new_from(3, 1);
    let new_public_key = rotation_keys.pub_key(0).unwrap();
    let new_secret_key = rotation_keys.sec_key(0).unwrap();
    let new_signers_config =
        SignersConfig::with_artifact_signers_only(1, (vec![new_public_key.clone()], 1))?;

    // Read the current signers config (the builder's active config) to move it into history
    let current_signers_json = fs::read_to_string(signers_dir.join(SIGNERS_FILE))?;
    let current_signers_content = fs::read(signers_dir.join(SIGNERS_FILE))?;
    let current_signers_hash = sha512_for_content(current_signers_content)?;
    let current_signers_sig = setup
        .test_keys()
        .sec_key(0)
        .unwrap()
        .sign(&current_signers_hash)?;
    let mut current_signatures = SignaturesFile::new();
    let first_pub_key = setup.test_keys().pub_key(0).unwrap();
    current_signatures.entries.insert(
        first_pub_key.to_base64(),
        TaggedSignature {
            format: first_pub_key.key_format(),
            signature: current_signers_sig.to_base64(),
        },
    );
    let metadata = test_helpers::test_metadata();

    let (metadata_json, metadata_sigs) =
        test_helpers::history_helpers::sign_metadata(&metadata, setup.test_keys(), &[0]).unwrap();

    let rotation_time = Utc::now();
    let history_file_path = repo_path.join(SIGNERS_HISTORY_FILE);
    let mut updated_history = HistoryFile::load_from_file(&history_file_path)?;
    updated_history.add_entry(HistoryEntry {
        obsoleted_at: rotation_time,
        signers_file: current_signers_json,
        signatures: current_signatures,
        metadata: metadata_json,
        metadata_signatures: metadata_sigs,
    });
    updated_history.save_to_file(&history_file_path)?;

    // Write the new signers config
    fs::write(
        signers_dir.join(SIGNERS_FILE),
        new_signers_config.to_json()?,
    )?;

    // Create signatures for new signers config
    let new_signers_content = fs::read(signers_dir.join(SIGNERS_FILE))?;
    let new_signers_hash = sha512_for_content(new_signers_content)?;
    let new_signers_sig = new_secret_key.sign(&new_signers_hash)?;
    let mut new_signatures = SignaturesFile::new();
    new_signatures.entries.insert(
        new_public_key.to_base64(),
        TaggedSignature {
            format: new_public_key.key_format(),
            signature: new_signers_sig.to_base64(),
        },
    );
    let signers_file_path = signers_dir.join(SIGNERS_FILE);
    let signers_sig_path = signatures_path_for(&signers_file_path)?;
    fs::write(&signers_sig_path, serde_json::to_string(&new_signatures)?)?;

    // Update metadata
    let new_metadata = test_helpers::test_metadata();
    let metadata_path = metadata_path_for(&signers_file_path)?;
    fs::write(&metadata_path, serde_json::to_string_pretty(&new_metadata)?)?;

    // Commit the rotation
    git_commit(
        repo_path,
        &[SIGNERS_DIR, SIGNERS_HISTORY_FILE],
        "signers rotation: key 1 -> key 2",
    )?;

    // --- Phase 3: Verify the chain is unchanged after post-signing rotation ---
    let response_after = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_artifact_signers_chain/{}",
            setup.port(),
            setup.artifact_path()
        ))
        .send()
        .await?;

    let status_after = response_after.status();
    let body_text_after = response_after.text().await?;
    assert_eq!(
        status_after, 200,
        "Expected 200 OK after rotation, got {}. Body: {}",
        status_after, body_text_after
    );

    let body_after: GetSignersChainResponse = serde_json::from_str(&body_text_after)?;

    // Chain should STILL have exactly 2 entries -- the post-signing rotation must NOT appear
    assert_eq!(
        body_after.chain.entries().len(),
        2,
        "Chain should still have 2 entries after post-signing rotation (rotation should be excluded)"
    );

    // First entry should still be the old config (key 0)
    let historical_after = &body_after.chain.entries()[0];
    let historical_config_after = historical_after
        .signers_config()
        .expect("Historical entry should still be valid after rotation");
    assert!(
        historical_config_after
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == old_key_base64),
        "Historical entry should still contain the old public key (key 0) after rotation"
    );

    // Second entry should still be the pre-rotation active config (key 1), NOT key 2 only
    let active_after = &body_after.chain.entries()[1];
    let active_config_after = active_after
        .signers_config()
        .expect("Active entry should still be valid after rotation");
    assert!(
        active_config_after
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == current_key_base64),
        "Active entry should still contain key 1 (not the post-rotation key 2)"
    );
    let new_key_base64 = new_public_key.to_base64();
    assert!(
        !active_config_after
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == new_key_base64),
        "Post-rotation key 2 should NOT appear in the chain"
    );

    // Also verify the serialized chain is byte-identical before and after rotation
    assert_eq!(
        chain_before_rotation, body_text_after,
        "Chain JSON should be byte-identical before and after post-signing rotation"
    );

    Ok(())
}
