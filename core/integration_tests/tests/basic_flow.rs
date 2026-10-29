use anyhow::Result;
use common::SignedFileLoader;
use common::fs::names::metadata_path_for;
use common::sha512_for_file;
use features_lib::SignatureWithState;
use features_lib::SignedFileWithKindTrait;
use features_lib::constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE};
use features_lib::sign_signers_and_metadata_file;
use signatures::keys::AsfaloadSecretKeyTrait;
use signers_file::initialize_signers_file;
use signers_file_types::{SignersConfig, SignersConfigMetadata};
use std::fs;
use tempfile::TempDir;
use test_helpers::TestKeys;
use test_helpers::test_metadata;

#[test]
fn basic_flow() -> Result<()> {
    // Create a temporary directory for our test
    let temp_dir = TempDir::new()?;
    let root_dir = temp_dir.path();

    // Load pre-generated keys for two users
    let test_keys = TestKeys::new(2);
    let user1_pk = test_keys.pub_key(0).unwrap();
    let user1_sk = test_keys.sec_key(0).unwrap();
    let user2_pk = test_keys.pub_key(1).unwrap();
    let user2_sk = test_keys.sec_key(1).unwrap();

    // We create scopes for each operation taking place, to ensure each
    // user has access to the data it needs.

    // User1 initialises the signers file (no signature at init)
    {
        let signers_content = SignersConfig::with_artifact_signers_only(
            1,
            (vec![user1_pk.clone(), user2_pk.clone()], 2),
        )
        .expect("Could not build signers config")
        .to_json()
        .expect("Could not serialise SignersConfig to json");

        initialize_signers_file(
            root_dir,
            &signers_content,
            &common::to_posix_json(&test_metadata())?,
            user1_pk,
        )?;
    }

    // Verify files exist after init
    let pending_signers_path = root_dir.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
    assert!(pending_signers_path.exists());
    let pending_metadata = metadata_path_for(&pending_signers_path)?;
    assert!(
        pending_metadata.exists(),
        "metadata should exist after init"
    );

    // User1 signs both files
    {
        let signers_hash = sha512_for_file(&pending_signers_path)?;
        let sig1 = user1_sk.sign(&signers_hash)?;
        let metadata_hash = sha512_for_file(&pending_metadata)?;
        let meta_sig1 = user1_sk.sign(&metadata_hash)?;
        sign_signers_and_metadata_file(&pending_signers_path, &sig1, user1_pk, &meta_sig1)?;
    }

    // User2 signs both files — this completes the aggregate signature and activates
    {
        let signers_hash = sha512_for_file(&pending_signers_path)?;
        let sig2 = user2_sk.sign(&signers_hash)?;
        let metadata_hash = sha512_for_file(&pending_metadata)?;
        let meta_sig2 = user2_sk.sign(&metadata_hash)?;
        sign_signers_and_metadata_file(&pending_signers_path, &sig2, user2_pk, &meta_sig2)?;
    }

    // Verify activation moved both files
    assert!(
        !pending_metadata.exists(),
        "pending metadata should not exist after activation"
    );
    let active_metadata = metadata_path_for(root_dir.join(SIGNERS_DIR).join(SIGNERS_FILE)).unwrap();
    assert!(
        active_metadata.exists(),
        "metadata should exist in active dir"
    );
    let _: SignersConfigMetadata = serde_json::from_str(&fs::read_to_string(&active_metadata)?)?;

    // The signers file is now active and can be used.

    // Create a text file in a sibling directory
    let sibling_dir = root_dir.join("sibling");
    fs::create_dir_all(&sibling_dir)?;
    let text_file = sibling_dir.join("test.txt");
    fs::write(&text_file, "This is a test file to be signed")?;

    // User2 signs the text file
    {
        // User2 scope for signing the file
        let text_file_hash = sha512_for_file(&text_file)?;
        let signature2 = user2_sk.sign(&text_file_hash)?;
        let signed_file = SignedFileLoader::load(&text_file)?;
        signed_file.add_signature(signature2, user2_pk.clone())?;
    }

    // Check it left the signature as pending
    let is_signed = SignedFileLoader::load(&text_file)?.is_signed()?;
    assert!(!is_signed);
    match SignatureWithState::load_for_file(&text_file)? {
        SignatureWithState::Pending(_) => Ok(()),
        _ => Err(anyhow::anyhow!("Unexpected signature state")),
    }?;

    // User1 signs the text file
    {
        // User1 scope for signing the file
        let text_file_hash = sha512_for_file(&text_file)?;
        let signature1 = user1_sk.sign(&text_file_hash)?;
        SignedFileLoader::load(&text_file)?.add_signature(signature1, user1_pk.clone())?;
    }

    // As both signatures have been collected, the aggregate signature is now complete.
    match SignatureWithState::load_for_file(&text_file)? {
        SignatureWithState::Complete(_) => Ok(()),
        _ => Err(anyhow::anyhow!(
            "Unexpected signature state: should be complete at end of test"
        )),
    }?;

    Ok(())
}
