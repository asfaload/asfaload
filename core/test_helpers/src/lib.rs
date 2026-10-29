pub mod history_helpers;
pub mod scenarios;
pub mod signers_setup;

use signatures::keys::AsfaloadSecretKeyTrait;
pub use signers_setup::*;

use signatures::keys::AsfaloadKeyPairTrait;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::keys::KeyFormat;
use signatures::keys::asfaload::format::Argon2Params;
use signatures::types::AsfaloadKeyPairs;
use signatures::types::AsfaloadPublicKeys;
use signatures::types::AsfaloadSecretKeys;
use signers_file_types::Forge;
use signers_file_types::SignersConfigMetadata;
use signers_file_types::VerifiedForgeContent;
use std::path::PathBuf;
use tempfile::TempDir;

/// Number of pre-generated fixture keypairs available.
const FIXTURE_KEY_COUNT: usize = 10;

/// Password used for all fixture keypairs.
const FIXTURE_PASSWORD: &str = "password";

/// Low-cost argon2id for fast test key generation. NOT for production.
/// Keep in sync with Argon2Params::TEST in signatures/src/keys/asfaload/format.rs.
const TEST_ARGON2_PARAMS: Argon2Params = Argon2Params::TEST;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}
pub fn fixtures_keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}
pub fn fixtures_pub_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("key_{}.pub", n))
}
pub fn fixtures_sec_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("key_{}", n))
}
pub fn fixtures_asfaload_pub_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("key_{}.pub", n))
}

/// Returns the `.pub` path of a 0600 copy of the committed passwordless
/// ed25519 signing keypair, staged once per process into a temp dir. ssh
/// refuses a private key that is group/world readable, and the committed
/// fixture is checked out with the umask's mode, so copying (rather than using
/// the fixture in place) guarantees the private key is 0600 regardless of the
/// checkout. Every test entry point relies on this — no Makefile `chmod`
/// side-channel needed.
pub fn git_signing_pub_key_path() -> PathBuf {
    use std::sync::OnceLock;
    static KEY: OnceLock<PathBuf> = OnceLock::new();
    KEY.get_or_init(|| {
        let dir = tempfile::TempDir::new().unwrap().keep();
        let dst_priv = dir.join("git_signing_key");
        let dst_pub = dir.join("git_signing_key.pub");
        std::fs::copy(fixtures_dir().join("git_signing_key"), &dst_priv).unwrap();
        std::fs::copy(fixtures_dir().join("git_signing_key.pub"), &dst_pub).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dst_priv, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        dst_pub
    })
    .clone()
}

/// Load a key pair from fixture files.
pub fn get_key_pair() -> anyhow::Result<(AsfaloadPublicKeys, AsfaloadSecretKeys)> {
    let dir = fixtures_keys_dir();
    let pk = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    Ok((pk, sk))
}
/// Load two key pairs from fixture files.
pub fn get_two_key_pairs() -> anyhow::Result<(
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
)> {
    let dir = fixtures_keys_dir();
    let pk1 = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk1 = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    let pk2 = AsfaloadPublicKeys::from_file(dir.join("key_1.pub"))?;
    let sk2 = AsfaloadSecretKeys::from_file(dir.join("key_1"), "password")?;
    Ok((pk1, sk1, pk2, sk2))
}

/// Generate a fresh asfaload key pair (fast TEST params) and save to temp dir.
/// Returns (public key, secret key) via the enum facade.
pub fn get_asfaload_key_pair() -> anyhow::Result<(TempDir, AsfaloadPublicKeys, AsfaloadSecretKeys)>
{
    let temp_dir = tempfile::tempdir()?;
    let kp = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp.save(temp_dir.path())?;
    let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "password")?;
    Ok((temp_dir, pk, sk))
}

/// Generate two fresh asfaload key pairs (fast TEST params).
pub fn get_two_asfaload_key_pairs() -> anyhow::Result<(
    TempDir,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
)> {
    let temp_dir = tempfile::tempdir()?;
    let kp1 = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password1",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp1.save(temp_dir.path().join("key1"))?;
    let kp2 = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password2",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp2.save(temp_dir.path().join("key2"))?;
    let pk1 = AsfaloadPublicKeys::from_file(temp_dir.path().join("key1.pub"))?;
    let sk1 = AsfaloadSecretKeys::from_file(temp_dir.path().join("key1"), "password1")?;
    let pk2 = AsfaloadPublicKeys::from_file(temp_dir.path().join("key2.pub"))?;
    let sk2 = AsfaloadSecretKeys::from_file(temp_dir.path().join("key2"), "password2")?;
    Ok((temp_dir, pk1, sk1, pk2, sk2))
}
/// Select key algorithm from the KEY_TYPE env var, matching the e2e test convention.
/// Panics on unrecognised values to surface typos early.
pub fn default_key_type() -> KeyFormat {
    match std::env::var("KEY_TYPE").as_deref() {
        Ok("asfaload") => KeyFormat::Asfaload,
        Err(_) => KeyFormat::Asfaload,
        Ok(other) => panic!("Unknown KEY_TYPE: {other} (expected: asfaload)"),
    }
}

pub struct TestKeys {
    key_pairs: Vec<AsfaloadKeyPairs>,
    pub_keys: Vec<AsfaloadPublicKeys>,
    sec_keys: Vec<AsfaloadSecretKeys>,
}

impl TestKeys {
    /// Load pre-generated keys based on KEY_TYPE env var.
    /// default is asfaload, KEY_TYPE=asfaload loads asfaload fixtures
    pub fn new(n: usize) -> Self {
        Self::new_from(0, n)
    }

    /// Load pre-generated keys based on KEY_TYPE env var, starting at `start`.
    pub fn new_from(start: usize, n: usize) -> Self {
        match default_key_type() {
            KeyFormat::Asfaload => Self::new_asfaload_from(start, n),
            KeyFormat::OpenSsh => {
                panic!("TestKeys does not support OpenSsh; use asfaload")
            }
        }
    }

    /// Generate fresh keypairs at runtime using KEY_TYPE env var to select format.
    pub fn new_generated(n: usize) -> Self {
        Self::new_generated_with_format(n, &default_key_type())
    }

    /// Generate fresh keypairs at runtime with a specific algorithm format.
    pub fn new_generated_with_format(n: usize, format: &KeyFormat) -> Self {
        let mut r = TestKeys {
            key_pairs: Vec::with_capacity(n),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for _ in 0..n {
            let key_pair = AsfaloadKeyPairs::new_with_format_and_argon2_params(
                FIXTURE_PASSWORD,
                format,
                TEST_ARGON2_PARAMS,
            )
            .unwrap();
            let pub_key = key_pair.public_key();
            let sec_key = key_pair.secret_key(FIXTURE_PASSWORD).unwrap();
            r.key_pairs.push(key_pair);
            r.sec_keys.push(sec_key);
            r.pub_keys.push(pub_key);
        }

        r
    }

    /// Load pre-generated asfaload keys from fixture files starting at index 0.
    pub fn new_asfaload(n: usize) -> Self {
        Self::new_asfaload_from(0, n)
    }

    /// Load pre-generated asfaload keys from fixture files starting at `start`.
    pub fn new_asfaload_from(start: usize, n: usize) -> Self {
        assert!(
            start + n <= FIXTURE_KEY_COUNT,
            "Only {FIXTURE_KEY_COUNT} fixture keypairs available, requested indices {start}..{}",
            start + n
        );
        let fixtures_dir = fixtures_keys_dir();

        let mut r = TestKeys {
            key_pairs: Vec::new(),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for i in start..start + n {
            let pk = AsfaloadPublicKeys::from_file(fixtures_dir.join(format!("key_{i}.pub")))
                .unwrap_or_else(|e| {
                    panic!("Failed to load fixture asfaload public key key_{i}.pub: {e}")
                });
            let sk = AsfaloadSecretKeys::from_file_for_format(
                fixtures_dir.join(format!("key_{i}")),
                FIXTURE_PASSWORD,
                &KeyFormat::Asfaload,
            )
            .unwrap_or_else(|e| panic!("Failed to load fixture asfaload secret key key_{i}: {e}"));
            r.pub_keys.push(pk);
            r.sec_keys.push(sk);
        }

        r
    }

    pub fn pub_key(&self, n: usize) -> Option<&AsfaloadPublicKeys> {
        self.pub_keys.get(n)
    }
    pub fn sec_key(&self, n: usize) -> Option<&AsfaloadSecretKeys> {
        self.sec_keys.get(n)
    }
    pub fn key_pair(&self, n: usize) -> Option<&AsfaloadKeyPairs> {
        self.key_pairs.get(n)
    }

    pub fn substitute_keys(&self, tpl: String) -> String {
        let result = self.pub_keys.iter().enumerate().fold(tpl, |t, (i, k)| {
            // Insert bare base64 (with "format:" prefix)
            let prefixed = k.to_base64();
            t.replace(format!("PUBKEY{}_PLACEHOLDER", i).as_str(), &prefixed)
        });
        // Replace FORMAT_PLACEHOLDER with the serialized key format string.
        // All keys in a TestKeys instance share the same format.
        if let Some(first_key) = self.pub_keys.first() {
            let format_str = first_key.key_format().to_string();
            result.replace("FORMAT_PLACEHOLDER", &format_str)
        } else {
            result
        }
    }
}

pub fn pause() {
    let mut s = "".to_string();
    println!("Pausing test, press enter when done");
    let _ = std::io::stdin().read_line(&mut s);
}

pub fn test_metadata() -> SignersConfigMetadata {
    SignersConfigMetadata::new(
        Forge::Github,
        "https://example.com/test".to_string(),
        VerifiedForgeContent::new_for_test(
            "https://raw.example.com/test/signers.json".to_string(),
            "test_hash_placeholder".to_string(),
        ),
        chrono::Utc::now(),
    )
}

/// Metadata for a signers file published on a forge.
///
/// The recorded retrieval url is `source_url` and the verified content hash is
/// the sha512 of `content`, which tests serve at `source_url`. Constructed
/// through the types in `signers_file_types`, so it stays in sync when the
/// metadata serialization format changes.
pub fn forge_metadata(forge_url: &str, source_url: &str, content: &[u8]) -> SignersConfigMetadata {
    let source_content = String::from_utf8_lossy(content);
    SignersConfigMetadata::new(
        Forge::Github,
        forge_url.to_string(),
        VerifiedForgeContent::new_for_test(source_url.to_string(), source_content.to_string()),
        chrono::Utc::now(),
    )
}

/// Serialize forge metadata as the backend serves it: compact posix JSON with
/// a single trailing newline.
pub fn signers_metadata_json(forge_url: &str, source_url: &str, content: &[u8]) -> String {
    common::to_posix_json(&forge_metadata(forge_url, source_url, content))
        .expect("forge metadata should serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use signatures::keys::AsfaloadSecretKeyTrait;

    /// Generate fixture keypairs and save them to fixtures/keys/.
    /// Run with: cargo test --package test_helpers -- gen_fixture_keys --ignored --nocapture
    #[test]
    #[ignore]
    fn gen_fixture_keys() {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("keys");
        std::fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures/keys dir");

        for i in 0..FIXTURE_KEY_COUNT {
            let kp = AsfaloadKeyPairs::new(FIXTURE_PASSWORD).expect("Failed to generate keypair");
            let key_path = fixtures_dir.join(format!("key_{i}"));
            kp.save(&key_path)
                .unwrap_or_else(|e| panic!("Failed to save keypair {i}: {e}"));
            println!("Generated key_{i}");
        }
        println!(
            "Done: generated {FIXTURE_KEY_COUNT} keypairs in {}",
            fixtures_dir.display()
        );
    }

    /// Generate asfaload fixture keypairs and save them to fixtures/keys/.
    /// Run with: cargo test --package test_helpers -- gen_fixture_asfaload_keys --ignored --nocapture
    #[test]
    #[ignore]
    fn gen_fixture_asfaload_keys() {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("keys");
        std::fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures/keys dir");

        for i in 0..FIXTURE_KEY_COUNT {
            let kp = AsfaloadKeyPairs::new_with_format_and_argon2_params(
                FIXTURE_PASSWORD,
                &KeyFormat::Asfaload,
                TEST_ARGON2_PARAMS,
            )
            .expect("Failed to generate asfaload keypair");
            let key_path = fixtures_dir.join(format!("key_{i}"));
            // Remove existing files to allow regeneration
            let _ = std::fs::remove_file(&key_path);
            let _ = std::fs::remove_file(key_path.with_extension("pub"));
            kp.save(&key_path)
                .unwrap_or_else(|e| panic!("Failed to save asfaload keypair {i}: {e}"));
            println!("Generated key_{i}");
        }
        println!(
            "Done: generated {FIXTURE_KEY_COUNT} asfaload keypairs in {}",
            fixtures_dir.display()
        );
    }

    /// Generate the passwordless ed25519 SSH signing key fixture.
    /// Run with: cargo test --package test_helpers -- gen_git_signing_key --ignored --nocapture
    #[test]
    #[ignore]
    fn gen_git_signing_key() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("git_signing_key");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("pub"));

        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "git-actor@asfaload.com",
                "-f",
            ])
            .arg(&path)
            .status()
            .expect("ssh-keygen should run");
        assert!(status.success(), "ssh-keygen failed");
        println!("Generated {}", path.display());
    }

    #[test]
    fn test_git_signing_pub_key_fixture_exists() {
        let pub_path = fixtures_dir().join("git_signing_key.pub");
        assert!(
            pub_path.exists(),
            "missing fixture: {} (regenerate with `cargo test -p test_helpers -- gen_git_signing_key --ignored`)",
            pub_path.display()
        );
        // The private key must sit next to the public key for ssh signing.
        let priv_path = pub_path.with_extension("");
        assert!(
            priv_path.exists(),
            "missing private key: {}",
            priv_path.display()
        );
    }

    /// ssh refuses to use a private key that is group/world readable. The
    /// committed fixture is checked out with the umask's mode, so the helper
    /// must hand back a key that is 0600 regardless of the checkout — every
    /// test entry point relies on this, not just the Makefile.
    #[test]
    #[cfg(unix)]
    fn test_git_signing_private_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let priv_path = git_signing_pub_key_path().with_extension("");
        let mode = std::fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must be 0600, got {:o}", mode);
    }

    /// The metadata JSON helper must produce JSON that deserializes back into
    /// the same metadata. A change in the metadata serialization format shows
    /// up here first, before the CLI test fixtures start failing.
    #[test]
    fn signers_metadata_json_round_trips() {
        let source_url = "https://github.com/acme/tool/raw/main/asfaload.signers/index.json";
        let content = br#"{"version":1}"#;
        let json =
            signers_metadata_json(source_url, "https://source.example.com/index.json", content);
        let parsed: SignersConfigMetadata =
            serde_json::from_str(&json).expect("helper JSON should deserialize");
        assert_eq!(
            parsed.retrieval_url(),
            "https://source.example.com/index.json"
        );
        assert!(matches!(parsed.kind(), Forge::Github));
    }

    #[test]
    fn test_load_fixture_keys() {
        let keys = TestKeys::new(5);
        for i in 0..5 {
            assert!(keys.pub_key(i).is_some(), "pub_key({i}) should exist");
            assert!(keys.sec_key(i).is_some(), "sec_key({i}) should exist");
        }
        // Fixture-loaded keys don't have key_pairs
        assert!(keys.key_pair(0).is_none());
    }

    #[test]
    fn test_fixture_keys_can_sign_and_verify() {
        let keys = TestKeys::new(2);
        let data = common::sha512_for_content(b"test data".to_vec()).unwrap();
        let sig = keys.sec_key(0).unwrap().sign(&data).unwrap();
        keys.pub_key(0).unwrap().verify(&sig, &data).unwrap();
    }

    #[test]
    fn test_load_asfaload_fixture_keys() {
        let keys = TestKeys::new_asfaload(5);
        for i in 0..5 {
            assert!(
                keys.pub_key(i).is_some(),
                "asfaload pub_key({i}) should exist"
            );
            assert!(
                keys.sec_key(i).is_some(),
                "asfaload sec_key({i}) should exist"
            );
        }
        assert!(keys.key_pair(0).is_none());
    }

    #[test]
    fn test_asfaload_fixture_keys_can_sign_and_verify() {
        let keys = TestKeys::new_asfaload(2);
        let data = common::sha512_for_content(b"test data".to_vec()).unwrap();
        let sig = keys.sec_key(0).unwrap().sign(&data).unwrap();
        keys.pub_key(0).unwrap().verify(&sig, &data).unwrap();
    }
}
