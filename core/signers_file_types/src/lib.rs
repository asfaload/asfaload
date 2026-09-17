pub mod revocation;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use common::errors::{SignersConfigError, SignersFileError, keys::KeyError};
use common::fs::names::{metadata_path_for, metadata_signatures_path_for, signatures_path_for};
use common::sha512_for_content;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use signatures::keys::KeyFormat;
use signatures::signatures_file::SignaturesFile;
use signatures::{keys::AsfaloadPublicKeyTrait, types::AsfaloadPublicKeys};

// We set a bound in the serde annotation. Here why, as explained by AI:
// Without this bound, we get the error `E0277` "the trait bound `P: _::_serde::Deserialize<'_>` is
// not satisfied" occurs because when `#[derive(Deserialize)]` is used on generic structs like
// `SignersConfig`, `SignerGroup`, and `Signer`, `serde` implicitly adds `P: Deserialize` and `P:
// Serialize` bounds to their generic parameter `P`.
// However, in this design, the actual deserialization and serialization of the generic `P` (which
// represents the public key) is handled manually within the `SignerData<APK>`'s custom `impl
// Serialize` and `impl Deserialize` blocks, which only require `P: AsfaloadPublicKeyTrait`. `P`
// itself does not need to implement `serde::Deserialize` or `serde::Serialize` directly.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
// FIXME: check if this needs fixing
//#[serde(bound(
//    serialize = "APK: AsfaloadPublicKeyTrait",
//    deserialize = "APK: AsfaloadPublicKeyTrait"
//))]
pub struct SignersConfig {
    version: u32,
    timestamp: DateTime<Utc>,
    artifact_signers: Vec<SignerGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_keys: Option<Vec<SignerGroup>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    master_keys: Option<Vec<SignerGroup>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocation_keys: Option<Vec<SignerGroup>>,
}

// Deserialize is hand-written (not derived) so JSON parsing is forced through
// SignersConfig::new, which enforces the master-keys-disjoint invariant.
// A derived Deserialize would bypass that validation.
impl<'de> Deserialize<'de> for SignersConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SignersConfigHelper {
            version: u32,
            timestamp: DateTime<Utc>,
            artifact_signers: Vec<SignerGroup>,
            #[serde(default)]
            admin_keys: Option<Vec<SignerGroup>>,
            #[serde(default)]
            master_keys: Option<Vec<SignerGroup>>,
            #[serde(default)]
            revocation_keys: Option<Vec<SignerGroup>>,
        }

        let helper = SignersConfigHelper::deserialize(deserializer)?;
        let proposal = SignersConfigProposal {
            version: helper.version,
            timestamp: helper.timestamp,
            artifact_signers: helper.artifact_signers,
            admin_keys: helper.admin_keys,
            master_keys: helper.master_keys,
            revocation_keys: helper.revocation_keys,
        };
        SignersConfig::new(proposal).map_err(serde::de::Error::custom)
    }
}

// Introduced to make fields of SignersConfig private while:
// - limiting changes: no need to edit field names, etc in code where
//   a SignersConfig was constructed
// - keeping the code clear: I first started to require the use of
//   SignersConfig::new with arguments (version, artifact, admin,master),
//   but in the end it was not very readable code because the function arguments don't make it
//   clear which argument is which SignersGroup.
// In the end, rewriting new to take this struct as argument seemed the best solution.
// Apart from requiing the use of accessor to private fields, this does not change much at this time
// but it enables us to add a validation step when building a SignersConfig.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
//#[serde(bound(
//    serialize = "APK: AsfaloadPublicKeyTrait",
//    deserialize = "APK: AsfaloadPublicKeyTrait"
//))]
pub struct SignersConfigProposal {
    pub version: u32,
    pub timestamp: DateTime<Utc>,
    pub artifact_signers: Vec<SignerGroup>,
    pub admin_keys: Option<Vec<SignerGroup>>,
    pub master_keys: Option<Vec<SignerGroup>>,
    pub revocation_keys: Option<Vec<SignerGroup>>,
}

impl SignersConfigProposal {
    // Implemented so we can call do SignersConfigProposal{...}.build()
    // without having to assign the proposal.
    pub fn build(&self) -> Result<SignersConfig, SignersConfigError> {
        SignersConfig::new(self.clone())
    }
}
impl SignersConfig {
    // Returns Result<(), _> rather than bool so the error can carry the
    // offending key for debuggability — a bool could only say "a violation
    // exists" without naming which key.
    fn validate_master_disjoint(
        artifact_signers: &[SignerGroup],
        admin_keys: Option<&[SignerGroup]>,
        master_keys: Option<&[SignerGroup]>,
        revocation_keys: Option<&[SignerGroup]>,
    ) -> Result<(), SignersConfigError> {
        let Some(master) = master_keys else {
            return Ok(());
        };

        let master_pubkeys: HashSet<&AsfaloadPublicKeys> = master
            .iter()
            .flat_map(|g| g.signers.iter().map(|s| &s.data.pubkey))
            .collect();

        if master_pubkeys.is_empty() {
            return Ok(());
        }

        let others = artifact_signers
            .iter()
            .chain(admin_keys.into_iter().flatten())
            .chain(revocation_keys.into_iter().flatten());

        for signer in others.flat_map(|g| &g.signers) {
            if master_pubkeys.contains(&signer.data.pubkey) {
                return Err(SignersConfigError::MasterKeyInOtherGroup {
                    key: signer.data.pubkey.to_base64(),
                });
            }
        }
        Ok(())
    }

    pub fn new(p: SignersConfigProposal) -> Result<Self, SignersConfigError> {
        Self::validate_master_disjoint(
            &p.artifact_signers,
            p.admin_keys.as_deref(),
            p.master_keys.as_deref(),
            p.revocation_keys.as_deref(),
        )?;
        Ok(Self {
            timestamp: p.timestamp,
            version: p.version,
            artifact_signers: p.artifact_signers,
            master_keys: p.master_keys,
            admin_keys: p.admin_keys,
            revocation_keys: p.revocation_keys,
        })
    }

    pub fn from_file<P: AsRef<Path>>(path_in: P) -> Result<Self, SignersConfigError> {
        let signers_path = path_in.as_ref();
        let signers_content = std::fs::read_to_string(signers_path)?;
        let signers_config = parse_signers_config(&signers_content)?;
        Ok(signers_config)
    }

    // Helper function to create a SignerGroup from pubkeys' string representation.
    fn create_group(
        pubkeys: Vec<AsfaloadPublicKeys>,
        threshold: u32,
    ) -> Result<SignerGroup, SignersConfigError> {
        if pubkeys.is_empty() {
            return Err(SignersConfigError::GroupError(
                "Empty groups cannot be built".to_string(),
            ));
        }
        let signers = pubkeys
            .iter()
            .map(Signer::from_key)
            .collect::<Result<Vec<Signer>, KeyError>>()?;
        Ok(SignerGroup { signers, threshold })
    }

    pub fn as_proposal(&self) -> SignersConfigProposal {
        SignersConfigProposal {
            timestamp: self.timestamp,
            version: self.version,
            artifact_signers: self.artifact_signers.clone(),
            master_keys: self.master_keys.clone(),
            admin_keys: self.admin_keys.clone(),
            revocation_keys: self.revocation_keys.clone(),
        }
    }

    // Create a SignersConfig with the given public keys as strings and threshold for different groups
    pub fn with_keys(
        version: u32,
        (artifact_signers, artifact_threshold): (Vec<AsfaloadPublicKeys>, u32),
        admin_keys: Option<(Vec<AsfaloadPublicKeys>, u32)>,
        master_keys: Option<(Vec<AsfaloadPublicKeys>, u32)>,
        revocation_keys: Option<(Vec<AsfaloadPublicKeys>, u32)>,
    ) -> Result<Self, SignersConfigError> {
        // Helper function to create a SignerGroup from a vector of public key strings
        // Create the artifact signers group
        let artifact_signers = if artifact_signers.is_empty() {
            vec![]
        } else {
            vec![Self::create_group(artifact_signers, artifact_threshold)?]
        };

        // Create the admin signers group
        let admin_keys = match admin_keys {
            Some((keys, _threshold)) if keys.is_empty() => None,
            Some((keys, threshold)) => Some(vec![Self::create_group(keys, threshold)?]),
            None => None,
        };

        // Create the master signers group
        let master_keys = match master_keys {
            Some((keys, _threshold)) if keys.is_empty() => None,
            Some((keys, threshold)) => Some(vec![Self::create_group(keys, threshold)?]),
            None => None,
        };

        let revocation_keys = match revocation_keys {
            Some((keys, _threshold)) if keys.is_empty() => None,
            Some((keys, threshold)) => Some(vec![Self::create_group(keys, threshold)?]),
            None => None,
        };

        Self::new(SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version,
            artifact_signers,
            admin_keys,
            master_keys,
            revocation_keys,
        })
    }

    pub fn with_artifact_signers_only(
        version: u32,
        artifact_signers_and_threshold: (Vec<AsfaloadPublicKeys>, u32),
    ) -> Result<Self, SignersConfigError> {
        Self::with_keys(version, artifact_signers_and_threshold, None, None, None)
    }

    pub fn artifact_signers(&self) -> &[SignerGroup] {
        &self.artifact_signers
    }
    pub fn admin_keys(&self) -> &[SignerGroup] {
        match &self.admin_keys {
            Some(v) if !v.is_empty() => v,
            _ => &self.artifact_signers,
        }
    }
    pub fn master_keys(&self) -> Option<Vec<SignerGroup>> {
        self.master_keys.clone()
    }

    // Revocation keys are either specified explicitly, or we fall back
    // to admin_keys, which themselves fall back to artifact signers.
    pub fn revocation_keys(&self) -> &[SignerGroup] {
        match &self.revocation_keys {
            Some(v) if !v.is_empty() => v,
            _ => self.admin_keys(),
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        common::to_posix_json(self)
    }
    // Get all signers keys present in the SignersConfig.
    pub fn all_signer_keys(&self) -> HashSet<AsfaloadPublicKeys> {
        // Do not use the accessors: we do not want to follow the fallback mechanisms, as this
        // would lead to duplicated keys (eg if admin group is empty, the admin accessor will
        // return the artifact signers, which we add later on.)
        self.admin_keys
            .as_deref()
            .unwrap_or_default()
            .iter()
            .chain(self.master_keys().unwrap_or_default().iter())
            .chain(self.artifact_signers.iter())
            .chain(self.revocation_keys.as_deref().unwrap_or_default().iter())
            .flat_map(|group| {
                group
                    .signers
                    .iter()
                    .map(|signer| signer.data.pubkey.clone())
            })
            .collect()
    }
}
/// Errors that can occur when creating a [`VerifiedForgeContent`].
#[derive(Debug, thiserror::Error)]
pub enum VerifiedForgeContentError {
    #[error("Failed to fetch content: {0}")]
    FetchError(String),
    #[error("Failed to compute hash: {0}")]
    HashError(String),
    #[error("Fetched content's hash {actual} does not match expected {expected}")]
    FetchedContentHashMismatch { actual: String, expected: String },
}

/// A retrieval URL paired with the SHA-512 hash of the content at that URL.
///
/// Enforces that URL and hash are always consistent. In production, the only
/// way to create one is [`VerifiedForgeContent::new`], which fetches the URL
/// and computes the hash internally, eliminating any possibility of
/// URL/content mismatch.
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct VerifiedForgeContent {
    retrieval_url: String,
    content_hash: String,
    /// Cached fetched content. Present after `new()`, absent after deserialization.
    #[serde(skip)]
    content: Option<String>,
}

/// Equality compares only `retrieval_url` and `content_hash` — the `content`
/// field is transient (skipped in serde) and must not affect equality.
impl PartialEq for VerifiedForgeContent {
    fn eq(&self, other: &Self) -> bool {
        self.retrieval_url == other.retrieval_url && self.content_hash == other.content_hash
    }
}

impl VerifiedForgeContent {
    /// URL used to fetch the raw file content.
    pub fn retrieval_url(&self) -> &str {
        &self.retrieval_url
    }

    /// SHA-512 hex digest of the content at `retrieval_url`.
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// Returns the fetched content. If not cached (e.g. after deserialization),
    /// re-fetches from `retrieval_url`. Does not cache the re-fetched result, but
    /// impact is null or minimal in our scenario as we don't call it multiple times on
    /// an instance that was deserialized. Validates that content fetched has same hash
    /// as expected.
    pub async fn content(&self) -> Result<String, VerifiedForgeContentError> {
        if let Some(ref c) = self.content {
            return Ok(c.clone());
        }
        let fetched = common::http::fetch_with_retry(&self.retrieval_url)
            .await
            .map_err(|e| VerifiedForgeContentError::FetchError(e.to_string()))?;
        let fetched_hash = sha512_for_content(fetched.as_bytes())
            .map_err(|e| VerifiedForgeContentError::HashError(e.to_string()))?
            .to_hex();
        if fetched_hash == self.content_hash {
            Ok(fetched)
        } else {
            Err(VerifiedForgeContentError::FetchedContentHashMismatch {
                actual: fetched_hash,
                expected: self.content_hash.clone(),
            })
        }
    }

    /// Production constructor: fetches content from the URL and computes the hash.
    /// This is the only way to create a `VerifiedForgeContent` in production,
    /// guaranteeing that the URL and content hash are always consistent.
    /// Retries with exponential backoff on HTTP 429 (rate limiting).
    pub async fn new(retrieval_url: String) -> Result<Self, VerifiedForgeContentError> {
        let content = common::http::fetch_with_retry(&retrieval_url)
            .await
            .map_err(|e| VerifiedForgeContentError::FetchError(e.to_string()))?;

        let hash = common::sha512_for_content(content.as_bytes())
            .map_err(|e| VerifiedForgeContentError::HashError(e.to_string()))?;

        Ok(Self {
            retrieval_url,
            content_hash: hash.to_hex(),
            content: Some(content),
        })
    }

    /// Test-only constructor that bypasses the fetch+hash guarantee.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(retrieval_url: String, content: String) -> Self {
        let content_hash = common::sha512_for_content(content.as_bytes())
            .unwrap()
            .to_hex();
        Self {
            retrieval_url,
            content_hash,
            content: Some(content),
        }
    }
}

// Supported forges
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Forge {
    Github,
    Gitlab,
    FileServer,
}
// Metadata about the signers file retrieved from a forge
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForgeOrigin {
    kind: Forge,
    url: String,
    verified_content: VerifiedForgeContent,
    retrieved_at: DateTime<Utc>,
}

impl ForgeOrigin {
    pub fn new(
        kind: Forge,
        url: String,
        verified_content: VerifiedForgeContent,
        retrieved_at: DateTime<Utc>,
    ) -> Self {
        Self {
            kind,
            url,
            verified_content,
            retrieved_at,
        }
    }

    /// The original URL as provided by the user.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// URL to use when fetching file content. Delegates to `verified_content`.
    pub fn retrieval_url(&self) -> &str {
        self.verified_content.retrieval_url()
    }

    /// The verified content metadata (retrieval URL + content hash).
    pub fn verified_content(&self) -> &VerifiedForgeContent {
        &self.verified_content
    }

    pub fn kind(&self) -> &Forge {
        &self.kind
    }
}

// Enum listing possible origins of a signers file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignersConfigOrigin {
    Forge(ForgeOrigin),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignersConfigMetadata {
    data: SignersConfigOrigin,
}

impl SignersConfigMetadata {
    pub fn from_forge(origin: ForgeOrigin) -> Self {
        Self {
            data: SignersConfigOrigin::Forge(origin),
        }
    }

    pub fn origin(&self) -> &SignersConfigOrigin {
        &self.data
    }
}

#[derive(Debug, Clone, Serialize)]
//#[serde(bound(
//    serialize = "APK: AsfaloadPublicKeyTrait",
//    deserialize = "APK: AsfaloadPublicKeyTrait"
//))]
#[derive(Eq, PartialEq)]
pub struct SignerGroup {
    pub signers: Vec<Signer>,
    pub threshold: u32,
}

// Custom deserializer for SignerGroup that validates threshold <= signers.len()
impl<'de> Deserialize<'de> for SignerGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a helper struct that mirrors SignerGroup but without the custom Deserialize
        #[derive(Deserialize)]
        //#[serde(bound(deserialize = "APK: AsfaloadPublicKeyTrait"))]
        struct SignerGroupHelper {
            signers: Vec<Signer>,
            threshold: u32,
        }

        // Deserialize into the helper struct
        let helper = SignerGroupHelper::deserialize(deserializer)?;

        // Validate that we have at least one signer
        if helper.signers.is_empty() {
            return Err(serde::de::Error::custom("Group size must be at least 1"));
        }
        // Validate that threshold > 0
        if helper.threshold == 0 {
            return Err(serde::de::Error::custom(format!(
                "Threshold ({}) must be strictly greater than 0",
                helper.threshold,
            )));
        }
        // Validate that threshold <= signers.len()
        if helper.threshold > helper.signers.len() as u32 {
            return Err(serde::de::Error::custom(format!(
                "Threshold ({}) cannot be greater than the number of signers ({})",
                helper.threshold,
                helper.signers.len()
            )));
        }

        // If validation passes, create the actual SignerGroup
        Ok(SignerGroup {
            signers: helper.signers,
            threshold: helper.threshold,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
//#[serde(bound(
//    serialize = "APK: AsfaloadPublicKeyTrait",
//    deserialize = "APK: AsfaloadPublicKeyTrait"
//))]
#[derive(Eq, PartialEq)]
pub struct Signer {
    pub kind: SignerKind,
    pub data: SignerData,
}

impl Signer {
    pub fn from_key(pk: &AsfaloadPublicKeys) -> Result<Self, KeyError> {
        Ok(Self {
            kind: SignerKind::Key,
            data: SignerData { pubkey: pk.clone() },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignerKind {
    Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerData {
    pub pubkey: AsfaloadPublicKeys,
}

impl Serialize for SignerData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SignerData", 2)?;
        // Write bare base64 (with format prefix)
        let prefixed = self.pubkey.to_base64();
        state.serialize_field("pubkey", &prefixed)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SignerData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SignerDataHelper {
            pubkey: String,
        }

        let helper = SignerDataHelper::deserialize(deserializer)?;
        // base64 includes key format prefix
        let pubkey = AsfaloadPublicKeys::from_base64(&helper.pubkey).map_err(|_e| {
            serde::de::Error::custom(format!("Problem parsing pubkey base64: {}", helper.pubkey))
        })?;
        Ok(SignerData { pubkey })
    }
}

pub fn parse_signers_config(json_str: &str) -> Result<SignersConfig, serde_json::Error> {
    serde_json::from_str(json_str)
}

pub fn parse_signers_config_proposal(
    json_str: &str,
) -> Result<SignersConfigProposal, serde_json::Error> {
    serde_json::from_str(json_str)
}

/// Serde helpers that base64-encode a `String` on serialization and
/// base64-decode back to a `String` on deserialization. This makes the
/// stored bytes completely opaque to any JSON formatter, preventing
/// accidental modification of the signed content.
/// Use it with an annotation on the field:
///      #[serde(with = "signers_file_types::base64_serde")]
///      my_field: String
pub mod base64_serde {
    use base64::{Engine, prelude::BASE64_STANDARD};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(value.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b64 = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(&b64)
            .map_err(serde::de::Error::custom)?;
        String::from_utf8(bytes).map_err(serde::de::Error::custom)
    }
}

/// Trait implemented by structs containing signers files information, like CurrentSignersInfo and
/// HistoryEntry
pub trait SignersInfoTrait {
    /// Parse the raw JSON into a SignersConfig.
    fn signers_config(&self) -> Result<SignersConfig, serde_json::Error>;
    /// Parse the raw JSON into a SignersConfigMetadata.
    fn metadata(&self) -> Result<SignersConfigMetadata, serde_json::Error>;
}
/// Information about the current signers file. Similar to a HistoryEntry, but without the
/// obsoleted_at field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurrentSignersInfo {
    /// Content of the signers file as raw JSON, base64-encoded in serialized form.
    /// Base64 encoding makes the content completely opaque to JSON formatters,
    /// preventing accidental modification of the signed bytes.
    /// Use `signers_config()` to parse into a `SignersConfig`.
    #[serde(with = "base64_serde")]
    pub signers_file: String,
    /// Signatures collected for the signers file
    pub signatures: SignaturesFile,
    /// Content of the metadata file as raw JSON, base64-encoded in serialized form.
    /// Base64 encoding preserves the exact bytes that were signed.
    /// Use `metadata()` to parse into a `SignersConfigMetadata`.
    #[serde(with = "base64_serde")]
    pub metadata: String,
    /// Signatures collected for the metadata file
    pub metadata_signatures: SignaturesFile,
}

impl CurrentSignersInfo {
    pub fn for_path<P: AsRef<Path>>(signers_path_in: P) -> Result<Self, SignersFileError> {
        let signers_file_path = signers_path_in.as_ref();

        let chain_err =
            |msg: String| -> SignersFileError { SignersFileError::ChainValidationFailed(msg) };

        let signers_file_raw = fs::read_to_string(signers_file_path).map_err(|e| {
            chain_err(format!(
                "read signers file {}: {e}",
                signers_file_path.display()
            ))
        })?;

        let signatures_path = signatures_path_for(signers_file_path)
            .map_err(|e| chain_err(format!("compute signatures path: {e}")))?;
        let signatures_str = fs::read_to_string(&signatures_path)
            .map_err(|e| chain_err(format!("read {}: {e}", signatures_path.display())))?;
        let signatures: SignaturesFile = serde_json::from_str(&signatures_str)
            .map_err(|e| chain_err(format!("parse signatures: {e}")))?;

        let metadata_path = metadata_path_for(signers_file_path)
            .map_err(|e| chain_err(format!("compute metadata path: {e}")))?;
        let metadata_raw = fs::read_to_string(&metadata_path)
            .map_err(|e| chain_err(format!("read {}: {e}", metadata_path.display())))?;

        let meta_sigs_path = metadata_signatures_path_for(signers_file_path)
            .map_err(|e| chain_err(format!("compute metadata signatures path: {e}")))?;
        let meta_sigs_str = fs::read_to_string(&meta_sigs_path)
            .map_err(|e| chain_err(format!("read {}: {e}", meta_sigs_path.display())))?;
        let metadata_signatures: SignaturesFile = serde_json::from_str(&meta_sigs_str)
            .map_err(|e| chain_err(format!("parse metadata signatures: {e}")))?;

        Ok(CurrentSignersInfo {
            signers_file: signers_file_raw,
            signatures,
            metadata: metadata_raw,
            metadata_signatures,
        })
    }
}

impl SignersInfoTrait for CurrentSignersInfo {
    /// Parse the raw JSON into a SignersConfig.
    fn signers_config(&self) -> Result<SignersConfig, serde_json::Error> {
        parse_signers_config(&self.signers_file)
    }

    /// Parse the raw JSON into a SignersConfigMetadata.
    fn metadata(&self) -> Result<SignersConfigMetadata, serde_json::Error> {
        serde_json::from_str(&self.metadata)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    /// ISO8601 formatted UTC date and time
    pub obsoleted_at: DateTime<Utc>,
    /// Content of the signers file as raw JSON, base64-encoded in serialized form.
    /// Base64 encoding makes the content completely opaque to JSON formatters,
    /// preventing accidental modification of the signed bytes.
    /// Use `signers_config()` to parse into a `SignersConfig`.
    #[serde(with = "base64_serde")]
    pub signers_file: String,
    /// Signatures collected for the signers file
    pub signatures: SignaturesFile,
    /// Content of the metadata file as raw JSON, base64-encoded in serialized form.
    /// Base64 encoding preserves the exact bytes that were signed.
    /// Use `metadata()` to parse into a `SignersConfigMetadata`.
    #[serde(with = "base64_serde")]
    pub metadata: String,
    /// Signatures collected for the metadata file
    pub metadata_signatures: SignaturesFile,
}

impl SignersInfoTrait for HistoryEntry {
    /// Parse the raw JSON into a SignersConfig.
    fn signers_config(&self) -> Result<SignersConfig, serde_json::Error> {
        parse_signers_config(&self.signers_file)
    }

    /// Parse the raw JSON into a SignersConfigMetadata.
    fn metadata(&self) -> Result<SignersConfigMetadata, serde_json::Error> {
        serde_json::from_str(&self.metadata)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryFile {
    /// Array of history entries, sorted chronologically
    pub entries: Vec<HistoryEntry>,
}

impl HistoryFile {
    /// Create a new empty history file
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a new entry to the history file
    pub fn add_entry(&mut self, entry: HistoryEntry) {
        self.entries.push(entry);
    }

    /// Get all entries in the history file
    pub fn entries(&self) -> &Vec<HistoryEntry> {
        &self.entries
    }

    /// Get the most recent entry in the history file
    pub fn latest_entry(&self) -> Option<&HistoryEntry> {
        self.entries.last()
    }

    /// Parse a history file from JSON string
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Convert the history file to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        common::to_posix_json(self)
    }

    /// Load a history file from the given path
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, SignersFileError> {
        let content = std::fs::read_to_string(path)?;
        let history_file = Self::from_json(&content)?;
        Ok(history_file)
    }

    /// Save the history file to the given path
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), SignersFileError> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

pub enum SignersChainEntry {
    History(HistoryEntry),
    Current(CurrentSignersInfo),
}

impl SignersChainEntry {
    pub fn obsoleted_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::History(h) => Some(h.obsoleted_at),
            Self::Current(_) => None,
        }
    }
    pub fn metadata(&self) -> Result<SignersConfigMetadata, serde_json::Error> {
        match self {
            Self::History(h) => h.metadata(),
            Self::Current(c) => c.metadata(),
        }
    }
    pub fn signers_config(&self) -> Result<SignersConfig, serde_json::Error> {
        match self {
            Self::History(h) => h.signers_config(),
            Self::Current(c) => c.signers_config(),
        }
    }
    pub fn signers_file(&self) -> String {
        match self {
            Self::History(h) => h.signers_file.clone(),
            Self::Current(c) => c.signers_file.clone(),
        }
    }
    pub fn signatures(&self) -> SignaturesFile {
        match self {
            Self::History(h) => h.signatures.clone(),
            Self::Current(c) => c.signatures.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SignersChain {
    pub history_entries: Vec<HistoryEntry>,
    pub current_signers_info: Option<CurrentSignersInfo>,
}

impl SignersChain {
    pub fn new(history: HistoryFile, current: CurrentSignersInfo) -> Self {
        Self {
            history_entries: history.entries().clone(),
            current_signers_info: Some(current),
        }
    }
    /// Add a new entry to the history entries
    pub fn add_entry(&mut self, entry: HistoryEntry) {
        self.history_entries.push(entry.clone());
    }
    /// Take entries from history
    pub fn set_entries_from_history(&mut self, history: HistoryFile) {
        for entry in history.entries() {
            self.history_entries.push(entry.clone())
        }
    }
    /// Add a new entry to the history entries
    pub fn set_current_info(&mut self, signers_info: CurrentSignersInfo) {
        self.current_signers_info = Some(signers_info);
    }

    pub fn history_entries(&self) -> &[HistoryEntry] {
        &self.history_entries
    }

    pub fn current_signers_info(&self) -> Option<&CurrentSignersInfo> {
        self.current_signers_info.as_ref()
    }

    pub fn entries(&self) -> Vec<SignersChainEntry> {
        let mut all_entries: Vec<SignersChainEntry> = self
            .history_entries
            .iter()
            .cloned() // Assumes HistoryEntry is Clone
            .map(SignersChainEntry::History)
            .collect();

        if let Some(ref current) = self.current_signers_info {
            all_entries.push(SignersChainEntry::Current(current.clone()));
        }

        all_entries
    }

    pub fn first_entry(&self) -> Option<SignersChainEntry> {
        if self.history_entries().is_empty() {
            self.current_signers_info()
                .map(|v| SignersChainEntry::Current(v.clone()))
        } else {
            self.history_entries()
                .first()
                .map(|v| SignersChainEntry::History(v.clone()))
        }
    }
}
impl Default for HistoryFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to parse a history file from JSON string
pub fn parse_history_file(json_str: &str) -> Result<HistoryFile, serde_json::Error> {
    HistoryFile::from_json(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::TestKeys;

    /// Build a SignersConfig with explicit control over all key groups.
    /// Each group that is `Some` gets threshold=1.
    fn build_config(
        artifact_keys: Vec<AsfaloadPublicKeys>,
        admin_keys: Option<Vec<AsfaloadPublicKeys>>,
        revocation_keys: Option<Vec<AsfaloadPublicKeys>>,
    ) -> SignersConfig {
        SignersConfig::with_keys(
            1,
            (artifact_keys, 1),
            admin_keys.map(|k| (k, 1)),
            None,
            revocation_keys.map(|k| (k, 1)),
        )
        .expect("failed to build SignersConfig")
    }

    /// Extract the public keys from the signer groups returned by an accessor.
    fn pubkeys_from_groups(groups: &[SignerGroup]) -> Vec<AsfaloadPublicKeys> {
        groups
            .iter()
            .flat_map(|g| g.signers.iter().map(|s| s.data.pubkey.clone()))
            .collect()
    }

    #[test]
    fn revocation_keys_returns_explicit_revocation_keys_when_present() {
        let keys = TestKeys::new(3);
        let artifact = vec![keys.pub_key(0).unwrap().clone()];
        let admin = vec![keys.pub_key(1).unwrap().clone()];
        let revocation = vec![keys.pub_key(2).unwrap().clone()];

        let config = build_config(artifact, Some(admin), Some(revocation.clone()));

        let result = pubkeys_from_groups(config.revocation_keys());
        assert_eq!(result, revocation);
    }

    #[test]
    fn revocation_keys_falls_back_to_admin_keys_when_none() {
        let keys = TestKeys::new(2);
        let artifact = vec![keys.pub_key(0).unwrap().clone()];
        let admin = vec![keys.pub_key(1).unwrap().clone()];

        let config = build_config(artifact, Some(admin.clone()), None);

        let result = pubkeys_from_groups(config.revocation_keys());
        assert_eq!(result, admin);
    }

    #[test]
    fn revocation_keys_falls_back_to_admin_keys_when_empty() {
        let keys = TestKeys::new(2);
        let artifact = vec![keys.pub_key(0).unwrap().clone()];
        let admin = vec![keys.pub_key(1).unwrap().clone()];

        // with_keys converts empty vec to None internally, so build via proposal
        let config = build_config(artifact, Some(admin.clone()), Some(vec![]));

        // Empty revocation list → falls back to admin_keys
        let result = pubkeys_from_groups(config.revocation_keys());
        assert_eq!(result, admin);
    }

    #[test]
    fn revocation_keys_falls_back_to_artifact_signers_when_no_admin_or_revocation() {
        let keys = TestKeys::new(1);
        let artifact = vec![keys.pub_key(0).unwrap().clone()];

        let config = build_config(artifact.clone(), None, None);

        // No revocation → admin_keys() → no admin → artifact_signers
        let result = pubkeys_from_groups(config.revocation_keys());
        assert_eq!(result, artifact);
    }

    #[test]
    fn revocation_keys_falls_back_to_artifact_signers_when_admin_empty_and_revocation_none() {
        let keys = TestKeys::new(1);
        let artifact = vec![keys.pub_key(0).unwrap().clone()];

        let config = build_config(artifact.clone(), Some(vec![]), None);

        // No revocation → admin_keys() → empty admin → artifact_signers
        let result = pubkeys_from_groups(config.revocation_keys());
        assert_eq!(result, artifact);
    }

    #[test]
    fn new_rejects_master_key_also_in_artifact_signers() {
        let keys = TestKeys::new(2);
        let shared = keys.pub_key(0).unwrap().clone();
        let other = keys.pub_key(1).unwrap().clone();

        let proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&shared).unwrap()],
                threshold: 1,
            }],
            admin_keys: None,
            master_keys: Some(vec![SignerGroup {
                signers: vec![
                    Signer::from_key(&shared).unwrap(),
                    Signer::from_key(&other).unwrap(),
                ],
                threshold: 1,
            }]),
            revocation_keys: None,
        };

        match SignersConfig::new(proposal) {
            Err(SignersConfigError::MasterKeyInOtherGroup { key }) => {
                assert_eq!(key, shared.to_base64());
            }
            Err(e) => panic!("expected MasterKeyInOtherGroup, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn new_rejects_master_key_also_in_admin_keys() {
        let keys = TestKeys::new(2);
        let shared = keys.pub_key(0).unwrap().clone();
        let artifact = keys.pub_key(1).unwrap().clone();

        let proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&artifact).unwrap()],
                threshold: 1,
            }],
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&shared).unwrap()],
                threshold: 1,
            }]),
            master_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&shared).unwrap()],
                threshold: 1,
            }]),
            revocation_keys: None,
        };

        match SignersConfig::new(proposal) {
            Err(SignersConfigError::MasterKeyInOtherGroup { key }) => {
                assert_eq!(key, shared.to_base64());
            }
            Err(e) => panic!("expected MasterKeyInOtherGroup, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn new_rejects_master_key_also_in_revocation_keys() {
        let keys = TestKeys::new(2);
        let shared = keys.pub_key(0).unwrap().clone();
        let artifact = keys.pub_key(1).unwrap().clone();

        let proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&artifact).unwrap()],
                threshold: 1,
            }],
            admin_keys: None,
            master_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&shared).unwrap()],
                threshold: 1,
            }]),
            revocation_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&shared).unwrap()],
                threshold: 1,
            }]),
        };

        match SignersConfig::new(proposal) {
            Err(SignersConfigError::MasterKeyInOtherGroup { key }) => {
                assert_eq!(key, shared.to_base64());
            }
            Err(e) => panic!("expected MasterKeyInOtherGroup, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn new_accepts_disjoint_groups() {
        let keys = TestKeys::new(4);
        let artifact = keys.pub_key(0).unwrap().clone();
        let admin = keys.pub_key(1).unwrap().clone();
        let master = keys.pub_key(2).unwrap().clone();
        let revocation = keys.pub_key(3).unwrap().clone();

        let proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&artifact).unwrap()],
                threshold: 1,
            }],
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&admin).unwrap()],
                threshold: 1,
            }]),
            master_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&master).unwrap()],
                threshold: 1,
            }]),
            revocation_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&revocation).unwrap()],
                threshold: 1,
            }]),
        };

        assert!(SignersConfig::new(proposal).is_ok());
    }

    #[test]
    fn new_accepts_config_without_master_keys() {
        // With master_keys: None, the master-disjoint check is skipped entirely.
        // Use distinct keys per group so this test isn't read as documenting
        // anything about cross-group sharing in the non-master groups.
        let keys = TestKeys::new(3);
        let artifact = keys.pub_key(0).unwrap().clone();
        let admin = keys.pub_key(1).unwrap().clone();
        let revocation = keys.pub_key(2).unwrap().clone();

        let proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&artifact).unwrap()],
                threshold: 1,
            }],
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&admin).unwrap()],
                threshold: 1,
            }]),
            master_keys: None,
            revocation_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&revocation).unwrap()],
                threshold: 1,
            }]),
        };

        assert!(SignersConfig::new(proposal).is_ok());
    }

    #[test]
    fn new_allows_duplicate_key_within_master_keys_only() {
        // Invariant is master-vs-others disjointness, not within-master uniqueness.
        // A master key appearing in two master SignerGroups is allowed, as long as
        // it does not appear in any other group.
        let keys = TestKeys::new(2);
        let master = keys.pub_key(0).unwrap().clone();
        let artifact = keys.pub_key(1).unwrap().clone();

        let proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&artifact).unwrap()],
                threshold: 1,
            }],
            admin_keys: None,
            master_keys: Some(vec![
                SignerGroup {
                    signers: vec![Signer::from_key(&master).unwrap()],
                    threshold: 1,
                },
                SignerGroup {
                    signers: vec![Signer::from_key(&master).unwrap()],
                    threshold: 1,
                },
            ]),
            revocation_keys: None,
        };

        assert!(SignersConfig::new(proposal).is_ok());
    }

    #[test]
    fn parse_rejects_master_key_in_another_group() {
        let keys = TestKeys::new(2);
        let shared = keys.pub_key(0).unwrap().clone();
        let other = keys.pub_key(1).unwrap().clone();

        let json = format!(
            r#"{{
                "version": 1,
                "timestamp": "2026-04-14T00:00:00Z",
                "artifact_signers": [{{
                    "signers": [{{ "kind": "key", "data": {{ "pubkey": "{shared}" }} }}],
                    "threshold": 1
                }}],
                "master_keys": [{{
                    "signers": [
                        {{ "kind": "key", "data": {{ "pubkey": "{shared}" }} }},
                        {{ "kind": "key", "data": {{ "pubkey": "{other}" }} }}
                    ],
                    "threshold": 1
                }}]
            }}"#,
            shared = shared.to_base64(),
            other = other.to_base64(),
        );

        match parse_signers_config(&json) {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains(&shared.to_base64()),
                    "error message should name the offending key: {msg}"
                );
            }
            Ok(_) => panic!("expected Err — master key in another group"),
        }
    }

    #[test]
    fn parse_accepts_disjoint_config() {
        let keys = TestKeys::new(2);
        let artifact = keys.pub_key(0).unwrap().clone();
        let master = keys.pub_key(1).unwrap().clone();

        let json = format!(
            r#"{{
                "version": 1,
                "timestamp": "2026-04-14T00:00:00Z",
                "artifact_signers": [{{
                    "signers": [{{ "kind": "key", "data": {{ "pubkey": "{artifact}" }} }}],
                    "threshold": 1
                }}],
                "master_keys": [{{
                    "signers": [{{ "kind": "key", "data": {{ "pubkey": "{master}" }} }}],
                    "threshold": 1
                }}]
            }}"#,
            artifact = artifact.to_base64(),
            master = master.to_base64(),
        );

        assert!(parse_signers_config(&json).is_ok());
    }

    #[test]
    fn signers_config_round_trips_via_serde() {
        // Serialize and Deserialize are now decoupled (one derived, one hand-written),
        // so explicitly verify they agree on the wire format.
        let keys = TestKeys::new(3);
        let artifact = keys.pub_key(0).unwrap().clone();
        let admin = keys.pub_key(1).unwrap().clone();
        let master = keys.pub_key(2).unwrap().clone();

        let original = SignersConfig::new(SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer::from_key(&artifact).unwrap()],
                threshold: 1,
            }],
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&admin).unwrap()],
                threshold: 1,
            }]),
            master_keys: Some(vec![SignerGroup {
                signers: vec![Signer::from_key(&master).unwrap()],
                threshold: 1,
            }]),
            revocation_keys: None,
        })
        .unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let round_tripped = parse_signers_config(&json).unwrap();
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn signers_config_to_json_ends_with_single_newline() {
        let keys = TestKeys::new(1);
        let cfg = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let json = cfg.to_json().unwrap();
        assert!(json.ends_with("}\n"));
        assert!(!json.ends_with("\n\n"));
    }

    #[test]
    fn history_file_to_json_ends_with_single_newline() {
        let json = HistoryFile::new().to_json().unwrap();
        assert!(json.ends_with("\n"));
        assert!(!json.ends_with("\n\n"));
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn history_entry_round_trips_with_metadata_signatures() {
        // Build a HistoryEntry with metadata_signatures via JSON, then
        // round-trip it through serialization/deserialization.
        // We avoid direct cross-crate type comparisons (diamond dependency)
        // by comparing the serialized JSON instead.
        let entry_json = test_helpers::history_helpers::make_history_entry_json();

        let entry: HistoryEntry = serde_json::from_str(&entry_json).unwrap();
        assert!(!entry.metadata_signatures.entries.is_empty());

        // Round-trip
        let reserialized = serde_json::to_string(&entry).unwrap();
        let deserialized: HistoryEntry = serde_json::from_str(&reserialized).unwrap();

        assert_eq!(
            deserialized.metadata_signatures.entries.len(),
            entry.metadata_signatures.entries.len(),
        );
        assert_eq!(
            serde_json::to_value(&deserialized.metadata).unwrap(),
            serde_json::to_value(&entry.metadata).unwrap(),
        );
        assert_eq!(
            serde_json::to_value(&deserialized.metadata_signatures).unwrap(),
            serde_json::to_value(&entry.metadata_signatures).unwrap(),
        );
    }

    #[test]
    fn forge_origin_retrieval_url_delegates_to_verified_content() {
        let verified = VerifiedForgeContent::new_for_test(
            "https://raw.githubusercontent.com/org/repo/main/signers.json".to_string(),
            "content".to_string(),
        );
        let origin = ForgeOrigin::new(
            Forge::Github,
            "https://github.com/org/repo/blob/main/signers.json".to_string(),
            verified,
            chrono::Utc::now(),
        );
        assert_eq!(
            origin.retrieval_url(),
            "https://raw.githubusercontent.com/org/repo/main/signers.json"
        );
        assert_eq!(
            origin.verified_content().content_hash(),
            "b2d1d285b5199c85f988d03649c37e44fd3dde01e5d69c50fef90651962f48110e9340b60d49a479c4c0b53f5f07d690686dd87d2481937a512e8b85ee7c617f"
        );
    }

    #[test]
    fn forge_origin_url_returns_url() {
        let verified = VerifiedForgeContent::new_for_test(
            "https://raw.example.com/signers.json".to_string(),
            "deadbeef".to_string(),
        );
        let origin = ForgeOrigin::new(
            Forge::Github,
            "https://example.com/signers.json".to_string(),
            verified,
            Utc::now(),
        );
        assert_eq!(origin.url(), "https://example.com/signers.json");
    }

    #[test]
    fn forge_origin_kind_returns_forge() {
        let verified = VerifiedForgeContent::new_for_test(
            "https://raw.gitlab.com/signers.json".to_string(),
            "deadbeef".to_string(),
        );
        let origin = ForgeOrigin::new(
            Forge::Gitlab,
            "https://gitlab.com/signers.json".to_string(),
            verified,
            Utc::now(),
        );
        assert!(matches!(origin.kind(), Forge::Gitlab));
    }

    #[test]
    fn forge_origin_round_trips_through_serde() {
        let verified = VerifiedForgeContent::new_for_test(
            "https://raw.example.com/file.json".to_string(),
            "deadbeef".to_string(),
        );
        let origin = ForgeOrigin::new(
            Forge::Github,
            "https://example.com/file.json".to_string(),
            verified,
            chrono::Utc::now(),
        );
        let json = serde_json::to_string(&origin).unwrap();
        let deserialized: ForgeOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.retrieval_url(), origin.retrieval_url());
        assert_eq!(
            deserialized.verified_content().content_hash(),
            origin.verified_content().content_hash()
        );
    }

    #[test]
    fn signers_config_metadata_origin_returns_origin() {
        let verified = VerifiedForgeContent::new_for_test(
            "https://raw.example.com/s.json".to_string(),
            "hash".to_string(),
        );
        let forge = ForgeOrigin::new(
            Forge::Github,
            "https://example.com".to_string(),
            verified,
            Utc::now(),
        );
        let metadata = SignersConfigMetadata::from_forge(forge.clone());
        match metadata.origin() {
            SignersConfigOrigin::Forge(f) => {
                assert_eq!(f.url(), forge.url());
            }
        }
    }

    #[test]
    fn verified_forge_content_accessors_return_stored_values() {
        let content = VerifiedForgeContent::new_for_test(
            "https://raw.githubusercontent.com/org/repo/main/signers.json".to_string(),
            "abcdef1234567890".to_string(),
        );
        assert_eq!(
            content.retrieval_url(),
            "https://raw.githubusercontent.com/org/repo/main/signers.json"
        );
        assert_eq!(
            content.content_hash(),
            "0332ea992739e7467276716cb5f013dadb207d06a09daa43561a053e3758283efd04d4ed07d5c7bf465c3477a99846de71ebd7cc87bd1f6cc7bdaa68b8f59874"
        );
    }

    #[test]
    fn verified_forge_content_round_trips_through_serde() {
        let content = VerifiedForgeContent::new_for_test(
            "https://raw.githubusercontent.com/org/repo/main/signers.json".to_string(),
            "abc123".to_string(),
        );
        let json = serde_json::to_string(&content).unwrap();
        let deserialized: VerifiedForgeContent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.retrieval_url(), content.retrieval_url());
        assert_eq!(deserialized.content_hash(), content.content_hash());
    }

    #[test]
    fn verified_forge_content_requires_both_fields_for_deserialization() {
        let json_missing_hash = r#"{"retrieval_url":"https://example.com"}"#;
        let result: Result<VerifiedForgeContent, _> = serde_json::from_str(json_missing_hash);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verified_forge_content_new_stores_content() {
        let mut server = mockito::Server::new_async().await;
        let body = "test content for hashing";
        let mock = server
            .mock("GET", "/test-file")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let url = format!("{}/test-file", server.url());
        let verified = VerifiedForgeContent::new(url.clone()).await.unwrap();
        // content() returns cached content without re-fetching
        assert_eq!(verified.content().await.unwrap(), body);
        mock.assert();
    }

    #[test]
    fn verified_forge_content_content_not_serialized() {
        let v = VerifiedForgeContent::new_for_test(
            "https://example.com".to_string(),
            "some content".to_string(),
        );
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            !json.contains("some content"),
            "content should not appear in serialized JSON"
        );
        assert!(
            !json.contains("\"content\""),
            "content field should be skipped"
        );
    }

    #[tokio::test]
    async fn verified_forge_content_content_refetches_after_deserialization() {
        let mut server = mockito::Server::new_async().await;
        let body = "refetched content";
        let mock = server
            .mock("GET", "/refetch")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let url = format!("{}/refetch", server.url());
        let original = VerifiedForgeContent::new_for_test(url.clone(), body.to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: VerifiedForgeContent = serde_json::from_str(&json).unwrap();

        // content() on deserialized instance re-fetches
        let fetched = deserialized.content().await.unwrap();
        assert_eq!(fetched, body);
        mock.assert();
    }

    #[tokio::test]
    async fn verified_forge_content_new_fetches_and_hashes() {
        let mut server = mockito::Server::new_async().await;
        let content = "test content for hashing";
        let mock = server
            .mock("GET", "/test-file")
            .with_status(200)
            .with_body(content)
            .create_async()
            .await;

        let url = format!("{}/test-file", server.url());
        let verified = VerifiedForgeContent::new(url.clone()).await.unwrap();

        assert_eq!(verified.retrieval_url(), url);
        // Verify hash matches what we'd compute manually
        let expected_hash = common::sha512_for_content(content.as_bytes().to_vec()).unwrap();
        assert_eq!(verified.content_hash(), expected_hash.to_hex());

        mock.assert();
    }

    #[tokio::test]
    async fn verified_forge_content_new_returns_error_on_http_failure() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/missing")
            .with_status(404)
            .create_async()
            .await;

        let url = format!("{}/missing", server.url());
        let result = VerifiedForgeContent::new(url).await;
        assert!(result.is_err());
        assert!(
            matches!(
                result.as_ref().unwrap_err(),
                VerifiedForgeContentError::FetchError(_)
            ),
            "Expected FetchError, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn all_signer_keys_includes_revocation_keys() {
        let keys = test_helpers::TestKeys::new(4);
        let config = SignersConfig::with_keys(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
            Some((vec![keys.pub_key(1).unwrap().clone()], 1)),
            Some((vec![keys.pub_key(2).unwrap().clone()], 1)),
            Some((vec![keys.pub_key(3).unwrap().clone()], 1)),
        )
        .unwrap();

        let all_keys = config.all_signer_keys();
        assert!(
            all_keys.contains(keys.pub_key(0).unwrap()),
            "should contain artifact key"
        );
        assert!(
            all_keys.contains(keys.pub_key(1).unwrap()),
            "should contain admin key"
        );
        assert!(
            all_keys.contains(keys.pub_key(2).unwrap()),
            "should contain master key"
        );
        assert!(
            all_keys.contains(keys.pub_key(3).unwrap()),
            "should contain revocation key"
        );
        assert_eq!(all_keys.len(), 4);
    }
}
