pub mod checksums_parser;
pub mod errors;
pub mod fs;
pub mod http;
pub mod index_types;
pub mod index_validation;

use constants::{
    METADATA_SUFFIX, PENDING_REVOCATION_SUFFIX, PENDING_SIGNERS_DIR, PENDING_SUFFIX,
    REVOCATION_SUFFIX, SIGNERS_DIR, SIGNERS_FILE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512, digest::typenum};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::fs::names::{find_global_signers_for, has_revocation_file};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum AsfaloadHashes {
    Sha512(sha2::digest::generic_array::GenericArray<u8, typenum::consts::U64>),
}

impl fmt::Display for AsfaloadHashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, bytes) = match self {
            Self::Sha512(b) => ("sha512", b.as_slice()),
        };
        write!(f, "{}:{}", prefix, hex::encode(bytes))
    }
}

// Required by #[serde(into = "String")]
impl From<AsfaloadHashes> for String {
    fn from(hash: AsfaloadHashes) -> Self {
        hash.to_string()
    }
}
// --- 2. Deserialization Logic (String -> Enum) ---

// This parses "algo:hex" back into the Enum
impl FromStr for AsfaloadHashes {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split into "algo" and "hash"
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("Invalid format. Expected 'algo:hex_string'".to_string());
        }

        let algo = parts[0].to_lowercase();
        let hex_val = parts[1];

        let bytes = hex::decode(hex_val).map_err(|_| "Invalid hex string".to_string())?;

        match algo.as_str() {
            "sha512" => {
                if bytes.len() != 64 {
                    return Err("SHA512 must be 64 bytes".to_string());
                }
                Ok(Self::Sha512(
                    *sha2::digest::generic_array::GenericArray::from_slice(&bytes),
                ))
            }
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }
    }
}

// Required by #[serde(try_from = "String")]
impl TryFrom<String> for AsfaloadHashes {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        AsfaloadHashes::from_str(&s)
    }
}

impl AsfaloadHashes {
    pub fn to_hex(&self) -> String {
        match self {
            AsfaloadHashes::Sha512(digest) => digest.iter().map(|b| format!("{:02x}", b)).collect(),
        }
    }
}

/// Serialize `value` as pretty JSON terminated by exactly one '\n'.
///
/// For content we AUTHOR. Never call on bytes received from a forge or another
/// party — those must be stored and hashed verbatim (their exact bytes are
/// signed and trust-anchor-compared).
pub fn to_posix_json<T: serde::Serialize>(value: &T) -> serde_json::Result<String> {
    let mut s = serde_json::to_string_pretty(value)?;
    s.truncate(s.trim_end_matches('\n').len());
    s.push('\n');
    Ok(s)
}

pub fn sha512_for_content<T: std::borrow::Borrow<[u8]>>(
    content_in: T,
) -> Result<AsfaloadHashes, std::io::Error> {
    let content = content_in.borrow();
    if content.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ))
    } else {
        Ok(AsfaloadHashes::Sha512(Sha512::digest(content)))
    }
}

pub fn sha512_for_file<P: AsRef<Path>>(path_in: P) -> Result<AsfaloadHashes, std::io::Error> {
    let mut file = File::open(path_in.as_ref())?;
    let mut hasher = Sha512::new();
    let bytes_copied = std::io::copy(&mut file, &mut hasher)?;
    if bytes_copied == 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ))
    } else {
        let result = hasher.finalize();
        Ok(AsfaloadHashes::Sha512(result))
    }
}
pub async fn sha512_for_url(url_in: url::Url) -> Result<AsfaloadHashes, std::io::Error> {
    let io_err = |e: reqwest::Error| std::io::Error::other(e.to_string());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(io_err)?;

    let mut response = client.get(url_in.as_str()).send().await.map_err(io_err)?;

    if !response.status().is_success() {
        return Err(std::io::Error::other(format!(
            "HTTP {}: {}",
            response.status(),
            url_in
        )));
    }

    let mut hasher = Sha512::new();
    let mut bytes_hashed: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(io_err)? {
        hasher.update(&chunk);
        bytes_hashed += chunk.len() as u64;
    }

    if bytes_hashed == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ));
    }

    Ok(AsfaloadHashes::Sha512(hasher.finalize()))
}

// We distincuish 3 types of signed files, which have different criteria
// used to determine if their signature is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Artifact,
    Signers,
    InitialSigners,
    Revocation,
    RevokedArtifact,
    Metadata,
}

impl Display for FileType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            FileType::Artifact => write!(f, "Artifact"),
            FileType::Signers => write!(f, "Signers"),
            FileType::InitialSigners => write!(f, "InitialSigners"),
            FileType::Revocation => write!(f, "Revocation"),
            FileType::RevokedArtifact => write!(f, "RevokedArtifact"),
            FileType::Metadata => write!(f, "Metadata"),
        }
    }
}
pub fn has_revocation_suffix<P: AsRef<Path>>(path_in: P) -> bool {
    let Some(file_name) = path_in.as_ref().file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    let revocation_pending = format!("{}.{}", REVOCATION_SUFFIX, PENDING_SUFFIX);
    (file_name.ends_with(REVOCATION_SUFFIX) || file_name.ends_with(&revocation_pending))
        && file_name != REVOCATION_SUFFIX
        && file_name != revocation_pending
}
pub fn determine_file_type<P: AsRef<Path>>(file_path: P) -> Result<FileType, std::io::Error> {
    let path = file_path.as_ref();
    // Return immediately if we identify a revocation file
    if has_revocation_suffix(path) {
        return Ok(FileType::Revocation);
    }

    // Check for metadata files — generic, not restricted to signers dirs
    let dot_metadata_suffix = format!(".{}", METADATA_SUFFIX);
    if let Some(file_name) = path.file_name().and_then(|f| f.to_str())
        && file_name.ends_with(&dot_metadata_suffix)
        && file_name != dot_metadata_suffix
    {
        return Ok(FileType::Metadata);
    }

    let global_signers = find_global_signers_for(file_path.as_ref());
    let is_in_signers_dir = path
        .parent()
        .and_then(|dir| dir.file_name())
        .is_some_and(|name| name == SIGNERS_DIR || name == PENDING_SIGNERS_DIR);
    let is_signers_file = path.file_name().is_some_and(|fname| fname == SIGNERS_FILE);

    // Signers file if {SIGNERS_DIR}/{SIGNERSFILE}
    match (is_in_signers_dir, is_signers_file, global_signers) {
        (true, true, Err(_)) => Ok(FileType::InitialSigners),
        (true, true, Ok(_)) => Ok(FileType::Signers),
        (_, _, _) => match has_revocation_file(path) {
            Ok(true) => Ok(FileType::RevokedArtifact),
            Ok(false) => Ok(FileType::Artifact),
            Err(e) => Err(e),
        },
    }
}

// This represents a file signed by our multisig approach.
// The digest is an Option, to be filled lazily
// We use a marker type indicating the kind of file it is.
#[derive(Clone)]
pub struct SignedFile<T> {
    pub location: String,
    pub digest: Option<AsfaloadHashes>,
    marker: PhantomData<T>,
}

impl<T> SignedFile<T> {
    pub fn new(location: String, digest: Option<AsfaloadHashes>) -> Self {
        SignedFile {
            location,
            digest,
            marker: PhantomData,
        }
    }
}
impl<T> AsRef<Path> for SignedFile<T> {
    fn as_ref(&self) -> &Path {
        self.location.as_ref()
    }
}

// The SignedFile marker types
#[derive(Clone)]
pub struct InitialSignersFileMarker;
#[derive(Clone)]
pub struct SignersFileMarker;
#[derive(Clone)]
pub struct ArtifactMarker;
#[derive(Clone)]
pub struct RevocationMarker;
#[derive(Clone)]
pub struct RevokedArtifactMarker;
#[derive(Clone)]
pub struct MetadataFileMarker;

// As we have marker types on the SignedFile, we need a DU type to be able to have
// one function creating a SignedFile (ortherwise we would need one loader function
// per marker type)
#[derive(Clone)]
pub enum SignedFileWithKind {
    InitialSignersFile(SignedFile<InitialSignersFileMarker>),
    SignersFile(SignedFile<SignersFileMarker>),
    Artifact(SignedFile<ArtifactMarker>),
    Revocation(SignedFile<RevocationMarker>),
    RevokedArtifact(SignedFile<RevokedArtifactMarker>),
    Metadata(SignedFile<MetadataFileMarker>),
}

impl SignedFileWithKind {
    // Functions to extract the wrapped SignedFile.
    pub fn get_initial_signers(&self) -> Option<&SignedFile<InitialSignersFileMarker>> {
        match self {
            SignedFileWithKind::InitialSignersFile(f) => Some(f),
            _ => None,
        }
    }
    pub fn get_signers(&self) -> Option<&SignedFile<SignersFileMarker>> {
        match self {
            SignedFileWithKind::SignersFile(f) => Some(f),
            _ => None,
        }
    }
    pub fn get_artifact(&self) -> Option<&SignedFile<ArtifactMarker>> {
        match self {
            SignedFileWithKind::Artifact(f) => Some(f),
            _ => None,
        }
    }
    pub fn get_revoked_artifact(&self) -> Option<&SignedFile<RevokedArtifactMarker>> {
        match self {
            SignedFileWithKind::RevokedArtifact(f) => Some(f),
            _ => None,
        }
    }
    pub fn get_metadata(&self) -> Option<&SignedFile<MetadataFileMarker>> {
        match self {
            SignedFileWithKind::Metadata(f) => Some(f),
            _ => None,
        }
    }

    // Function to extract info from the wrapped SignedFile without
    // requiring the caller to unwrap it.
    pub fn location(&self) -> String {
        match self {
            SignedFileWithKind::InitialSignersFile(f) => f.location.clone(),
            SignedFileWithKind::SignersFile(f) => f.location.clone(),
            SignedFileWithKind::Artifact(f) => f.location.clone(),
            SignedFileWithKind::Revocation(f) => f.location.clone(),
            SignedFileWithKind::RevokedArtifact(f) => f.location.clone(),
            SignedFileWithKind::Metadata(f) => f.location.clone(),
        }
    }

    pub fn kind(&self) -> FileType {
        match self {
            SignedFileWithKind::InitialSignersFile(_) => FileType::InitialSigners,
            SignedFileWithKind::SignersFile(_) => FileType::Signers,
            SignedFileWithKind::Artifact(_) => FileType::Artifact,
            SignedFileWithKind::Revocation(_) => FileType::Revocation,
            SignedFileWithKind::RevokedArtifact(_) => FileType::RevokedArtifact,
            SignedFileWithKind::Metadata(_) => FileType::Metadata,
        }
    }

    // Functions to test the kind of SignedFile that is wrapped
    pub fn is_initial_signers(&self) -> bool {
        matches!(self, SignedFileWithKind::InitialSignersFile(_))
    }
    pub fn is_signers(&self) -> bool {
        matches!(self, SignedFileWithKind::SignersFile(_))
    }
    pub fn is_artifact(&self) -> bool {
        matches!(self, SignedFileWithKind::Artifact(_))
    }
    pub fn is_revocation(&self) -> bool {
        matches!(self, SignedFileWithKind::Revocation(_))
    }
    pub fn is_metadata(&self) -> bool {
        matches!(self, SignedFileWithKind::Metadata(_))
    }
    pub fn artifact_path_for_revocation(&self) -> Result<PathBuf, std::io::Error> {
        match self {
            SignedFileWithKind::Revocation(rev) => {
                let path = PathBuf::from(&rev.location);
                let file_name = path.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Revocation file has no filename",
                    )
                })?;
                let name = file_name.to_string_lossy();
                let artifact_name: &str = name
                    .strip_suffix(REVOCATION_SUFFIX)
                    .and_then(|s: &str| s.strip_suffix("."))
                    .or_else(|| {
                        name.strip_suffix(PENDING_REVOCATION_SUFFIX)
                            .and_then(|s: &str| s.strip_suffix("."))
                    })
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Revocation file has invalid suffix",
                        )
                    })?;
                let mut artifact_path = path.clone();
                artifact_path.set_file_name(artifact_name);
                Ok(artifact_path)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Not a revocation file",
            )),
        }
    }
}

// Allows us to use the SignedFileWithKind as the wrapped SignedFile's location for a Path.
impl AsRef<Path> for SignedFileWithKind {
    fn as_ref(&self) -> &Path {
        match self {
            SignedFileWithKind::InitialSignersFile(f) => f.location.as_ref(),
            SignedFileWithKind::SignersFile(f) => f.location.as_ref(),
            SignedFileWithKind::Artifact(f) => f.location.as_ref(),
            SignedFileWithKind::Revocation(f) => f.location.as_ref(),
            SignedFileWithKind::RevokedArtifact(f) => f.location.as_ref(),
            SignedFileWithKind::Metadata(f) => f.location.as_ref(),
        }
    }
}

// Structure giving access to the loader SignedFile loader, which is returned wrapped in the enum
// SignedFileWithKind.
pub struct SignedFileLoader();
impl SignedFileLoader {
    // This simply builds the record and wrapts is in the enum according to its kind.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<SignedFileWithKind, std::io::Error> {
        let file_type = determine_file_type(&path)?;
        match file_type {
            FileType::InitialSigners => Ok(SignedFileWithKind::InitialSignersFile(SignedFile::<
                InitialSignersFileMarker,
            > {
                location: path.as_ref().to_string_lossy().to_string(),
                digest: None,
                marker: PhantomData,
            })),
            FileType::Signers => Ok(SignedFileWithKind::SignersFile(SignedFile::<
                SignersFileMarker,
            > {
                location: path.as_ref().to_string_lossy().to_string(),
                digest: None,
                marker: PhantomData,
            })),
            FileType::Artifact => Ok(SignedFileWithKind::Artifact(SignedFile::<ArtifactMarker> {
                location: path.as_ref().to_string_lossy().to_string(),
                digest: None,
                marker: PhantomData,
            })),
            FileType::Revocation => Ok(SignedFileWithKind::Revocation(SignedFile::<
                RevocationMarker,
            > {
                location: path.as_ref().to_string_lossy().to_string(),
                digest: None,
                marker: PhantomData,
            })),
            FileType::RevokedArtifact => Ok(SignedFileWithKind::RevokedArtifact(SignedFile::<
                RevokedArtifactMarker,
            > {
                location: path.as_ref().to_string_lossy().to_string(),
                digest: None,
                marker: PhantomData,
            })),
            FileType::Metadata => Ok(SignedFileWithKind::Metadata(SignedFile::<
                MetadataFileMarker,
            > {
                location: path.as_ref().to_string_lossy().to_string(),
                digest: None,
                marker: PhantomData,
            })),
        }
    }
}

#[cfg(test)]
mod asfaload_common_tests {
    use super::*;
    use anyhow::Result;
    use sha2::{Digest, Sha512};
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use tempfile::{NamedTempFile, TempDir};
    use test_helpers::scenarios::setup_asfald_project_registered;

    #[test]
    fn test_sha512_for_content() -> Result<()> {
        // Test with empty content
        let empty_content = Vec::new();
        let hash = sha512_for_content(empty_content);
        match hash {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {} //expected
            _ => panic!("Computing sha of empty value should be an error"),
        }

        // Test with known content
        let content = b"hello world";
        let hash = sha512_for_content(content.to_vec())?;
        let expected = Sha512::digest(content);
        match hash {
            AsfaloadHashes::Sha512(h) => assert_eq!(h, expected),
        }
        Ok(())
    }

    #[test]
    fn test_sha512_for_nonexistent_file() {
        let result = sha512_for_file(Path::new("nonexistent_file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sha512_for_file() -> Result<(), Box<dyn std::error::Error>> {
        // Test without looking at the sha computed
        let temp_file = NamedTempFile::new()?;
        let content = b"hello world";
        std::fs::write(temp_file.path(), content)?;

        // Compute hash for the file
        let hash = sha512_for_file(temp_file.path())?;
        let expected = Sha512::digest(content);
        match hash {
            AsfaloadHashes::Sha512(h) => assert_eq!(h, expected),
        }

        // Test by validating we always get the exepcted sha value.
        // The fist test might pass but compute the value ortherwise and still pass
        // (eg if it first appends "\n" to the content).
        // Here we validate it still works for previously computed shas.
        let mut temp_file = NamedTempFile::new()?;
        let content = b"hello world";
        temp_file.write_all(content)?;
        temp_file.flush()?;

        let hash = sha512_for_file(temp_file.path())?;
        match hash {
            AsfaloadHashes::Sha512(_) => {
                let expected = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
                assert_eq!(hash.to_hex(), expected);
            }
        }

        // An empty file causes an error
        let temp_file = NamedTempFile::new()?;
        let hash = sha512_for_file(temp_file.path());
        match hash {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {} //expected
            _ => panic!("Computing sha of empty value should be an error"),
        }

        Ok(())
    }

    #[test]
    fn test_determine_file_type_github_hierarchy() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pending_index_file = setup_asfald_project_registered(temp_dir.path(), "{}")?;
        // This should be InitialSigners because there's NO asfaload.signers dir
        // in asfald/ or any parent directory
        assert_eq!(
            determine_file_type(&pending_index_file)?,
            FileType::InitialSigners,
            "Pending signers file in github.com/asfaload/asfald/ with no \
             asfaload.signers directory should be InitialSigners"
        );
        Ok(())
    }

    #[test]
    fn test_determine_file_type() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        //  Regular file (should be Artifact)
        let regular_file = temp_path.join("regular_file.txt");
        fs::write(&regular_file, "content").unwrap();
        assert_eq!(determine_file_type(&regular_file)?, FileType::Artifact);

        //  File in a regular directory (should be Artifact)
        let regular_dir = temp_path.join("regular_dir");
        fs::create_dir(&regular_dir).unwrap();
        let file_in_regular_dir = regular_dir.join("some_file.json");
        fs::write(&file_in_regular_dir, "content").unwrap();
        assert_eq!(
            determine_file_type(&file_in_regular_dir)?,
            FileType::Artifact
        );

        //  File in "asfaload.signers.pending" but not named "index.json" (should be Artifact)
        let pending_signers_dir = temp_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir(&pending_signers_dir).unwrap();
        let other_file = pending_signers_dir.join("other_file.json");
        fs::write(&other_file, "content").unwrap();
        assert_eq!(determine_file_type(&other_file)?, FileType::Artifact);

        //  File named "index.json" but not in "asfaload.signers.pending" (should be Artifact)
        let index_in_regular_dir = regular_dir.join(SIGNERS_FILE);
        fs::write(&index_in_regular_dir, "content").unwrap();
        assert_eq!(
            determine_file_type(&index_in_regular_dir)?,
            FileType::Artifact
        );

        //  File named "index.json" in "asfaload.signers.pending" (should be Signers)
        let index_file = pending_signers_dir.join(SIGNERS_FILE);
        fs::write(&index_file, "content").unwrap();
        assert_eq!(determine_file_type(&index_file)?, FileType::InitialSigners);

        //  Nested "asfaload.signers.pending" directory (should still work)
        let nested_dir = temp_path.join("nested").join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&nested_dir).unwrap();
        let nested_index = nested_dir.join(SIGNERS_FILE);
        fs::write(&nested_index, "content").unwrap();
        assert_eq!(
            determine_file_type(&nested_index)?,
            FileType::InitialSigners
        );

        //  Directory named similarly but not exactly "asfaload.signers.pending" (should be Artifact)
        let similar_dir = temp_path.join(format!("{}.{}", PENDING_SIGNERS_DIR, "backup"));
        fs::create_dir(&similar_dir).unwrap();
        let similar_index = similar_dir.join(SIGNERS_FILE);
        fs::write(&similar_index, "content").unwrap();
        assert_eq!(determine_file_type(&similar_index)?, FileType::Artifact);

        //  Case sensitivity check (should be Artifact since exact match is required)
        let case_dir = temp_path.join(PENDING_SIGNERS_DIR.to_uppercase());
        fs::create_dir(&case_dir).unwrap();
        let case_index = case_dir.join(SIGNERS_FILE);
        fs::write(&case_index, "content").unwrap();
        assert_eq!(determine_file_type(&case_index)?, FileType::Artifact);

        //  File named "INDEX.JSON" (uppercase) in "asfaload.signers.pending" (should be Artifact)
        let upper_index = pending_signers_dir.join("INDEX.JSON");
        fs::write(&upper_index, "content").unwrap();
        assert_eq!(determine_file_type(&upper_index)?, FileType::Artifact);

        // Create a current signers file, and validate that tests that
        // previously returned initial signers now return signers.
        let current_signers_dir = temp_path.join(SIGNERS_DIR);
        fs::create_dir(&current_signers_dir).unwrap();
        let file_in_regular_dir = current_signers_dir.join("index.json");
        fs::write(
            &file_in_regular_dir,
            "dummy signers content ok as only presence is checked",
        )
        .unwrap();

        //  File named "index.json" in "asfaload.signers.pending" (should be Signers)
        let index_file = pending_signers_dir.join(SIGNERS_FILE);
        fs::write(&index_file, "content").unwrap();
        assert_eq!(determine_file_type(&index_file)?, FileType::Signers);

        //  Nested "asfaload.signers.pending" directory (should still work)
        let nested_dir = temp_path.join("nested").join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&nested_dir).unwrap();
        let nested_index = nested_dir.join(SIGNERS_FILE);
        fs::write(&nested_index, "content").unwrap();
        assert_eq!(determine_file_type(&nested_index)?, FileType::Signers);
        Ok(())
    }

    #[test]
    fn test_determine_file_type_revocation() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // A revocation file: "artifact.revocation.json" → Revocation
        let revocation_file = temp_path.join(format!("my_binary.{}", constants::REVOCATION_SUFFIX));
        fs::write(&revocation_file, "content").unwrap();
        assert_eq!(determine_file_type(&revocation_file)?, FileType::Revocation);

        // A pending revocation file: "artifact.revocation.json.pending" → Revocation
        let pending_revocation = temp_path.join(format!(
            "my_binary.{}.{}",
            constants::REVOCATION_SUFFIX,
            constants::PENDING_SUFFIX,
        ));
        fs::write(&pending_revocation, "content").unwrap();
        assert_eq!(
            determine_file_type(&pending_revocation)?,
            FileType::Revocation
        );

        // A revocation file inside a signers directory is still Revocation
        // (revocation check takes priority over signers-dir check)
        let signers_dir = temp_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let revocation_in_signers =
            signers_dir.join(format!("artifact.{}", constants::REVOCATION_SUFFIX));
        fs::write(&revocation_in_signers, "content").unwrap();
        assert_eq!(
            determine_file_type(&revocation_in_signers)?,
            FileType::Revocation
        );

        // Bare "revocation.json" (no prefix) is NOT a revocation file → Artifact
        let bare_revocation = temp_path.join(constants::REVOCATION_SUFFIX);
        fs::write(&bare_revocation, "content").unwrap();
        assert_eq!(determine_file_type(&bare_revocation)?, FileType::Artifact);
        Ok(())
    }

    #[test]
    fn test_determine_file_type_revoked_artifact() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create an artifact file
        let artifact_path = temp_path.join("my_binary.bin");
        fs::write(&artifact_path, "artifact content").unwrap();

        // Initially, it's an Artifact
        assert_eq!(determine_file_type(&artifact_path)?, FileType::Artifact);

        // Create a revocation file for the artifact
        let revocation_file =
            temp_path.join(format!("my_binary.bin.{}", constants::REVOCATION_SUFFIX));
        fs::write(&revocation_file, r#"{"revoked": true}"#).unwrap();

        // Now it should be RevokedArtifact
        assert_eq!(
            determine_file_type(&artifact_path)?,
            FileType::RevokedArtifact
        );
        Ok(())
    }

    #[test]
    fn test_determine_file_type_revoked_artifact_in_subdirectory() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create subdirectory structure
        let subdir = temp_path.join("releases");
        fs::create_dir(&subdir).unwrap();

        // Create artifact in subdirectory
        let artifact_path = subdir.join("release.tar.gz");
        fs::write(&artifact_path, "release content").unwrap();

        // Create revocation file
        let revocation_file =
            subdir.join(format!("release.tar.gz.{}", constants::REVOCATION_SUFFIX));
        fs::write(&revocation_file, r#"{"revoked": true}"#).unwrap();

        assert_eq!(
            determine_file_type(&artifact_path)?,
            FileType::RevokedArtifact
        );
        Ok(())
    }

    #[test]
    fn test_determine_file_type_pending_revocation_is_still_artifact() -> Result<()> {
        // A pending revocation should NOT make the file RevokedArtifact
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create an artifact file
        let artifact_path = temp_path.join("my_binary.bin");
        fs::write(&artifact_path, "artifact content").unwrap();

        // Create a PENDING revocation file (not complete)
        let pending_revocation = temp_path.join(format!(
            "my_binary.bin.{}.{}",
            constants::REVOCATION_SUFFIX,
            constants::PENDING_SUFFIX
        ));
        fs::write(&pending_revocation, r#"{"revoked": true}"#).unwrap();

        // Should still be Artifact (only complete revocations block)
        assert_eq!(determine_file_type(&artifact_path)?, FileType::Artifact);
        Ok(())
    }

    #[test]
    fn test_determine_file_type_metadata_in_pending_signers_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;

        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&signers_file_path, r#"{"timestamp": 1}"#)?;

        let metadata_path = crate::fs::names::metadata_path_for(&signers_file_path)?;
        std::fs::write(&metadata_path, r#"{"origin": "test"}"#)?;

        let file_type = determine_file_type(&metadata_path)?;
        assert_eq!(file_type, FileType::Metadata);

        Ok(())
    }

    #[test]
    fn test_determine_file_type_metadata_in_arbitrary_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let subdir = temp_dir.path().join("some").join("nested").join("dir");
        std::fs::create_dir_all(&subdir)?;

        let file_path = subdir.join("report.json");
        std::fs::write(&file_path, r#"{"data": true}"#)?;

        let metadata_path = crate::fs::names::metadata_path_for(&file_path)?;
        std::fs::write(&metadata_path, r#"{"origin": "test"}"#)?;

        let file_type = determine_file_type(&metadata_path)?;
        assert_eq!(file_type, FileType::Metadata);

        Ok(())
    }

    // AsfaloadHashes serde
    use sha2::digest::generic_array::GenericArray;
    use sha2::digest::typenum::consts::U64;

    // --- Helper Functions to generate dummy hashes ---

    fn mock_sha512(fill: u8) -> AsfaloadHashes {
        let mut arr = GenericArray::<u8, U64>::default();
        arr.fill(fill);
        AsfaloadHashes::Sha512(arr)
    }

    // --- Serialization Tests (Enum -> JSON String) ---

    #[test]
    fn test_serialize_sha512_format() {
        // Create a SHA512 hash filled with 0xAA
        let hash = mock_sha512(0xAA);

        let json = serde_json::to_string(&hash).expect("Serialization failed");

        // 0xAA in hex is "aa". 64 bytes of 0xAA string length is 128 chars.
        // Expected format: "sha512:aaaaaaaa..."
        assert!(json.starts_with("\"sha512:"));
        assert!(json.contains("aaaa"));
        assert_eq!(json.len(), 1 + 7 + 128 + 1); // quotes(2) + "sha512:"(7) + hex(128)
    }

    // --- Deserialization Tests (JSON String -> Enum) ---

    #[test]
    fn test_deserialize_sha512_valid() {
        // A valid 64-byte hex string (128 chars) of zeros
        let input_str = "0".repeat(128);
        let json = format!("\"sha512:{}\"", input_str);

        let result: AsfaloadHashes = serde_json::from_str(&json).expect("Deserialization failed");

        match result {
            AsfaloadHashes::Sha512(bytes) => {
                assert_eq!(bytes[0], 0);
                assert_eq!(bytes[63], 0);
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Wrong variant parsed!"),
        }
    }

    #[test]
    fn test_round_trip() {
        // Ensure what goes in comes out exactly the same
        let original = mock_sha512(0x55);

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: AsfaloadHashes = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    // --- Error Handling Tests ---

    #[test]
    fn test_deserialize_invalid_prefix() {
        // "unknown" is not a supported algorithm
        let json = "\"unknown:000000\"";
        let result: Result<AsfaloadHashes, _> = serde_json::from_str(json);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unsupported hash algorithm"));
    }

    #[test]
    fn test_deserialize_missing_separator() {
        // Missing the ':' separator
        let json = "\"sha512abcdef\"";
        let result: Result<AsfaloadHashes, _> = serde_json::from_str(json);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid format"));
    }

    #[test]
    fn test_deserialize_bad_length() {
        // Claims to be sha512, but provides only 4 hex chars (2 bytes)
        let json = "\"sha512:ffff\"";
        let result: Result<AsfaloadHashes, _> = serde_json::from_str(json);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("SHA512 must be 64 bytes"));
    }

    #[test]
    fn test_deserialize_invalid_hex() {
        // Contains 'z', which is not valid hex
        let json = "\"sha512:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"";
        let result: Result<AsfaloadHashes, _> = serde_json::from_str(json);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid hex string")
        );
    }

    // --- has_revocation_suffix tests ---

    #[test]
    fn test_has_revocation_suffix_standalone_no_match() {
        // Exactly "revocation.json" is not a revocation file — it needs a prefix
        let s = format!("/repo/{}", REVOCATION_SUFFIX);
        let path = Path::new(&s);
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_standalone_pending_no_match() {
        // Exactly "revocation.json.pending" is not a revocation file
        let s = format!("/repo/{}.{}", REVOCATION_SUFFIX, PENDING_SUFFIX);
        let path = Path::new(&s);
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_bare_suffix_no_match() {
        let path = Path::new(REVOCATION_SUFFIX);
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_bare_pending_suffix_no_match() {
        let s = format!("{}.{}", REVOCATION_SUFFIX, PENDING_SUFFIX);
        let path = Path::new(&s);
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_dotted_filename() {
        // "artifact.revocation.json" — typical revocation file produced by revocation_path_for
        let s = format!("/repo/artifact.{}", REVOCATION_SUFFIX);
        let path = Path::new(&s);
        assert!(has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_dotted_pending() {
        let s = format!("/repo/artifact.{}.{}", REVOCATION_SUFFIX, PENDING_SUFFIX);
        let path = Path::new(&s);
        assert!(has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_plain_file() {
        let path = Path::new("/repo/some_file.txt");
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_signatures_file() {
        let path = Path::new("/repo/some_file.signatures.json");
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_partial_match_no_match() {
        // "revocation" alone is not the full suffix
        let path = Path::new("/repo/file.revocation");
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_has_revocation_suffix_signers_file_no_match() {
        let s = format!("/repo/{}/{}", SIGNERS_DIR, SIGNERS_FILE);
        let path = Path::new(&s);
        assert!(!has_revocation_suffix(path));
    }

    #[test]
    fn test_deserialize_case_insensitivity() {
        // Algorithm prefix should ideally be case-insensitive (our impl converts to lowercase)
        // Hex content handles mixed case via the `hex` crate automatically.
        let json = "\"SHA512:6c1ec408e1814783c405a01486c1ee439a5e567ce992b5e8077a41583df26ac9f50aa178d05c6bbdc6ccf40761aa1741d652d48c02b446f06b4aa9f3e73b5b6f\"";
        let result: AsfaloadHashes =
            serde_json::from_str(json).expect("Should parse uppercase algo");

        let AsfaloadHashes::Sha512(bytes) = result;
        assert_eq!(bytes[0], 0x6c);
    }

    #[test]
    fn asfaload_hashes_to_hex_produces_128_char_hex_string() {
        let hash = sha512_for_content(b"test data".to_vec()).unwrap();
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 128, "SHA-512 hex should be 128 characters");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn asfaload_hashes_to_hex_is_deterministic() {
        let hash1 = sha512_for_content(b"message".to_vec()).unwrap();
        let hash2 = sha512_for_content(b"message".to_vec()).unwrap();
        assert_eq!(hash1.to_hex(), hash2.to_hex());
    }

    #[test]
    fn to_posix_json_pretty_with_single_trailing_newline() {
        #[derive(serde::Serialize)]
        struct Sample {
            a: u32,
            b: u32,
        }
        let s = super::to_posix_json(&Sample { a: 1, b: 2 }).unwrap();
        // exactly one trailing newline
        assert!(s.ends_with("}\n"));
        assert!(!s.ends_with("\n\n"));
        // pretty format preserved (multi-line, indented)
        assert!(s.contains("\n  \"a\": 1"));
    }
}

#[cfg(test)]
mod sha512_for_url_tests {
    use super::*;

    #[tokio::test]
    async fn sha512_for_url_matches_sha512_for_content() {
        let content = b"hello from url";
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/file")
            .with_status(200)
            .with_body(content.as_ref())
            .create_async()
            .await;

        let url = url::Url::parse(&format!("{}/file", server.url())).unwrap();
        let hash = sha512_for_url(url).await.unwrap();
        let expected = sha512_for_content(content.as_ref()).unwrap();
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn sha512_for_url_errors_on_http_failure() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/file")
            .with_status(500)
            .with_body("internal error")
            .create_async()
            .await;

        let url = url::Url::parse(&format!("{}/file", server.url())).unwrap();
        let result = sha512_for_url(url).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("500"));
    }

    #[tokio::test]
    async fn sha512_for_url_errors_on_empty_body() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/empty")
            .with_status(200)
            .with_body("")
            .create_async()
            .await;

        let url = url::Url::parse(&format!("{}/empty", server.url())).unwrap();
        let result = sha512_for_url(url).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
