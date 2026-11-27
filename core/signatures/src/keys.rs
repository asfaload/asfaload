pub mod asfaload;

const OPENSSH_PRIVATE_KEY_PEM_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
use std::path::{Path, PathBuf};

use common::errors::keys::{SignError, SignatureError, VerifyError, append_pub_extension};
use common::{AsfaloadHashes, errors::keys::KeyError};

/// True when `head` starts with the marker of a secret key of a supported format (no I/O).
pub fn is_secret_key_head(head: &str) -> bool {
    head.starts_with(asfaload::ASFALOAD_PRIV_PREFIX)
        || head.starts_with(OPENSSH_PRIVATE_KEY_PEM_HEADER)
}

/// True when `head` starts with the marker of a public key of a supported format (no I/O).
pub fn is_public_key_head(head: &str) -> bool {
    head.starts_with(asfaload::ASFALOAD_PUB_PREFIX)
        || head.starts_with(asfaload::SSH_ED25519_PREFIX)
}

/// Resolve secret-key and public-key file paths from a save target,
/// and refuse to overwrite existing files.
///
/// If `path` is an existing directory, uses default names `key` / `key.pub`.
/// Otherwise treats `path` as the secret-key file and appends `.pub` for the public key.
pub(crate) fn resolve_save_paths<T: AsRef<Path>>(p: T) -> Result<(PathBuf, PathBuf), KeyError> {
    let path = p.as_ref();

    let (sk_path, pk_path) = if path.is_dir() {
        (path.join("key"), path.join("key.pub"))
    } else {
        (path.to_path_buf(), append_pub_extension(&p)?)
    };

    if sk_path.exists() || pk_path.exists() {
        return Err(KeyError::NotOverwriting(
            "Refusing to write key to existing file!".to_string(),
        ));
    }

    Ok((sk_path, pk_path))
}
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyFormat {
    Asfaload,
    OpenSsh,
}

impl std::fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyFormat::Asfaload => write!(f, "asfaload"),
            KeyFormat::OpenSsh => write!(f, "openssh"),
        }
    }
}

impl std::str::FromStr for KeyFormat {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "asfaload" => Ok(KeyFormat::Asfaload),
            "openssh" => Ok(KeyFormat::OpenSsh),
            _ => Err(KeyError::ParseError(format!("Unknown key format: {}", s))),
        }
    }
}

impl KeyFormat {
    /// Detect the key format from the first bytes of content (no I/O).
    /// Accepts markers for both private and public keys of any supported format.
    pub fn from_head(head: &str) -> Result<Self, KeyError> {
        use asfaload::{ASFALOAD_PRIV_PREFIX, ASFALOAD_PUB_PREFIX, SSH_ED25519_PREFIX};

        if head.starts_with(ASFALOAD_PRIV_PREFIX) || head.starts_with(ASFALOAD_PUB_PREFIX) {
            Ok(KeyFormat::Asfaload)
        } else if head.starts_with(OPENSSH_PRIVATE_KEY_PEM_HEADER)
            || head.starts_with(SSH_ED25519_PREFIX)
        {
            Ok(KeyFormat::OpenSsh)
        } else {
            Err(KeyError::FormatError(format!(
                "unrecognised key format in input starting with '{}'",
                &head[..head.len().min(32)]
            )))
        }
    }

    /// Detect the key format of a file by inspecting its first-line prefix.
    /// Accepts both private- and public-key files of any supported format.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let head = content.trim_start();
        Self::from_head(head).map_err(|e| {
            KeyError::FormatError(format!(
                "unrecognised key format in {}: {}",
                path.as_ref().display(),
                e
            ))
        })
    }
}

// Trait that we will implement for keypairs we support.
pub trait AsfaloadKeyPairTrait<'a>: Sized {
    type PublicKey;
    type SecretKey;
    fn new(pw: &str) -> Result<Self, KeyError>;
    // If the path is an existing directory, save the secret key in this directory in
    // file named 'key', and public key in 'key.pub'.
    // If the path is an inexisting file in an existing directory, save secret key
    // in this newly created file, and save the public key in the same filename with added suffx
    // '.pub'
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, KeyError>;
    // As we used minisign as the first (and initially only) signing scheme, our proposed API is
    // modelled after it. When we generate a minisign key pair, the private key is encrypted and
    // needs to be decrypted for use.
    // This method returns the decrypted secret key, and thus requires the decryption password as
    // argument.
    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError>;
    fn public_key(&self) -> Self::PublicKey;
}

#[derive(Debug)]
pub struct AsfaloadKeyPair<T> {
    key_pair: T,
}

// This trait should never give access to the private key it manages, as it is non-encrypted
pub trait AsfaloadSecretKeyTrait: Sized {
    type SecretKey;
    type Signature;
    fn sign(&self, data: &common::AsfaloadHashes) -> Result<Self::Signature, SignError>;
    fn from_bytes(data: &[u8]) -> Result<Self, KeyError>;
    /// Parse and decrypt the on-disk textual representation of the secret key.
    fn from_string(s: &str, password: &str) -> Result<Self, KeyError>;
    /// Default impl: read the file, then call `from_string`. Implementors that
    /// need custom I/O (e.g., binary file formats) can override.
    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::from_string(&content, password)
    }
}

// Struct to store a secret key immediately usable.
// This means it holds the non-encrypted secret key.
#[derive(Debug, Clone)]
pub struct AsfaloadSecretKey<K> {
    pub(crate) key: K,
}

// Allows to simply call .into() on a v:K (eg VerifyingKey) to
// get the AsfaloadSecretKey { key: v }
impl<K> From<K> for AsfaloadSecretKey<K> {
    fn from(key: K) -> Self {
        Self { key }
    }
}

pub trait AsfaloadPublicKeyTrait: Sized + Eq + std::hash::Hash + Clone + std::fmt::Debug {
    type Signature: AsfaloadSignatureTrait;
    type KeyType;
    type SecretKeyType;

    fn verify(&self, signature: &Self::Signature, data: &AsfaloadHashes)
    -> Result<(), VerifyError>;
    fn to_base64(&self) -> String;
    fn to_filename(&self) -> String {
        self.to_base64().replace("+", "-").replace("/", "_")
    }
    fn from_filename(n: String) -> Result<Self, KeyError> {
        let b64 = n.replace("-", "+").replace("_", "/");
        Self::from_base64(&b64)
    }
    fn from_bytes(data: &[u8]) -> Result<Self, KeyError>;
    fn from_base64(s: &str) -> Result<Self, KeyError> {
        Self::from_bytes(s.as_bytes())
    }
    fn from_base64_with_format(s: &str, _format: &KeyFormat) -> Result<Self, KeyError> {
        Self::from_base64(s)
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError>;
    fn from_secret_key(sk: &Self::SecretKeyType) -> Result<Self, KeyError>;
    fn key_format(&self) -> KeyFormat;
    fn key(&self) -> Self::KeyType;
}

#[derive(Debug, Clone)]
pub struct AsfaloadPublicKey<K> {
    key: K,
}

// Build a AsfaloadPublicKey<K> simply by calling .into() on
// the value of type K (eg VerifyingKey).
impl<K> From<K> for AsfaloadPublicKey<K> {
    fn from(key: K) -> Self {
        Self { key }
    }
}

impl<K> TryFrom<String> for AsfaloadPublicKey<K>
where
    AsfaloadPublicKey<K>: AsfaloadPublicKeyTrait,
{
    type Error = KeyError;
    fn try_from(value: String) -> Result<AsfaloadPublicKey<K>, KeyError> {
        Self::from_base64(&value)
    }
}

#[derive(Debug, Clone)]
pub struct AsfaloadSignature<S> {
    signature: S,
}

// Build a AsfaloadSignature<S> simply by calling .into() on
// the value of type S.
impl<S> From<S> for AsfaloadSignature<S> {
    fn from(signature: S) -> Self {
        Self { signature }
    }
}
pub trait AsfaloadSignatureTrait: Sized {
    type PublicKeyType: AsfaloadPublicKeyTrait<Signature = Self>;
    fn to_string(&self) -> String;
    fn from_string(s: &str) -> Result<Self, SignatureError>;
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError>;
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError>;

    // As we need to serialise to json, and json does not support multiline strings, we support
    // the serialisation to base64 format.
    fn from_base64(s: &str) -> Result<Self, SignatureError>;
    fn from_base64_with_format(s: &str, _format: &KeyFormat) -> Result<Self, SignatureError> {
        Self::from_base64(s)
    }

    fn to_base64(&self) -> String;
}

#[cfg(test)]
mod key_format_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_is_secret_key_head() {
        let cases = [
            ("asfaload-priv:QVNGQUxPQUQB", true),
            ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk", true),
            (
                "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8",
                false,
            ),
            ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA", false),
            (" asfaload-priv:QVNGQUxPQUQB", false),
            ("some text", false),
            ("", false),
        ];
        for (head, expected) in cases {
            assert_eq!(is_secret_key_head(head), expected, "head {head:?}");
        }
    }

    #[test]
    fn test_is_public_key_head() {
        let cases = [
            (
                "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8",
                true,
            ),
            ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA", true),
            ("asfaload-priv:QVNGQUxPQUQB", false),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk",
                false,
            ),
            (" asfaload-pub:b5S+CxuqICIUn", false),
            ("some text", false),
            ("", false),
        ];
        for (head, expected) in cases {
            assert_eq!(is_public_key_head(head), expected, "head {head:?}");
        }
    }

    #[test]
    fn test_key_format_display() {
        assert_eq!(format!("{}", KeyFormat::Asfaload), "asfaload");
        assert_eq!(format!("{}", KeyFormat::OpenSsh), "openssh");
    }

    #[test]
    fn test_key_format_from_str() {
        assert_eq!(
            KeyFormat::from_str("asfaload").unwrap(),
            KeyFormat::Asfaload
        );
        assert_eq!(KeyFormat::from_str("openssh").unwrap(), KeyFormat::OpenSsh);
    }

    #[test]
    fn test_key_format_from_str_invalid() {
        assert!(KeyFormat::from_str("rsa").is_err());
        assert!(KeyFormat::from_str("ed25519").is_err());
        assert!(KeyFormat::from_str("").is_err());
    }

    #[test]
    fn test_key_format_roundtrip() {
        let formats = [KeyFormat::Asfaload, KeyFormat::OpenSsh];
        for fmt in &formats {
            let s = format!("{}", fmt);
            let parsed = KeyFormat::from_str(&s).unwrap();
            assert_eq!(*fmt, parsed);
        }
    }
    #[test]
    fn test_append_pub_extension() {
        let p = Path::new("/home/asfa/key");
        let buf_with_ext = append_pub_extension(&p).unwrap();
        let with_ext = buf_with_ext.as_path();
        assert_eq!(with_ext.to_str(), Some("/home/asfa/key.pub"));

        // Illustration that the trailing / is dropped. See append_pub_extension comment.
        let p = Path::new("/home/asfa/key/");
        let buf_with_ext = append_pub_extension(&p).unwrap();
        let with_ext = buf_with_ext.as_path();
        assert_eq!(with_ext.to_str(), Some("/home/asfa/key.pub"));
    }
}
