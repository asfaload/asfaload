use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use common::base64_for_string;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSecretKeys, AsfaloadSignatureTrait,
    sha512_for_content,
};
use rest_api_auth::{AuthInfo, AuthSignature};
use rest_api_types::RegisterAssetsPayload;
use rest_api_types::models::GithubReleasePayload;

/// Builds the register-assets payload a client sends for a github release,
/// and the authentication headers covering it.
///
/// The index content and the key that signs it are caller-provided, so e2e
/// tests can submit invalid client data (mismatching index, signature of
/// another key, invalid encodings) with valid authentication, and check the
/// backend rejects them.
///
/// Prints a single json object with the serialized payload and its auth
/// headers, which scripts pass to curl.
#[derive(Parser)]
struct Args {
    /// Secret key authenticating the request; its public key is the client
    /// public key header sent with the request.
    #[arg(long)]
    secret_key: PathBuf,

    /// Password for --secret-key.
    #[arg(long)]
    password: String,

    /// Github release page URL to register.
    #[arg(long)]
    github_release_url: String,

    /// File holding the raw index content: it is base64-encoded and signed.
    #[arg(long, conflicts_with = "index_b64")]
    index_file: Option<PathBuf>,

    /// Base64 index string sent verbatim, for tests needing an index that
    /// does not decode. Mirrors what a broken client would send.
    #[arg(long, conflicts_with = "index_file")]
    index_b64: Option<String>,

    /// Secret key signing the payload index. Defaults to --secret-key: use
    /// another key to simulate an index signed by an unrelated signer.
    #[arg(long)]
    index_signature_key: Option<PathBuf>,

    /// Password for --index-signature-key. Defaults to --password.
    #[arg(long)]
    index_signature_password: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let auth_secret_key = AsfaloadSecretKeys::from_file(&args.secret_key, &args.password)
        .map_err(|e| anyhow::anyhow!("Could not load secret key {:?}: {}", args.secret_key, e))?;
    let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&auth_secret_key)?;

    let index_signature_key = match &args.index_signature_key {
        Some(key_path) => {
            let password = args
                .index_signature_password
                .as_deref()
                .unwrap_or(&args.password);
            AsfaloadSecretKeys::from_file(key_path, password).map_err(|e| {
                anyhow::anyhow!("Could not load index signature key {:?}: {}", key_path, e)
            })?
        }
        None => AsfaloadSecretKeys::from_file(
            &args.secret_key,
            args.index_signature_password
                .as_deref()
                .unwrap_or(&args.password),
        )
        .map_err(|e| anyhow::anyhow!("Could not load secret key {:?}: {}", args.secret_key, e))?,
    };

    // The signature the backend verifies covers the sha512 of the decoded
    // index content, not of its base64 form: mirror what admin-lib signs on
    // release registration.
    let (index, index_signature_source) = match (&args.index_file, &args.index_b64) {
        (Some(file), None) => {
            let content = std::fs::read_to_string(file)
                .with_context(|| format!("Could not read index file {:?}", file))?;
            (base64_for_string(&content), content)
        }
        // For a verbatim index the server fails at decoding before it looks
        // at the signature, so any structurally valid signature works: sign
        // the sent string.
        (None, Some(index)) => (index.clone(), index.clone()),
        // clap already enforced exactly one of the two arguments.
        _ => anyhow::bail!("Exactly one of --index-file or --index-b64 must be given"),
    };

    let index_digest = sha512_for_content(index_signature_source.as_bytes().to_vec())
        .map_err(anyhow::Error::from)?;
    let index_signature = index_signature_key.sign(&index_digest)?;

    let payload_string = serde_json::to_string(&RegisterAssetsPayload::GithubRelease(
        GithubReleasePayload {
            github_release_url: args.github_release_url.clone(),
            index: index.clone(),
            signature: index_signature.to_base64(),
        },
    ))?;

    let auth_info = AuthInfo::new(payload_string.clone());
    let auth_signature = AuthSignature::new(&auth_info, &auth_secret_key)?;

    println!(
        "{}",
        serde_json::json!({
            "payload": payload_string,
            "timestamp": auth_signature.auth_info().timestamp().to_rfc3339(),
            "nonce": auth_signature.auth_info().nonce(),
            "signature": auth_signature.signature().to_base64(),
            "public_key": public_key.to_base64(),
        })
    );

    Ok(())
}
