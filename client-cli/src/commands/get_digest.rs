use std::path::PathBuf;

use common::{sha512_for_file, sha512_for_url};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct GetDigestOutput {
    digest: String,
}

pub async fn handle_get_digest_command(file: &str, json: bool) -> anyhow::Result<()> {
    let digest = if file.starts_with("http://") || file.starts_with("https://") {
        let parsed_url = url::Url::parse(file)
            .map_err(|e| std::io::Error::other(format!("Invalid URL: {e}")))?;
        sha512_for_url(parsed_url).await
    } else {
        let p = PathBuf::from(file);
        sha512_for_file(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::other(format!("File not found at {}", file))
            } else {
                e
            }
        })
    }?;
    if json {
        let output = GetDigestOutput {
            digest: digest.to_string(),
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("{}", digest);
    }
    Ok(())
}
