use crate::error::Result;
use admin_lib::v1::RegistrationMode;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;
use forge_url::github::is_github_release_host;

pub async fn handle_register_assets_command(
    backend_url: &str,
    mode: RegistrationMode,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.register_assets(&mode, &secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Assets registered successfully! Remember you still need to sign it yourself!");
        if let Some(index_path) = response.index_file_path {
            println!("Index file path: {}", index_path);
        }
    } else {
        println!("Asset registration failed: {}", response.message);
    }

    Ok(())
}
pub(crate) fn determine_registration_mode(
    github_release_url: &Option<String>,
    csum_file: &[String],
) -> anyhow::Result<admin_lib::v1::RegistrationMode> {
    match (github_release_url.as_ref(), csum_file.is_empty()) {
        (Some(url), true) => {
            let parsed =
                url::Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid release URL: {}", e))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Release URL missing host"))?;
            if !is_github_release_host(host) {
                anyhow::bail!(
                    "--github-release-url must be a GitHub URL. Host '{}' is not a known GitHub host",
                    host
                );
            }
            Ok(admin_lib::v1::RegistrationMode::GithubRelease { url: url.clone() })
        }
        (None, false) => {
            let parsed_urls: Vec<url::Url> = csum_file
                .iter()
                .map(|s| {
                    url::Url::parse(s).map_err(|e| anyhow::anyhow!("Invalid URL '{}': {}", s, e))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rest_api_types::validate_common_parent(&parsed_urls)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            Ok(admin_lib::v1::RegistrationMode::ChecksumFiles {
                urls: csum_file.to_vec(),
            })
        }
        (Some(_), false) => {
            anyhow::bail!("--github-release-url and --csum-file are mutually exclusive");
        }
        (None, true) => {
            anyhow::bail!("Either --github-release-url or --csum-file must be provided");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The github rest api serves release info, but a release url must target
    // the project's release pages: the api host is not a repo host.
    #[test]
    fn github_api_release_url_is_rejected() {
        let release_url = Some("https://api.github.com/repos/owner/repo/releases/123".to_string());

        match determine_registration_mode(&release_url, &[]) {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("not a known GitHub host"),
                    "unexpected error message: {msg}"
                );
            }
            Ok(_) => panic!("expected github api release url to be rejected"),
        }
    }
}
