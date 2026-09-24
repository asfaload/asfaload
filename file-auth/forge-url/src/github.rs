use std::path::{Path, PathBuf};

use url::Url;

use crate::{ForgeTrait, ForgeUrlError, path_prefix_from_url};

#[derive(Debug, Clone)]
pub struct GitHubRepoInfo {
    owner: String,
    repo: String,
    branch: String,
    file_path: PathBuf,
    raw_url: Url,
    path_prefix: String,
}

#[cfg(not(feature = "test-utils"))]
pub const GITHUB_HOSTS: &[&str] = &["github.com", "raw.githubusercontent.com", "api.github.com"];

#[cfg(feature = "test-utils")]
pub const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "localhost",
    "127.0.0.1",
];

impl ForgeTrait for GitHubRepoInfo {
    /// Parse a GitHub URL (blob or raw format) and extract repo information
    /// Accepts both:
    /// - https://github.com/owner/repo/blob/branch/path/to/file.json
    /// - https://raw.githubusercontent.com/owner/repo/branch/path/to/file.json
    /// - http://localhost:port/owner/repo/branch/path/to/file.json (for testing)
    fn new(url: &url::Url) -> Result<GitHubRepoInfo, ForgeUrlError> {
        let host = url.host_str().unwrap_or("");

        if !GITHUB_HOSTS.contains(&host) {
            return Err(ForgeUrlError::InvalidFormat(format!(
                "URL must be one of {}",
                GITHUB_HOSTS.join(","),
            )));
        }

        let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();

        let (owner, repo, branch, file_path, raw_url) = match url.host_str() {
            // Url of the form
            // "https://github.com/asfaload/repo_for_e2e_tests/blob/master/basic_flow/signers_file_1_asfaload.json"
            // The url in the browser of a signers file in a repo
            Some("github.com") => {
                if segments.len() < 5 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 5 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                if segments[2] != "blob" {
                    return Err(ForgeUrlError::InvalidFormat(
                        "GitHub URL must contain /blob/".to_string(),
                    ));
                }
                let branch = segments[3].to_string();
                let file_path = segments[4..].join("/");
                let raw_url = url::Url::parse(
                    format!(
                        "https://raw.githubusercontent.com/{}/{}/{}/{}",
                        owner, repo, branch, file_path
                    )
                    .as_str(),
                )
                .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            // Url of the form
            // "https://raw.githubusercontent.com/asfaload/repo_for_e2e_tests/master/basic_flow/signers_file_1_asfaload.json"
            // Found in signers files' metadata files (effective retrieval url corresponding to a
            // browser url's raw content url).
            Some("raw.githubusercontent.com") => {
                if segments.len() < 4 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 4 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                let branch = segments[2].to_string();
                let file_path = segments[3..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            // Url of the form
            // "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244"
            // As found in index files built from Github releases.
            Some("api.github.com") => {
                if segments.len() < 5 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 5 path segments".to_string(),
                    ));
                }
                if segments[0] != "repos" {
                    return Err(ForgeUrlError::InvalidFormat(
                        "GitHub api URL must start with /repos/".to_string(),
                    ));
                }
                if segments[3] != "releases" {
                    return Err(ForgeUrlError::InvalidFormat(
                        "GitHub api URL exepected to include /releases/".to_string(),
                    ));
                }
                let owner = segments[1].to_string();
                let repo = segments[2].to_string();
                let branch = segments[4].to_string();
                let file_path = segments[5..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            #[cfg(feature = "test-utils")]
            Some("localhost") | Some("127.0.0.1") => {
                if segments.len() < 4 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 4 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                let branch = segments[2].to_string();
                let file_path = segments[3..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            _ => {
                return Err(ForgeUrlError::InvalidFormat(
                    "Unsupported GitHub URL format".to_string(),
                ));
            }
        };

        if branch.is_empty() {
            return Err(ForgeUrlError::MissingBranch);
        }

        if file_path.as_os_str().is_empty() {
            return Err(ForgeUrlError::MissingFilePath);
        }

        // raw.githubusercontent.com is GitHub's content host, but the project's
        // identity is the github.com repo. Canonicalise the prefix so blob and
        // raw URLs for the same repo share one project_id.
        let host_str = url.host_str();
        let path_prefix = if host_str == Some("raw.githubusercontent.com")
            || host_str == Some("api.github.com")
        {
            "https/github.com/443".to_string()
        } else {
            path_prefix_from_url(url)?
        };

        Ok(GitHubRepoInfo {
            owner,
            repo,
            branch,
            file_path,
            raw_url,
            path_prefix,
        })
    }

    fn project_id(&self) -> String {
        format!("{}/{}/{}", self.path_prefix, self.owner, self.repo)
    }

    fn owner(&self) -> &str {
        &self.owner
    }

    fn repo(&self) -> &str {
        &self.repo
    }

    fn branch(&self) -> &str {
        &self.branch
    }

    fn file_path(&self) -> &Path {
        &self.file_path
    }

    fn raw_url(&self) -> &url::Url {
        &self.raw_url
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_blob_url() {
        let url = url::Url::parse(
            "https://github.com/owner/repo/blob/main/asfaload.initial_signers.json",
        )
        .unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "owner");
        assert_eq!(result.repo(), "repo");
        assert_eq!(result.branch(), "main");
        assert_eq!(
            result.file_path(),
            PathBuf::from("asfaload.initial_signers.json")
        );
        assert_eq!(
            result.raw_url(),
            &url::Url::parse(
                "https://raw.githubusercontent.com/owner/repo/main/asfaload.initial_signers.json"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_github_raw_url() {
        let url = url::Url::parse(
            "https://raw.githubusercontent.com/owner/repo/develop/path/to/file.json",
        )
        .unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "owner");
        assert_eq!(result.repo(), "repo");
        assert_eq!(result.branch(), "develop");
        assert_eq!(result.file_path(), PathBuf::from("path/to/file.json"));
        assert_eq!(result.raw_url(), &url);
    }

    #[test]
    fn test_parse_invalid_domain() {
        let url = url::Url::parse("https://gitlab.com/owner/repo/blob/main/file.json").unwrap();
        let result = GitHubRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_blob_segment() {
        let url = url::Url::parse("https://github.com/owner/repo/main/file.json").unwrap();
        let result = GitHubRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_branch() {
        let url =
            url::Url::parse("https://raw.githubusercontent.com/owner/repo/file.json").unwrap();
        let result = GitHubRepoInfo::new(&url);
        assert!(result.is_err());
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod test_utils_tests {
    use super::*;

    #[test]
    fn test_parse_localhost_url() {
        let url = url::Url::parse("http://localhost:8080/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "owner");
        assert_eq!(result.repo(), "repo");
        assert_eq!(result.branch(), "main");
        assert_eq!(result.file_path(), PathBuf::from("signers.json"));
        assert_eq!(result.raw_url(), &url);
    }

    #[test]
    fn test_parse_127_0_0_1_url() {
        let url = url::Url::parse("http://127.0.0.1:8080/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "owner");
        assert_eq!(result.repo(), "repo");
        assert_eq!(result.branch(), "main");
        assert_eq!(result.file_path(), PathBuf::from("signers.json"));
        assert_eq!(result.raw_url(), &url);
    }

    #[test]
    fn test_parse_localhost_without_port() {
        let url = url::Url::parse("http://localhost/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "owner");
        assert_eq!(result.repo(), "repo");
        assert_eq!(result.branch(), "main");
        assert_eq!(result.file_path(), PathBuf::from("signers.json"));
        assert_eq!(result.raw_url(), &url);
    }

    #[test]
    fn test_parse_127_0_0_1_without_port() {
        let url = url::Url::parse("http://127.0.0.1/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "owner");
        assert_eq!(result.repo(), "repo");
        assert_eq!(result.branch(), "main");
        assert_eq!(result.file_path(), PathBuf::from("signers.json"));
        assert_eq!(result.raw_url(), &url);
    }
}
