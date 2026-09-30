use std::path::{Path, PathBuf};

use url::Url;

use crate::{
    ForgeTrait, ForgeUrlError, error::UrlInfoError, path_prefix_from_url, traits::UrlInfoTrait,
};

#[derive(Debug, Clone)]
pub struct GitHubRepoInfo {
    url_info: GithubRepoUrlInfo,
}

#[cfg(not(feature = "test-utils"))]
pub const GITHUB_REPO_HOSTS: &[&str] = &["github.com", "raw.githubusercontent.com"];
#[cfg(not(feature = "test-utils"))]
pub const GITHUB_API_HOSTS: &[&str] = &["api.github.com"];
#[cfg(not(feature = "test-utils"))]
pub const GITHUB_HOSTS: &[&str] = &["github.com", "raw.githubusercontent.com", "api.github.com"];

// In this case, localhost is accepted as repo host and 127.0.0.2 as api host to be able to mock both
// locally
#[cfg(feature = "test-utils")]
pub const GITHUB_REPO_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "localhost",
    "127.0.0.1",
];
// Mock api servers need to listen on 127.0.0.2 to avoid test failures.
#[cfg(feature = "test-utils")]
pub const GITHUB_API_HOSTS: &[&str] = &["api.github.com", "127.0.0.2"];
#[cfg(feature = "test-utils")]
pub const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "localhost",
    "127.0.0.1",
    "127.0.0.2",
];

#[derive(Debug, Clone)]
pub struct GithubRepoUrlInfo {
    original_url: Url,
    raw_url: Url,
    owner: String,
    repo: String,
    branch: String,
    file_path: PathBuf,
    path_prefix: String,
}
impl UrlInfoTrait for GithubRepoUrlInfo {
    fn new(url: &url::Url) -> Result<Self, UrlInfoError> {
        let host = url.host_str().unwrap_or("");

        if !GITHUB_HOSTS.contains(&host) {
            return Err(UrlInfoError::InvalidFormat(format!(
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
                    return Err(UrlInfoError::InvalidFormat(
                        "URL must have at least 5 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                if segments[2] != "blob" {
                    return Err(UrlInfoError::InvalidFormat(
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
                .map_err(|e| UrlInfoError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            Some("raw.githubusercontent.com") => {
                if segments.len() < 4 {
                    return Err(UrlInfoError::InvalidFormat(
                        "URL must have at least 4 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                let branch = segments[2].to_string();
                let file_path = segments[3..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| UrlInfoError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }

            #[cfg(feature = "test-utils")]
            Some("localhost") | Some("127.0.0.1") => {
                if segments.len() < 4 {
                    return Err(UrlInfoError::InvalidFormat(
                        "URL must have at least 4 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                let branch = segments[2].to_string();
                let file_path = segments[3..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| UrlInfoError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            Some(other) => {
                return Err(UrlInfoError::InvalidFormat(format!(
                    "Unsupported hostname {} for Github repo url",
                    other
                )));
            }
            None => {
                return Err(UrlInfoError::InvalidFormat(
                    "Unsupported absent host name for Github repo url".into(),
                ));
            }
        };

        if branch.is_empty() {
            return Err(UrlInfoError::InvalidFormat(format!(
                "Missing branch in url {}",
                url
            )));
        }

        if file_path.as_os_str().is_empty() {
            return Err(UrlInfoError::InvalidFormat(format!(
                "Missing file_path in url {}",
                url
            )));
        }

        // Only manually map to the github prefix for raw urls. If we set it to the prefix
        // "https/github.com/443" for all executions, tests won't pass as the test-utils feature
        // considers locahost as github urls, but still writes http/localhost/$port to disk!
        let path_prefix = if url.host_str() == Some("raw.githubusercontent.com") {
            "https/github.com/443".to_string()
        } else {
            path_prefix_from_url(url).map_err(|e| {
                UrlInfoError::InvalidFormat(format!(
                    "Could not determine prefix from url {}: {}",
                    url, e
                ))
            })?
        };

        Ok(GithubRepoUrlInfo {
            original_url: url.clone(),
            raw_url,
            owner,
            repo,
            branch,
            file_path,
            path_prefix,
        })
    }

    fn project_id(&self) -> String {
        format!("{}/{}/{}", self.path_prefix, self.owner, self.repo)
    }

    fn raw_url(&self) -> &Url {
        &self.raw_url
    }
    fn file_path(&self) -> Option<&PathBuf> {
        Some(&self.file_path)
    }

    fn original_url(&self) -> &Url {
        &self.original_url
    }
}
#[derive(Debug, Clone)]
pub struct GithubApiReleaseUrlInfo {
    original_url: Url,
    path_prefix: String,
    owner: String,
    repo: String,
}

impl UrlInfoTrait for GithubApiReleaseUrlInfo {
    fn new(url: &url::Url) -> Result<Self, UrlInfoError> {
        let host = url.host_str().unwrap_or("");

        if !GITHUB_API_HOSTS.contains(&host) {
            return Err(UrlInfoError::InvalidFormat(format!(
                "URL must be one of {}",
                GITHUB_API_HOSTS.join(","),
            )));
        }

        let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 5 {
            return Err(UrlInfoError::InvalidFormat(
                "URL must have at least 5 path segments".to_string(),
            ));
        }
        if segments[0] != "repos" {
            return Err(UrlInfoError::InvalidFormat(
                "GitHub api URL must start with /repos/".to_string(),
            ));
        }
        if segments[3] != "releases" {
            return Err(UrlInfoError::InvalidFormat(
                "GitHub api URL exepected to include /releases/".to_string(),
            ));
        }
        Ok(GithubApiReleaseUrlInfo {
            original_url: url.clone(),
            path_prefix: "https/github.com/443".into(),
            owner: segments[1].to_string(),
            repo: segments[2].to_string(),
        })
    }

    fn project_id(&self) -> String {
        format!("{}/{}/{}", self.path_prefix, self.owner, self.repo)
    }

    // For an api url, the raw url, which is the url returning the raw document, is the original
    // url itself.
    fn raw_url(&self) -> &Url {
        &self.original_url
    }

    fn file_path(&self) -> Option<&PathBuf> {
        None
    }

    fn original_url(&self) -> &Url {
        &self.original_url
    }
}

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
        let url_info = GithubRepoUrlInfo::new(url)?;
        Ok(GitHubRepoInfo { url_info })
    }

    fn owner(&self) -> &str {
        &self.url_info.owner
    }

    fn repo(&self) -> &str {
        &self.url_info.repo
    }

    fn branch(&self) -> &str {
        &self.url_info.branch
    }

    fn url_info(&self) -> &dyn UrlInfoTrait {
        &self.url_info
    }
}

// Implement some accessors to url_info fields to limit changes to app code in a refactoring
// introducing trait UrlInfoTrait
impl GitHubRepoInfo {
    pub fn project_id(&self) -> String {
        self.url_info.project_id()
    }

    pub fn file_path(&self) -> &Path {
        &self.url_info.file_path
    }

    pub fn raw_url(&self) -> &url::Url {
        &self.url_info.raw_url
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

    // Indexes built from github releases record the release api url as digest
    // source. A plain release url ends with the release id: it has no file
    // path, but it still resolves to the github project of the repo.
    // Release api urls are handled by UrlInfo's GithubReleaseApi variant.
    #[test]
    fn test_parse_release_api_url_without_asset_path() {
        let url = url::Url::parse(
            "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893",
        )
        .unwrap();
        let url_info = crate::url_info::UrlInfo::new(&url).unwrap();
        match &url_info {
            crate::url_info::UrlInfo::GithubReleaseApi(_info) => {}
            other => panic!("Expected GithubReleaseApi variant, got {:?}", other),
        }
        assert_eq!(
            url_info.project_id(),
            "https/github.com/443/asfaload/repo_for_e2e_tests"
        );
    }

    #[test]
    fn test_parse_release_api_url_with_asset_path() {
        let url = url::Url::parse(
            "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893/assets/456",
        )
        .unwrap();
        let url_info = crate::url_info::UrlInfo::new(&url).unwrap();
        match &url_info {
            crate::url_info::UrlInfo::GithubReleaseApi(_info) => {}
            other => panic!("Expected GithubReleaseApi variant, got {:?}", other),
        }
        assert_eq!(
            url_info.project_id(),
            "https/github.com/443/asfaload/repo_for_e2e_tests"
        );
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
