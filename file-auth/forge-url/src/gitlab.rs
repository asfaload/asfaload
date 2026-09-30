use std::path::{Path, PathBuf};

use url::Url;

use crate::{ForgeTrait, ForgeUrlError, error::UrlInfoError, traits::UrlInfoTrait};

#[derive(Debug, Clone)]
pub struct GitLabRepoUrlInfo {
    original_url: Url,
    raw_url: Url,
    segments: Vec<String>,
    namespace: String,
    project: String,
    branch: String,
    file_path: PathBuf,
    path_prefix: String,
}

impl UrlInfoTrait for GitLabRepoUrlInfo {
    fn new(url: &url::Url) -> Result<Self, crate::error::UrlInfoError> {
        let host = url.host_str().unwrap_or("");

        if !GITLAB_HOSTS.contains(&host) {
            return Err(UrlInfoError::InvalidFormat(format!(
                "URL must be one of {}",
                GITLAB_HOSTS.join(","),
            )));
        }

        let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();

        if segments.len() < 5 {
            return Err(UrlInfoError::InvalidFormat(
                "URL must have at least 5 path segments".to_string(),
            ));
        }

        let dash_idx = segments
            .iter()
            .position(|&s| s == "-")
            .ok_or_else(|| UrlInfoError::InvalidFormat("Invalid GitLab URL format".to_string()))?;

        if dash_idx == 0 {
            return Err(UrlInfoError::InvalidFormat(
                "GitLab URL must contain a namespace and project".to_string(),
            ));
        }

        let project = segments[dash_idx - 1].to_string();

        let namespace = if dash_idx > 1 {
            segments[..dash_idx - 1].join("/")
        } else {
            return Err(UrlInfoError::InvalidFormat(
                "Namespace cannot be empty".to_string(),
            ));
        };

        let action = segments.get(dash_idx + 1);
        let action = match action {
            Some(&a) if a == "blob" || a == "raw" => a,
            _ => {
                return Err(UrlInfoError::InvalidFormat(
                    "URL must contain /blob/ or /raw/".to_string(),
                ));
            }
        };

        let branch = segments
            .get(dash_idx + 2)
            .ok_or(UrlInfoError::InvalidFormat(format!(
                "Branch not found in url {}",
                url
            )))?
            .to_string();

        let file_path_segments =
            segments
                .get(dash_idx + 3..)
                .ok_or(UrlInfoError::InvalidFormat(format!(
                    "file_path not found in url {}",
                    url
                )))?;

        let file_path = file_path_segments.join("/");

        if project.is_empty() {
            return Err(UrlInfoError::InvalidFormat(
                "Project cannot be empty".to_string(),
            ));
        }

        if branch.is_empty() {
            return Err(UrlInfoError::InvalidFormat(format!(
                "Missing branch in url {}",
                url
            )));
        }

        if file_path.is_empty() {
            return Err(UrlInfoError::InvalidFormat(format!(
                "Missing file_path in url {}",
                url
            )));
        }

        let raw_url = if action == "raw" {
            url.clone()
        } else {
            url::Url::parse(
                format!(
                    "https://gitlab.com/{}/{}/-/raw/{}/{}",
                    namespace, project, branch, file_path
                )
                .as_str(),
            )
            .map_err(|e| UrlInfoError::InvalidFormat(e.to_string()))?
        };

        let path_prefix = crate::path_prefix_from_url(url).map_err(|e| {
            UrlInfoError::InvalidFormat(format!(
                "Path prefix could not be determined for {}: {}",
                url, e
            ))
        })?;

        Ok(GitLabRepoUrlInfo {
            original_url: url.clone(),
            segments: segments.iter().map(|s| s.to_string()).collect(),
            namespace,
            project,
            branch,
            file_path: PathBuf::from(file_path),
            raw_url,
            path_prefix,
        })
    }

    fn project_id(&self) -> String {
        format!("{}/{}/{}", self.path_prefix, self.namespace, self.project)
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
pub struct GitLabRepoInfo {
    url_info: GitLabRepoUrlInfo,
}

#[cfg(not(feature = "test-utils"))]
pub const GITLAB_HOSTS: &[&str] = &["gitlab.com"];

#[cfg(feature = "test-utils")]
pub const GITLAB_HOSTS: &[&str] = &["gitlab.com", "localhost", "127.0.0.1"];

impl ForgeTrait for GitLabRepoInfo {
    fn new(url: &url::Url) -> Result<GitLabRepoInfo, ForgeUrlError> {
        let url_info = GitLabRepoUrlInfo::new(url)?;
        Ok(GitLabRepoInfo { url_info })
    }
    fn url_info(&self) -> &dyn UrlInfoTrait {
        &self.url_info
    }
    fn owner(&self) -> &str {
        &self.url_info.namespace
    }

    fn repo(&self) -> &str {
        &self.url_info.project
    }

    fn branch(&self) -> &str {
        &self.url_info.branch
    }
}

// Implement some accessors to url_info fields to limit changes to app code in a refactoring
// introducing trait UrlInfoTrait
impl GitLabRepoInfo {
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
    fn test_parse_gitlab_blob_url() {
        let url = url::Url::parse(
            "https://gitlab.com/namespace/project/-/blob/main/asfaload.initial_signers.json",
        )
        .unwrap();
        let result = GitLabRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "namespace");
        assert_eq!(result.repo(), "project");
        assert_eq!(result.branch(), "main");
        assert_eq!(
            result.file_path(),
            PathBuf::from("asfaload.initial_signers.json")
        );
        assert_eq!(
            result.raw_url(),
            &url::Url::parse(
                "https://gitlab.com/namespace/project/-/raw/main/asfaload.initial_signers.json"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_gitlab_raw_url() {
        let url =
            url::Url::parse("https://gitlab.com/namespace/project/-/raw/develop/path/to/file.json")
                .unwrap();
        let result = GitLabRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "namespace");
        assert_eq!(result.repo(), "project");
        assert_eq!(result.branch(), "develop");
        assert_eq!(result.file_path(), PathBuf::from("path/to/file.json"));
        assert_eq!(result.raw_url(), &url);
    }

    #[test]
    fn test_parse_gitlab_nested_namespace() {
        let url =
            url::Url::parse("https://gitlab.com/group/subgroup/project/-/blob/main/file.json")
                .unwrap();
        let result = GitLabRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner(), "group/subgroup");
        assert_eq!(result.repo(), "project");
        assert_eq!(result.branch(), "main");
        assert_eq!(result.file_path(), PathBuf::from("file.json"));
        assert_eq!(
            result.raw_url(),
            &url::Url::parse("https://gitlab.com/group/subgroup/project/-/raw/main/file.json")
                .unwrap()
        );
    }

    #[test]
    fn test_parse_invalid_domain() {
        let url =
            url::Url::parse("https://github.com/namespace/project/-/blob/main/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_blob_segment() {
        let url = url::Url::parse("https://gitlab.com/namespace/project/-/main/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_branch() {
        let url = url::Url::parse("https://gitlab.com/namespace/project/-/raw/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_namespace_and_project() {
        let url = url::Url::parse("https://gitlab.com/-/project/repo/blob/main/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        match result {
            Err(ForgeUrlError::UrlParsingError(UrlInfoError::InvalidFormat(msg))) => {
                if !msg.contains("GitLab URL must contain a namespace and project") {
                    panic!(
                        "Expected message to contain \"GitLab URL must contain a namespace and project\" but was \"{}\"",
                        msg
                    )
                }
            }
            Err(e) => panic!("Expected UrlParsingError with InvalidFormat, got {}", e),
            Ok(v) => panic!(
                "Expected UrlParsingError with InvalidFormat, got ok value {:?}",
                v
            ),
        }
    }
}
