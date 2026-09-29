use std::path::{Path, PathBuf};

use constants::{HIDDEN_SIGNERS_DIR, SIGNERS_DIR};
use url::Url;

use crate::{ForgeUrlError, error::UrlInfoError, traits::UrlInfoTrait};

/// Directory names on the file server that are transparent for project_id computation.
/// Both the hidden (dot-prefixed) and visible variants of the canonical signers directory
/// name are supported. URLs containing either directory in their path have it stripped
/// when computing the project root.
const SIGNERS_DIRS_ON_SERVER: &[&str] = &[HIDDEN_SIGNERS_DIR, SIGNERS_DIR];

#[derive(Debug, Clone)]
struct FileServerUrlInfo {
    host: String,
    file_path: PathBuf,
    original_url: Url,
    path_prefix: String,
}

impl UrlInfoTrait for FileServerUrlInfo {
    fn new(url: &url::Url) -> Result<Self, crate::error::UrlInfoError> {
        let host = url.host_str().unwrap_or("").to_string();

        if host.is_empty() {
            return Err(UrlInfoError::InvalidFormat(
                "URL must have a host".to_string(),
            ));
        }

        let path = url.path();
        // Reject empty or root-only paths
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Err(UrlInfoError::InvalidFormat(
                "Url must have segments in path".into(),
            ));
        }

        let file_path = PathBuf::from(segments.join("/"));

        let path_prefix = crate::path_prefix_from_url(url).map_err(|e| {
            UrlInfoError::InvalidFormat(format!(
                "Path prefix could not be determined for {}: {}",
                url, e
            ))
        })?;

        Ok(FileServerUrlInfo {
            host,
            file_path,
            original_url: url.clone(),
            path_prefix,
        })
    }

    fn project_id(&self) -> String {
        let prefix = &self.path_prefix;
        let path = &self.file_path;
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                // If the immediate parent is a signers directory, go up one more level
                let parent_name = parent
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Signers directories on the file server are organisational — they
                // should not affect the project root. Strip them so that
                // e.g. http/localhost/8080/project/.asfaload.signers/file.json and
                //      http/localhost/8080/project/releases/v1/SHA256SUMS
                // both resolve to the same project_id "http/localhost/8080/project".
                let effective_parent = if SIGNERS_DIRS_ON_SERVER.contains(&parent_name.as_str()) {
                    match parent.parent() {
                        Some(grandparent) if !grandparent.as_os_str().is_empty() => grandparent,
                        _ => return prefix.clone(),
                    }
                } else {
                    parent
                };

                format!("{}/{}", prefix, effective_parent.to_string_lossy())
            }
            _ => {
                // File is at root level (no parent dir)
                prefix.clone()
            }
        }
    }
}
#[derive(Debug, Clone)]
pub struct FileServerRepoInfo {
    url_info: FileServerUrlInfo,
}

impl FileServerRepoInfo {
    pub fn new(url: &Url) -> Result<Self, ForgeUrlError> {
        let url_info = FileServerUrlInfo::new(url)?;

        Ok(FileServerRepoInfo { url_info })
    }

    pub fn url_info(&self) -> &impl UrlInfoTrait {
        &self.url_info
    }
}
impl FileServerRepoInfo {
    pub fn file_path(&self) -> &Path {
        &self.url_info.file_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_url() {
        let url = Url::parse("http://localhost:8080/myproject/signers.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/localhost/8080/myproject");
    }

    #[test]
    fn test_hidden_signers_dir_stripped() {
        let url =
            Url::parse("http://localhost:8080/myproject/.asfaload.signers/signers1.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/localhost/8080/myproject");
    }

    #[test]
    fn test_visible_signers_dir_stripped() {
        let url =
            Url::parse("http://localhost:8080/myproject/asfaload.signers/signers1.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/localhost/8080/myproject");
    }

    #[test]
    fn test_nested_path() {
        let url = Url::parse("http://files.example.com/org/project/deep/file.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(
            info.project_id(),
            "http/files.example.com/80/org/project/deep"
        );
    }

    #[test]
    fn test_no_port() {
        let url = Url::parse("http://files.example.com/project/signers.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/files.example.com/80/project");
    }

    #[test]
    fn test_root_file() {
        let url = Url::parse("http://localhost:8080/signers.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/localhost/8080");
        assert_eq!(info.file_path, Path::new("signers.json"));
    }

    #[test]
    fn test_empty_path_fails() {
        let url = Url::parse("http://localhost:8080/").unwrap();
        let result = FileServerRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_only_hidden_signers_dir_parent() {
        let url = Url::parse("http://localhost:8080/.asfaload.signers/signers.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/localhost/8080");
    }

    #[test]
    fn test_only_visible_signers_dir_parent() {
        let url = Url::parse("http://localhost:8080/asfaload.signers/signers.json").unwrap();
        let info = FileServerUrlInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "http/localhost/8080");
    }
}
