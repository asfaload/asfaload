use crate::fileserver::FileServerUrlInfo;
use crate::github::{GITHUB_API_HOSTS, GITHUB_HOSTS, GithubApiReleaseUrlInfo, GithubRepoUrlInfo};
use crate::gitlab::{GITLAB_HOSTS, GitLabRepoUrlInfo};
use crate::traits::UrlInfoTrait;

/// Enum providing static dispatch to the different UrlInfoTrait implementers
#[derive(Debug)]
pub enum UrlInfo {
    GithubRepo(GithubRepoUrlInfo),
    GithubReleaseApi(GithubApiReleaseUrlInfo),
    Gitlab(GitLabRepoUrlInfo),
    FileServer(FileServerUrlInfo),
}

impl UrlInfoTrait for UrlInfo {
    fn new(url: &url::Url) -> Result<Self, crate::error::UrlInfoError>
    where
        Self: Sized,
    {
        // We match on the host to determine which wrapped type we need to initialise.
        let host = url.host_str().unwrap_or("");

        // The api hosts must be checked first: they are a subset of GITHUB_HOSTS, but
        // GithubRepoUrlInfo only accepts repo urls.
        if GITHUB_API_HOSTS.contains(&host) {
            Ok(Self::GithubReleaseApi(GithubApiReleaseUrlInfo::new(url)?))
        } else if GITHUB_HOSTS.contains(&host) {
            Ok(Self::GithubRepo(GithubRepoUrlInfo::new(url)?))
        } else if GITLAB_HOSTS.contains(&host) {
            Ok(Self::Gitlab(GitLabRepoUrlInfo::new(url)?))
        } else {
            Ok(Self::FileServer(FileServerUrlInfo::new(url)?))
        }
    }

    fn project_id(&self) -> String {
        match self {
            Self::GithubRepo(info) => info.project_id(),
            Self::GithubReleaseApi(info) => info.project_id(),
            Self::Gitlab(info) => info.project_id(),
            Self::FileServer(info) => info.project_id(),
        }
    }

    fn raw_url(&self) -> &url::Url {
        match self {
            Self::GithubRepo(info) => info.raw_url(),
            Self::GithubReleaseApi(info) => info.raw_url(),
            Self::Gitlab(info) => info.raw_url(),
            Self::FileServer(info) => info.raw_url(),
        }
    }

    fn file_path(&self) -> Option<&std::path::PathBuf> {
        match self {
            Self::GithubRepo(info) => info.file_path(),
            Self::GithubReleaseApi(info) => info.file_path(),
            Self::Gitlab(info) => info.file_path(),
            Self::FileServer(info) => info.file_path(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_dispatch_github_blob_url() {
        let url = url::Url::parse("https://github.com/owner/repo/blob/main/file.json").unwrap();
        let url_info = UrlInfo::new(&url).unwrap();

        match &url_info {
            UrlInfo::GithubRepo(info) => {
                assert_eq!(info.project_id(), url_info.project_id());
                assert_eq!(info.raw_url(), url_info.raw_url());
                assert_eq!(info.file_path(), url_info.file_path());
            }
            other => panic!("Expected GithubRepo variant, got {:?}", other),
        }
        assert_eq!(url_info.project_id(), "https/github.com/443/owner/repo");
        assert_eq!(
            url_info.raw_url(),
            &url::Url::parse("https://raw.githubusercontent.com/owner/repo/main/file.json")
                .unwrap()
        );
        assert_eq!(url_info.file_path(), Some(&PathBuf::from("file.json")));
    }

    #[test]
    fn test_dispatch_github_raw_url() {
        let url =
            url::Url::parse("https://raw.githubusercontent.com/owner/repo/main/file.json").unwrap();
        let url_info = UrlInfo::new(&url).unwrap();

        match &url_info {
            UrlInfo::GithubRepo(info) => {
                assert_eq!(info.project_id(), url_info.project_id());
                assert_eq!(info.raw_url(), url_info.raw_url());
                assert_eq!(info.file_path(), url_info.file_path());
            }
            other => panic!("Expected GithubRepo variant, got {:?}", other),
        }
        assert_eq!(url_info.project_id(), "https/github.com/443/owner/repo");
        assert_eq!(url_info.raw_url(), &url);
        assert_eq!(url_info.file_path(), Some(&PathBuf::from("file.json")));
    }

    // api.github.com belongs to both GITHUB_API_HOSTS and GITHUB_HOSTS: the api
    // hosts must be checked first, else the release url would be handed to the
    // repo url parser and rejected.
    #[test]
    fn test_dispatch_github_api_release_url() {
        let url =
            url::Url::parse("https://api.github.com/repos/owner/repo/releases/286360893").unwrap();
        let url_info = UrlInfo::new(&url).unwrap();

        match &url_info {
            UrlInfo::GithubReleaseApi(info) => {
                assert_eq!(info.project_id(), url_info.project_id());
                assert_eq!(info.raw_url(), url_info.raw_url());
            }
            other => panic!("Expected GithubReleaseApi variant, got {:?}", other),
        }
        assert_eq!(url_info.project_id(), "https/github.com/443/owner/repo");
        assert_eq!(url_info.raw_url(), &url);
        assert_eq!(url_info.file_path(), None);
    }

    #[test]
    fn test_dispatch_gitlab_blob_url() {
        let url =
            url::Url::parse("https://gitlab.com/namespace/project/-/blob/main/file.json").unwrap();
        let url_info = UrlInfo::new(&url).unwrap();

        match &url_info {
            UrlInfo::Gitlab(info) => {
                assert_eq!(info.project_id(), url_info.project_id());
                assert_eq!(info.raw_url(), url_info.raw_url());
                assert_eq!(info.file_path(), url_info.file_path());
            }
            other => panic!("Expected Gitlab variant, got {:?}", other),
        }
        assert_eq!(
            url_info.project_id(),
            "https/gitlab.com/443/namespace/project"
        );
        assert_eq!(
            url_info.raw_url(),
            &url::Url::parse("https://gitlab.com/namespace/project/-/raw/main/file.json").unwrap()
        );
        assert_eq!(url_info.file_path(), Some(&PathBuf::from("file.json")));
    }

    #[test]
    fn test_dispatch_unknown_host_falls_back_to_fileserver() {
        let url = url::Url::parse("https://files.example.com/project/file.json").unwrap();
        let url_info = UrlInfo::new(&url).unwrap();

        match &url_info {
            UrlInfo::FileServer(info) => {
                assert_eq!(info.project_id(), url_info.project_id());
                assert_eq!(info.raw_url(), url_info.raw_url());
                assert_eq!(info.file_path(), url_info.file_path());
            }
            other => panic!("Expected FileServer variant, got {:?}", other),
        }
        assert_eq!(url_info.project_id(), "https/files.example.com/443/project");
        assert_eq!(url_info.raw_url(), &url);
        assert_eq!(
            url_info.file_path(),
            Some(&PathBuf::from("project/file.json"))
        );
    }

    // A known forge url that does not match its url shape must error, not fall
    // back to the file server parser.
    #[test]
    fn test_invalid_github_url_propagates_error() {
        let url = url::Url::parse("https://github.com/owner/repo/main/file.json").unwrap();
        assert!(UrlInfo::new(&url).is_err());
    }
}
