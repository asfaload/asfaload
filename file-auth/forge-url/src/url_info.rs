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
