use crate::fileserver::{FileServerRepoInfo, FileServerUrlInfo};
use crate::github::{GITHUB_HOSTS, GitHubRepoInfo, GithubApiReleaseUrlInfo, GithubRepoUrlInfo};
use crate::gitlab::{GITLAB_HOSTS, GitLabRepoInfo, GitLabRepoUrlInfo};
use crate::traits::UrlInfoTrait;
use crate::{ForgeTrait, ForgeUrlError};

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
        todo!()
    }

    fn project_id(&self) -> String {
        todo!()
    }

    fn raw_url(&self) -> &url::Url {
        todo!()
    }

    fn file_path(&self) -> Option<&std::path::PathBuf> {
        todo!()
    }
}
