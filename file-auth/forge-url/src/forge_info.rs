use crate::fileserver::FileServerRepoInfo;
use crate::github::{GITHUB_HOSTS, GitHubRepoInfo};
use crate::gitlab::{GITLAB_HOSTS, GitLabRepoInfo};
use crate::{ForgeTrait, ForgeUrlError};

#[derive(Debug)]
pub enum ForgeInfo {
    Github(GitHubRepoInfo),
    Gitlab(GitLabRepoInfo),
    FileServer(FileServerRepoInfo),
}

impl ForgeTrait for ForgeInfo {
    fn new(url: &url::Url) -> Result<Self, ForgeUrlError> {
        let host = url.host_str().unwrap_or("");

        if GITHUB_HOSTS.contains(&host) {
            Ok(Self::Github(GitHubRepoInfo::new(url)?))
        } else if GITLAB_HOSTS.contains(&host) {
            Ok(Self::Gitlab(GitLabRepoInfo::new(url)?))
        } else {
            Ok(Self::FileServer(FileServerRepoInfo::new(url)?))
        }
    }

    fn owner(&self) -> &str {
        match self {
            Self::Github(info) => info.owner(),
            Self::Gitlab(info) => info.owner(),
            Self::FileServer(_info) => "",
        }
    }

    fn repo(&self) -> &str {
        match self {
            Self::Github(info) => info.repo(),
            Self::Gitlab(info) => info.repo(),
            Self::FileServer(_info) => "",
        }
    }

    fn branch(&self) -> &str {
        match self {
            Self::Github(info) => info.branch(),
            Self::Gitlab(info) => info.branch(),
            Self::FileServer(_info) => "",
        }
    }

    fn url_info(&self) -> &dyn crate::traits::UrlInfoTrait {
        match self {
            Self::Github(info) => info.url_info(),
            Self::Gitlab(info) => info.url_info(),
            Self::FileServer(info) => info.url_info(),
        }
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_github_blob_url() {
        let url = url::Url::parse(
            "https://github.com/owner/repo/blob/main/asfaload.initial_signers.json",
        )
        .unwrap();
        let result = ForgeInfo::new(&url).unwrap();

        match result {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), "owner");
                assert_eq!(info.repo(), "repo");
                assert_eq!(info.branch(), "main");
                assert_eq!(
                    info.file_path(),
                    PathBuf::from("asfaload.initial_signers.json")
                );
                assert_eq!(
                    info.raw_url(),
                    &url::Url::parse("https://raw.githubusercontent.com/owner/repo/main/asfaload.initial_signers.json").unwrap()
                );
            }
            _ => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    fn test_parse_github_raw_url() {
        let url = url::Url::parse(
            "https://raw.githubusercontent.com/owner/repo/develop/path/to/file.json",
        )
        .unwrap();
        let result = ForgeInfo::new(&url).unwrap();

        match result {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), "owner");
                assert_eq!(info.repo(), "repo");
                assert_eq!(info.branch(), "develop");
                assert_eq!(info.file_path(), PathBuf::from("path/to/file.json"));
                assert_eq!(info.raw_url(), &url);
            }
            _ => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    fn test_parse_gitlab_blob_url() {
        let url = url::Url::parse(
            "https://gitlab.com/namespace/project/-/blob/main/asfaload.initial_signers.json",
        )
        .unwrap();
        let result = ForgeInfo::new(&url).unwrap();

        match result {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), "namespace");
                assert_eq!(info.repo(), "project");
                assert_eq!(info.branch(), "main");
                assert_eq!(
                    info.file_path(),
                    PathBuf::from("asfaload.initial_signers.json")
                );
                assert_eq!(
                    info.raw_url(),
                    &url::Url::parse("https://gitlab.com/namespace/project/-/raw/main/asfaload.initial_signers.json").unwrap()
                );
            }
            _ => panic!("Expected GitLab variant"),
        }
    }

    #[test]
    fn test_parse_gitlab_raw_url() {
        let url =
            url::Url::parse("https://gitlab.com/namespace/project/-/raw/develop/path/to/file.json")
                .unwrap();
        let result = ForgeInfo::new(&url).unwrap();

        match result {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), "namespace");
                assert_eq!(info.repo(), "project");
                assert_eq!(info.branch(), "develop");
                assert_eq!(info.file_path(), PathBuf::from("path/to/file.json"));
                assert_eq!(info.raw_url(), &url);
            }
            _ => panic!("Expected GitLab variant"),
        }
    }

    #[test]
    fn test_unsupported_domain_falls_back_to_fileserver() {
        let url = url::Url::parse("https://bitbucket.org/owner/repo/src/main/file.json").unwrap();
        let result = ForgeInfo::new(&url).unwrap();
        match result {
            ForgeInfo::FileServer(info) => {
                assert_eq!(info.owner(), "bitbucket.org");
                assert_eq!(
                    info.file_path(),
                    PathBuf::from("owner/repo/src/main/file.json")
                );
            }
            _ => panic!("Expected FileServer variant"),
        }
    }

    #[test]
    fn test_invalid_github_url() {
        let url = url::Url::parse("https://github.com/owner/repo/main/file.json").unwrap();
        let result = ForgeInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_gitlab_url() {
        let url = url::Url::parse("https://gitlab.com/namespace/project/-/main/file.json").unwrap();
        let result = ForgeInfo::new(&url);
        assert!(result.is_err());
    }

    fn assert_forge_trait_methods(
        forge: &ForgeInfo,
        expected_owner: &str,
        expected_repo: &str,
        expected_branch: &str,
        expected_path: &str,
        expected_raw_url: &url::Url,
        expected_project_id: &str,
    ) {
        assert_eq!(forge.owner(), expected_owner, "owner mismatch");
        assert_eq!(forge.repo(), expected_repo, "repo mismatch");
        assert_eq!(forge.branch(), expected_branch, "branch mismatch");
        assert_eq!(
            forge.file_path(),
            PathBuf::from(expected_path),
            "file_path mismatch"
        );
        assert_eq!(forge.raw_url(), expected_raw_url, "raw_url mismatch");
        assert_eq!(
            forge.project_id(),
            expected_project_id,
            "project_id mismatch"
        );
    }

    #[test]
    fn test_github_blob_all_trait_methods() {
        let url =
            url::Url::parse("https://github.com/example-org/my-repo/blob/develop/docs/config.json")
                .unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "example-org",
            "my-repo",
            "develop",
            "docs/config.json",
            &url::Url::parse(
                "https://raw.githubusercontent.com/example-org/my-repo/develop/docs/config.json",
            )
            .unwrap(),
            "https/github.com/443/example-org/my-repo",
        );
    }

    #[test]
    fn test_github_raw_all_trait_methods() {
        let url =
            url::Url::parse("https://raw.githubusercontent.com/user/repo/v1.0/data.json").unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "user",
            "repo",
            "v1.0",
            "data.json",
            &url,
            "https/github.com/443/user/repo",
        );
    }

    #[test]
    fn test_github_nested_path_trait_methods() {
        let url = url::Url::parse(
            "https://github.com/org/complex-repo/blob/main/path/to/deeply/nested/config.yml",
        )
        .unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "org",
            "complex-repo",
            "main",
            "path/to/deeply/nested/config.yml",
            &url::Url::parse("https://raw.githubusercontent.com/org/complex-repo/main/path/to/deeply/nested/config.yml").unwrap(),
            "https/github.com/443/org/complex-repo",
        );
    }

    #[test]
    fn test_github_complex_branch_trait_methods() {
        let url = url::Url::parse(
            "https://github.com/acme/projects/blob/feature-auth-v2/src/auth/provider.ts",
        )
        .unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "acme",
            "projects",
            "feature-auth-v2",
            "src/auth/provider.ts",
            &url::Url::parse("https://raw.githubusercontent.com/acme/projects/feature-auth-v2/src/auth/provider.ts").unwrap(),
            "https/github.com/443/acme/projects",
        );
    }

    #[test]
    fn test_gitlab_blob_all_trait_methods() {
        let url =
            url::Url::parse("https://gitlab.com/group/subgroup/project/-/blob/dev/src/main.rs")
                .unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "group/subgroup",
            "project",
            "dev",
            "src/main.rs",
            &url::Url::parse("https://gitlab.com/group/subgroup/project/-/raw/dev/src/main.rs")
                .unwrap(),
            "https/gitlab.com/443/group/subgroup/project",
        );
    }

    #[test]
    fn test_gitlab_raw_all_trait_methods() {
        let url = url::Url::parse("https://gitlab.com/group/project/-/raw/main/file.txt").unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "group",
            "project",
            "main",
            "file.txt",
            &url,
            "https/gitlab.com/443/group/project",
        );
    }

    #[test]
    fn test_gitlab_nested_namespace_trait_methods() {
        let url = url::Url::parse("https://gitlab.com/enterprise/engineering/platform/app/-/blob/production/config/settings.toml").unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "enterprise/engineering/platform",
            "app",
            "production",
            "config/settings.toml",
            &url::Url::parse("https://gitlab.com/enterprise/engineering/platform/app/-/raw/production/config/settings.toml").unwrap(),
            "https/gitlab.com/443/enterprise/engineering/platform/app",
        );
    }

    #[test]
    fn test_gitlab_nested_path_trait_methods() {
        let url =
            url::Url::parse("https://gitlab.com/group/project/-/blob/deploy/lib/utils/helpers.js")
                .unwrap();
        let forge = ForgeInfo::new(&url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "group",
            "project",
            "deploy",
            "lib/utils/helpers.js",
            &url::Url::parse("https://gitlab.com/group/project/-/raw/deploy/lib/utils/helpers.js")
                .unwrap(),
            "https/gitlab.com/443/group/project",
        );
    }

    #[test]
    fn test_forge_trait_methods_delegation_github() {
        let github = ForgeInfo::new(
            &url::Url::parse("https://github.com/owner/repo/blob/main/file.json").unwrap(),
        )
        .unwrap();

        assert_eq!(github.owner(), "owner");
        assert_eq!(github.repo(), "repo");
        assert_eq!(github.branch(), "main");
        assert_eq!(github.file_path(), PathBuf::from("file.json"));
        assert_eq!(
            github.raw_url(),
            &url::Url::parse("https://raw.githubusercontent.com/owner/repo/main/file.json")
                .unwrap()
        );
        assert_eq!(github.project_id(), "https/github.com/443/owner/repo");

        match &github {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), github.owner());
                assert_eq!(info.repo(), github.repo());
                assert_eq!(info.branch(), github.branch());
                assert_eq!(info.file_path(), github.file_path());
                assert_eq!(info.raw_url(), github.raw_url());
                assert_eq!(info.project_id(), github.project_id());
            }
            _ => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    fn test_forge_trait_methods_delegation_gitlab() {
        let gitlab = ForgeInfo::new(
            &url::Url::parse("https://gitlab.com/ns/proj/-/blob/main/file.json").unwrap(),
        )
        .unwrap();

        assert_eq!(gitlab.owner(), "ns");
        assert_eq!(gitlab.repo(), "proj");
        assert_eq!(gitlab.branch(), "main");
        assert_eq!(gitlab.file_path(), PathBuf::from("file.json"));
        assert_eq!(
            gitlab.raw_url(),
            &url::Url::parse("https://gitlab.com/ns/proj/-/raw/main/file.json").unwrap()
        );
        assert_eq!(gitlab.project_id(), "https/gitlab.com/443/ns/proj");

        match &gitlab {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), gitlab.owner());
                assert_eq!(info.repo(), gitlab.repo());
                assert_eq!(info.branch(), gitlab.branch());
                assert_eq!(info.file_path(), gitlab.file_path());
                assert_eq!(info.raw_url(), gitlab.raw_url());
                assert_eq!(info.project_id(), gitlab.project_id());
            }
            _ => panic!("Expected GitLab variant"),
        }
    }
}
