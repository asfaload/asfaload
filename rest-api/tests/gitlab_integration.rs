#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use std::path::PathBuf;

    use forge_url::{ForgeTrait, github::GitHubRepoInfo, gitlab::GitLabRepoInfo};

    #[test]
    fn test_forge_trait_polymorphism() {
        let github_url = "https://github.com/owner/repo/blob/main/file.json";
        let gitlab_url = "https://gitlab.com/namespace/project/-/raw/main/file.json";

        let github_info = GitHubRepoInfo::new(&url::Url::parse(github_url).unwrap()).unwrap();
        let gitlab_info = GitLabRepoInfo::new(&url::Url::parse(gitlab_url).unwrap()).unwrap();

        assert!(github_info.project_id().contains("github.com"));
        assert!(gitlab_info.project_id().contains("gitlab.com"));

        assert!(!github_info.owner().is_empty());
        assert!(!gitlab_info.owner().is_empty());
        assert!(!github_info.repo().is_empty());
        assert!(!gitlab_info.repo().is_empty());
        assert!(!github_info.branch().is_empty());
        assert!(!gitlab_info.branch().is_empty());
    }

    #[test]
    fn test_forge_trait_methods_consistency() {
        let github_url = "https://github.com/test-org/test-repo/blob/develop/assets/signers.json";
        let gitlab_url =
            "https://gitlab.com/test-namespace/test-project/-/blob/develop/assets/signers.json";

        let github_info = GitHubRepoInfo::new(&url::Url::parse(github_url).unwrap()).unwrap();
        let gitlab_info = GitLabRepoInfo::new(&url::Url::parse(gitlab_url).unwrap()).unwrap();

        assert_eq!(github_info.owner(), "test-org");
        assert_eq!(gitlab_info.owner(), "test-namespace");

        assert_eq!(github_info.repo(), "test-repo");
        assert_eq!(gitlab_info.repo(), "test-project");

        assert_eq!(github_info.branch(), "develop");
        assert_eq!(gitlab_info.branch(), "develop");

        assert!(github_info.file_path().ends_with("assets/signers.json"));
        assert!(gitlab_info.file_path().ends_with("assets/signers.json"));

        assert!(
            github_info
                .raw_url()
                .as_str()
                .contains("raw.githubusercontent.com")
        );
        assert!(gitlab_info.raw_url().as_str().contains("gitlab.com"));
    }

    #[test]
    fn test_forge_trait_project_id_format() {
        let github_url = "https://github.com/my-org/my-repo/blob/main/test.json";
        let gitlab_url = "https://gitlab.com/group/subgroup/my-project/-/raw/main/test.json";

        let github_info = GitHubRepoInfo::new(&url::Url::parse(github_url).unwrap()).unwrap();
        let gitlab_info = GitLabRepoInfo::new(&url::Url::parse(gitlab_url).unwrap()).unwrap();

        assert_eq!(
            github_info.project_id(),
            "https/github.com/443/my-org/my-repo"
        );
        assert_eq!(
            gitlab_info.project_id(),
            "https/gitlab.com/443/group/subgroup/my-project"
        );
    }

    #[test]
    fn test_forge_trait_raw_url_construction() {
        let github_blob_url = "https://github.com/owner/repo/blob/main/path/to/file.json";
        let github_info = GitHubRepoInfo::new(&url::Url::parse(github_blob_url).unwrap()).unwrap();
        assert_eq!(
            github_info.raw_url(),
            &url::Url::parse("https://raw.githubusercontent.com/owner/repo/main/path/to/file.json")
                .unwrap()
        );

        let github_raw_url = "https://raw.githubusercontent.com/owner/repo/main/path/to/file.json";
        let github_info_raw =
            GitHubRepoInfo::new(&url::Url::parse(github_raw_url).unwrap()).unwrap();
        assert_eq!(
            github_info_raw.raw_url(),
            &url::Url::parse("https://raw.githubusercontent.com/owner/repo/main/path/to/file.json")
                .unwrap()
        );

        let gitlab_blob_url = "https://gitlab.com/namespace/project/-/blob/main/path/to/file.json";
        let gitlab_info = GitLabRepoInfo::new(&url::Url::parse(gitlab_blob_url).unwrap()).unwrap();
        assert_eq!(
            gitlab_info.raw_url(),
            &url::Url::parse("https://gitlab.com/namespace/project/-/raw/main/path/to/file.json")
                .unwrap()
        );

        let gitlab_raw_url = "https://gitlab.com/namespace/project/-/raw/main/path/to/file.json";
        let gitlab_info_raw =
            GitLabRepoInfo::new(&url::Url::parse(gitlab_raw_url).unwrap()).unwrap();
        assert_eq!(
            gitlab_info_raw.raw_url(),
            &url::Url::parse("https://gitlab.com/namespace/project/-/raw/main/path/to/file.json")
                .unwrap()
        );
    }

    #[test]
    fn test_forge_trait_interchangeable_usage_generic() {
        fn process_forge_url<F: ForgeTrait>(forge: &F) -> String {
            format!(
                "{}: {} on branch {} at {}",
                forge.url_info().project_id(),
                forge.repo(),
                forge.branch(),
                forge
                    .url_info()
                    .file_path()
                    .unwrap_or(&PathBuf::new())
                    .display()
            )
        }

        let github_info = GitHubRepoInfo::new(
            &url::Url::parse("https://github.com/user/repo/blob/feature/file.json").unwrap(),
        )
        .unwrap();
        let gitlab_info = GitLabRepoInfo::new(
            &url::Url::parse("https://gitlab.com/ns/proj/-/blob/feature/file.json").unwrap(),
        )
        .unwrap();

        let github_result = process_forge_url(&github_info);
        let gitlab_result = process_forge_url(&gitlab_info);

        assert!(github_result.contains("github.com"));
        assert!(github_result.contains("repo"));
        assert!(github_result.contains("feature"));

        assert!(gitlab_result.contains("gitlab.com"));
        assert!(gitlab_result.contains("proj"));
        assert!(gitlab_result.contains("feature"));
    }

    #[test]
    fn test_github_and_gitlab_implement_same_trait() {
        fn validate_trait_impl<T: ForgeTrait>(info: &T, expected_project_id: &str) {
            assert_eq!(info.url_info().project_id(), expected_project_id);
            assert!(!info.owner().is_empty());
            assert!(!info.repo().is_empty());
        }

        let github = GitHubRepoInfo::new(
            &url::Url::parse("https://github.com/org/repo/blob/main/file.json").unwrap(),
        )
        .unwrap();
        let gitlab = GitLabRepoInfo::new(
            &url::Url::parse("https://gitlab.com/ns/proj/-/raw/main/file.json").unwrap(),
        )
        .unwrap();

        validate_trait_impl(&github, "https/github.com/443/org/repo");
        validate_trait_impl(&gitlab, "https/gitlab.com/443/ns/proj");
    }

    #[test]
    fn test_trait_methods_work_identically() {
        fn get_branch_info<T: ForgeTrait>(info: &T) -> (String, String, String) {
            (
                info.url_info().project_id(),
                info.branch().to_string(),
                info.url_info()
                    .file_path()
                    .unwrap_or(&PathBuf::new())
                    .to_string_lossy()
                    .to_string(),
            )
        }

        let github = GitHubRepoInfo::new(
            &url::Url::parse("https://github.com/test/test/blob/v1.0/config.json").unwrap(),
        )
        .unwrap();
        let gitlab = GitLabRepoInfo::new(
            &url::Url::parse("https://gitlab.com/test/test/-/blob/v1.0/config.json").unwrap(),
        )
        .unwrap();

        let github_info = get_branch_info(&github);
        let gitlab_info = get_branch_info(&gitlab);

        assert_eq!(github_info.1, "v1.0");
        assert_eq!(gitlab_info.1, "v1.0");
        assert_eq!(github_info.2, "config.json");
        assert_eq!(gitlab_info.2, "config.json");
    }
}
