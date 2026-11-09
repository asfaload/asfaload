use crate::error::ForgeUrlError;
use crate::github::GITHUB_HOSTS;
use crate::gitlab::GITLAB_HOSTS;
use crate::traits::ForgesPathMethods;
use constants::INDEX_FILE;
use url::Url;

pub struct GithubForge;

impl ForgesPathMethods for GithubForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        path.replace("/releases/download/", "/releases/tag/")
    }

    fn translate_release_to_download_path(&self, path: &str) -> String {
        path.replace("/releases/tag/", "/releases/download/")
    }
}

pub struct GitlabForge;

impl ForgesPathMethods for GitlabForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        // GitLab URLs already use the release path directly.
        // Unlike GitHub (/releases/download/ -> /releases/tag/),
        // GitLab stores at /-/releases/tag/ which matches the URL structure.
        path.to_string()
    }

    fn translate_release_to_download_path(&self, path: &str) -> String {
        path.to_string()
    }
}

pub struct FileServerForge;

impl ForgesPathMethods for FileServerForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        path.to_string()
    }

    fn translate_release_to_download_path(&self, path: &str) -> String {
        path.to_string()
    }
}

pub enum Forges {
    Github(GithubForge),
    Gitlab(GitlabForge),
    FileServer(FileServerForge),
}

impl Forges {
    pub fn from_host(host: &str) -> Result<Self, ForgeUrlError> {
        if GITHUB_HOSTS.contains(&host) {
            Ok(Self::Github(GithubForge))
        } else if GITLAB_HOSTS.contains(&host) {
            Ok(Self::Gitlab(GitlabForge))
        } else {
            Ok(Self::FileServer(FileServerForge))
        }
    }

    pub fn from_type_str(type_str: &str) -> Result<Self, ForgeUrlError> {
        match type_str {
            "github" => Ok(Self::Github(GithubForge)),
            "gitlab" => Ok(Self::Gitlab(GitlabForge)),
            "fileserver" => Ok(Self::FileServer(FileServerForge)),
            other => Err(ForgeUrlError::UnsupportedForge(other.to_string())),
        }
    }
}

impl ForgesPathMethods for Forges {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        match self {
            Self::Github(f) => f.translate_download_to_release_path(path),
            Self::Gitlab(f) => f.translate_download_to_release_path(path),
            Self::FileServer(f) => f.translate_download_to_release_path(path),
        }
    }

    fn translate_release_to_download_path(&self, path: &str) -> String {
        match self {
            Self::Github(f) => f.translate_release_to_download_path(path),
            Self::Gitlab(f) => f.translate_release_to_download_path(path),
            Self::FileServer(f) => f.translate_release_to_download_path(path),
        }
    }
}

pub fn get_forge(file_url: &Url) -> Result<Forges, ForgeUrlError> {
    let host = file_url
        .host_str()
        .ok_or_else(|| ForgeUrlError::InvalidFormat("URL has no host".to_string()))?;
    Forges::from_host(host)
}

/// The URL of the directory that holds the artifacts of a release, built from
/// the repository path of its index, for example
/// `https/github.com/443/owner/repo/releases/tag/v1.0/asfaload.index.json`
/// gives `https://github.com/owner/repo/releases/download/v1.0/`.
///
/// It is the reverse of `construct_index_file_path`. The result is accepted
/// only if an artifact URL in the directory gives `index_path` again, so a
/// path that `construct_index_file_path` cannot produce is an error.
pub fn artifacts_url_prefix_for_index_path(index_path: &str) -> Result<Url, ForgeUrlError> {
    let invalid = || ForgeUrlError::InvalidFormat(format!("Not an index file path: {index_path}"));
    let dir_path = index_path
        .strip_suffix(&format!("/{INDEX_FILE}"))
        .ok_or_else(invalid)?;
    let mut parts = dir_path.splitn(4, '/');
    let (scheme, host, port, release_path) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(scheme), Some(host), Some(port), Some(release_path)) => {
                (scheme, host, port, release_path)
            }
            _ => return Err(invalid()),
        };
    let port: u16 = port.parse().map_err(|_| invalid())?;
    let mut url = Url::parse(&format!("{scheme}://{host}:{port}/")).map_err(|_| invalid())?;
    let forge = Forges::from_host(host)?;
    url.set_path(&format!(
        "{}/",
        forge.translate_release_to_download_path(release_path)
    ));

    // The URL parser normalises its input, so a path with unusual characters
    // could give a URL for another location.
    let artifact_url = url.join("artifact").map_err(|_| invalid())?;
    if forge.construct_index_file_path(&artifact_url)? != index_path {
        return Err(invalid());
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- translate (github) ---
    #[test]
    fn translate_github_release_path_standard() {
        assert_eq!(
            GithubForge.translate_download_to_release_path("owner/repo/releases/download/v1.0"),
            "owner/repo/releases/tag/v1.0"
        );
    }

    #[test]
    fn translate_github_release_path_no_match() {
        assert_eq!(
            GithubForge.translate_download_to_release_path("owner/repo/some/path"),
            "owner/repo/some/path"
        );
    }

    #[test]
    fn translate_github_release_path_empty() {
        assert_eq!(GithubForge.translate_download_to_release_path(""), "");
    }

    // --- translate (gitlab + fileserver are identity) ---
    #[test]
    fn translate_gitlab_release_path_identity() {
        assert_eq!(
            GitlabForge
                .translate_download_to_release_path("namespace/project/-/releases/v1.0/downloads"),
            "namespace/project/-/releases/v1.0/downloads"
        );
    }

    #[test]
    fn translate_fileserver_path_identity() {
        assert_eq!(
            FileServerForge.translate_download_to_release_path("some/path/to/files"),
            "some/path/to/files"
        );
    }

    // --- from_host ---
    #[test]
    fn from_host_github() {
        assert!(matches!(
            Forges::from_host("github.com"),
            Ok(Forges::Github(_))
        ));
    }

    #[test]
    fn from_host_gitlab() {
        assert!(matches!(
            Forges::from_host("gitlab.com"),
            Ok(Forges::Gitlab(_))
        ));
    }

    #[test]
    fn from_host_unknown_falls_back_to_fileserver() {
        assert!(matches!(
            Forges::from_host("example.com"),
            Ok(Forges::FileServer(_))
        ));
    }

    // --- from_type_str ---
    #[test]
    fn from_type_str_github() {
        assert!(matches!(
            Forges::from_type_str("github"),
            Ok(Forges::Github(_))
        ));
    }

    #[test]
    fn from_type_str_gitlab() {
        assert!(matches!(
            Forges::from_type_str("gitlab"),
            Ok(Forges::Gitlab(_))
        ));
    }

    #[test]
    fn from_type_str_fileserver() {
        assert!(matches!(
            Forges::from_type_str("fileserver"),
            Ok(Forges::FileServer(_))
        ));
    }

    #[test]
    fn from_type_str_unknown() {
        assert!(matches!(
            Forges::from_type_str("bitbucket"),
            Err(ForgeUrlError::UnsupportedForge(_))
        ));
    }

    // --- get_forge ---
    #[test]
    fn get_forge_no_host_errors() {
        let url = Url::parse("file:///some/path/file.txt").unwrap();
        assert!(matches!(
            get_forge(&url),
            Err(ForgeUrlError::InvalidFormat(_))
        ));
    }

    // --- construct_file_repo_path / construct_index_file_path ---
    #[test]
    fn construct_file_repo_path_standard_github_url() {
        let url =
            Url::parse("https://github.com/owner/repo/releases/download/v1.0/file.tar.gz").unwrap();
        let forge = get_forge(&url).unwrap();
        assert_eq!(
            forge.construct_file_repo_path(&url, "index.json").unwrap(),
            "https/github.com/443/owner/repo/releases/tag/v1.0/index.json"
        );
    }

    #[test]
    fn construct_index_file_path_happy_path() {
        let url = Url::parse("https://github.com/owner/repo/releases/download/v2.0/artifact.zip")
            .unwrap();
        let forge = get_forge(&url).unwrap();
        let result = forge.construct_index_file_path(&url).unwrap();
        assert!(result.ends_with(INDEX_FILE));
        assert!(result.starts_with("https/github.com/443/owner/repo/releases/tag/v2.0/"));
    }

    #[test]
    fn construct_index_file_path_unknown_host_uses_fileserver() {
        let url = Url::parse("https://example.com/owner/repo/-/releases/file.tar.gz").unwrap();
        let forge = get_forge(&url).unwrap();
        assert!(matches!(forge, Forges::FileServer(_)));
        assert_eq!(
            forge.construct_index_file_path(&url).unwrap(),
            format!("https/example.com/443/owner/repo/-/releases/{}", INDEX_FILE)
        );
    }

    #[test]
    fn construct_signers_file_path_standard_github_url() {
        let url =
            Url::parse("https://github.com/owner/repo/releases/download/v1.0/file.tar.gz").unwrap();
        let forge = get_forge(&url).unwrap();
        let signers_filename = format!("{}.signers.json", INDEX_FILE);
        assert_eq!(
            forge
                .construct_file_repo_path(&url, &signers_filename)
                .unwrap(),
            "https/github.com/443/owner/repo/releases/tag/v1.0/asfaload.index.json.signers.json"
        );
    }

    #[test]
    fn construct_file_repo_path_fileserver_url() {
        let url =
            Url::parse("https://files.example.com/public/releases/v1.0/installer.tar.gz").unwrap();
        let forge = Forges::from_type_str("fileserver").unwrap();
        assert_eq!(
            forge
                .construct_file_repo_path(&url, "asfaload.index.json")
                .unwrap(),
            "https/files.example.com/443/public/releases/v1.0/asfaload.index.json"
        );
    }

    #[test]
    fn construct_file_repo_path_gitlab_url() {
        let url = Url::parse("https://gitlab.com/ns/project/-/releases/v1.0/downloads/file.tar.gz")
            .unwrap();
        let forge = Forges::from_type_str("gitlab").unwrap();
        assert_eq!(
            forge
                .construct_file_repo_path(&url, "asfaload.index.json")
                .unwrap(),
            "https/gitlab.com/443/ns/project/-/releases/v1.0/downloads/asfaload.index.json"
        );
    }

    // --- translate back (download path from release path) ---
    #[test]
    fn translate_release_to_download_path_cases() {
        let cases: Vec<(Forges, &str, &str)> = vec![
            (
                Forges::Github(GithubForge),
                "owner/repo/releases/tag/v1.0",
                "owner/repo/releases/download/v1.0",
            ),
            (
                Forges::Github(GithubForge),
                "owner/repo/some/path",
                "owner/repo/some/path",
            ),
            (
                Forges::Gitlab(GitlabForge),
                "ns/project/-/releases/v1.0/downloads",
                "ns/project/-/releases/v1.0/downloads",
            ),
            (
                Forges::FileServer(FileServerForge),
                "public/releases/v1.0",
                "public/releases/v1.0",
            ),
        ];
        for (forge, release_path, expected) in cases {
            assert_eq!(
                forge.translate_release_to_download_path(release_path),
                expected,
                "release path {release_path:?}"
            );
        }
    }

    // --- artifacts_url_prefix_for_index_path ---
    #[test]
    fn artifacts_url_prefix_reverses_construct_index_file_path() {
        // (artifact URL, expected prefix)
        let cases = [
            (
                "https://github.com/owner/repo/releases/download/v1.0/file.tar.gz",
                "https://github.com/owner/repo/releases/download/v1.0/",
            ),
            (
                "https://gitlab.com/ns/project/-/releases/v1.0/downloads/file.tar.gz",
                "https://gitlab.com/ns/project/-/releases/v1.0/downloads/",
            ),
            (
                "https://files.example.com/public/releases/v1.0/installer.tar.gz",
                "https://files.example.com/public/releases/v1.0/",
            ),
            (
                "http://localhost:8080/releases/v1.0/installer.tar.gz",
                "http://localhost:8080/releases/v1.0/",
            ),
            (
                "https://example.com/installer.tar.gz",
                "https://example.com/",
            ),
        ];
        for (artifact_url, expected_prefix) in cases {
            let artifact_url = Url::parse(artifact_url).unwrap();
            let index_path = get_forge(&artifact_url)
                .unwrap()
                .construct_index_file_path(&artifact_url)
                .unwrap();

            let prefix = artifacts_url_prefix_for_index_path(&index_path).unwrap();

            assert_eq!(prefix.as_str(), expected_prefix, "index path {index_path}");
        }
    }

    #[test]
    fn artifacts_url_prefix_rejects_invalid_index_paths() {
        let cases = [
            "https/github.com/443/owner/repo/releases/tag/v1.0/other.json",
            "https/github.com/443/asfaload.index.json",
            "https/github.com/asfaload.index.json",
            "ftp/example.com/21/releases/asfaload.index.json",
            "https/example.com/no-port/releases/asfaload.index.json",
            "https/example.com/99999/releases/asfaload.index.json",
            "https/user@example.com/443/releases/asfaload.index.json",
            "https/example.com/443/a/../b/asfaload.index.json",
            "https/example.com/443/a b/asfaload.index.json",
            "https/example.com/443/releases?x=1/asfaload.index.json",
            "",
        ];
        for index_path in cases {
            assert!(
                artifacts_url_prefix_for_index_path(index_path).is_err(),
                "index path {index_path:?} should be rejected"
            );
        }
    }
}
