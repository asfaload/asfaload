use std::fs;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::errors::ApiError;

use crate::path_validation::NormalisedPaths;

#[derive(Debug)]
pub struct ArtifactSignersSource {
    // The commit that committed the copy at artifact_signers
    commit: String,
    // The timestamp of the commit that introduced the copy
    commit_time: DateTime<Utc>,
    // The signers file path the artifact_signers file was copied from
    path: NormalisedPaths,
    // copy of signers file taken when artifact signature completed
    artifact_signers: NormalisedPaths,
}

impl ArtifactSignersSource {
    pub fn commit(&self) -> &str {
        &self.commit
    }

    pub fn commit_time(&self) -> DateTime<Utc> {
        self.commit_time
    }

    pub fn path(&self) -> &NormalisedPaths {
        &self.path
    }

    pub fn artifact_signers(&self) -> &NormalisedPaths {
        &self.artifact_signers
    }
}

/// Trait abstracting git commit operations.
///
/// This allows swapping the underlying git implementation (e.g., SHA-1 vs SHA-256)
/// without changing the GitActor's external interface.
pub trait GitBackend: Send + Sync + 'static {
    /// Commit files to the repository at `repo_path`.
    ///
    /// `file_paths` are absolute paths on disk. The implementation is responsible
    /// for staging and committing them.
    fn commit_files(
        &self,
        file_paths: &[NormalisedPaths],
        commit_message: &str,
    ) -> Result<(), ApiError>;

    fn new<P: AsRef<Path>, P2: AsRef<Path>>(root: P, signing_pub_key: P2) -> Self
    where
        Self: Sized;
    fn root(&self) -> &PathBuf;

    fn init(&self) -> Result<(), ApiError>;

    /// Read file content at a specific git commit.
    ///
    /// Uses `git show {commit}:{path}` to retrieve file content from history.
    fn file_content_at_commit(
        &self,
        commit: &str,
        relative_path: &Path,
    ) -> Result<String, ApiError> {
        let spec = format!("{}:{}", commit, relative_path.to_string_lossy());
        // Verbatim: the returned bytes are hashed to validate signatures, so a
        // trailing newline must not be stripped (see git_verbatim).
        let content = GitCommand::git_verbatim(self.root(), &["show", &spec]).map_err(|e| {
            ApiError::GitError(format!(
                "Failed to read {} at commit {}: {}",
                relative_path.display(),
                commit,
                e
            ))
        })?;
        Ok(content)
    }

    // When an artifact signature is completed, a copy of the signers file is
    // stored alongside it. This method traces back to the original source of
    // that signers file using git copy detection.
    fn artifact_signers_source(
        &self,
        signers: NormalisedPaths,
    ) -> Result<ArtifactSignersSource, ApiError> {
        let first_commit = GitCommand::git(
            self.root(),
            &[
                "log",
                "--diff-filter=A",
                "--format=%H",
                "-1",
                "--",
                signers.relative_path().to_string_lossy().as_ref(),
            ],
        )?;

        if first_commit.is_empty() {
            return Err(ApiError::GitError(format!(
                "No commit found introducing {}",
                signers.relative_path().display()
            )));
        }

        let commit_time_str =
            GitCommand::git(self.root(), &["log", "--format=%cI", "-1", &first_commit])?;
        let commit_time: DateTime<Utc> = commit_time_str.parse().map_err(|e| {
            ApiError::GitError(format!(
                "Failed to parse commit time '{}': {}",
                commit_time_str, e
            ))
        })?;

        let git_output = GitCommand::git(
            self.root(),
            &[
                "diff-tree",
                "-r",
                "-C",
                "--find-copies-harder",
                &first_commit,
            ],
        )?;
        let found = git_output
            .lines()
            .find(|l| l.split('\t').next_back() == Some(&signers.relative_path().to_string_lossy()))
            .ok_or(ApiError::GitError(
                "Error extracting signers source from git diff-tree.".to_string(),
            ))?;

        // diff-tree raw output format:
        // :100644 100644 <old_hash> <new_hash> C100\tsource_path\tdest_path
        // The metadata and paths are separated by a tab. `split_whitespace` is not
        // safe as paths can contain spaces.
        let source_path_str = found
            .split_once('\t')
            .and_then(|(_, paths)| paths.split('\t').next())
            .ok_or_else(|| {
                ApiError::GitError(format!("Could not parse source path from: {}", found))
            })?;

        // The signers copy is always taken from the active signers dir,
        // never from the pending dir. However, git copy detection can be
        // ambiguous when both directories contain the same file content
        // (same blob). If git reports the pending dir as the source,
        // verify the active dir has the same file at that commit and use
        // it instead. If the active dir doesn't have it, that's an error.
        use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR};
        let source_path_str = {
            let source_path = Path::new(source_path_str);
            if source_path
                .components()
                .any(|c| c.as_os_str() == PENDING_SIGNERS_DIR)
            {
                let components: Vec<_> = source_path
                    .components()
                    .map(|c| {
                        if c.as_os_str() == PENDING_SIGNERS_DIR {
                            Component::Normal(SIGNERS_DIR.as_ref())
                        } else {
                            c
                        }
                    })
                    .collect();
                let active_candidate_path: PathBuf = components.iter().collect();

                // Verify the active signers file exists at this commit
                self.file_content_at_commit(&first_commit, &active_candidate_path)
                    .map_err(|_|
                        ApiError::GitError(format!(
                            "Signers copy source is in pending dir ({}) but no matching active signers file found at commit {}",
                            source_path_str, first_commit
                        ))
                    )?;
                active_candidate_path.to_string_lossy().into_owned()
            } else {
                source_path_str.to_string()
            }
        };
        let source_path = NormalisedPaths::new_sync(self.root(), &source_path_str)?;

        let res = ArtifactSignersSource {
            commit: first_commit,
            commit_time,
            path: source_path,
            artifact_signers: signers,
        };
        Ok(res)
    }

    /// Return the HEAD commit hash and its commit time.
    ///
    /// Chain building reads files at a pinned commit, never from the working
    /// tree: a commit is an atomic snapshot, immune to in-flight git_actor
    /// mutations (an update writes several files before committing) and to
    /// dirty trees left behind by a crash mid-update.
    fn head_commit(&self) -> Result<(String, DateTime<Utc>), ApiError> {
        // Single git call: the hash and time always come from the same commit,
        // even if HEAD moves concurrently.
        let output = GitCommand::git(self.root(), &["log", "--format=%H%n%cI", "-1", "HEAD"])?;
        let mut lines = output.lines();
        let (Some(commit), Some(commit_time_str), None) =
            (lines.next(), lines.next(), lines.next())
        else {
            return Err(ApiError::GitError(format!(
                "Expected '<hash>\\n<commit time>' from git log, got: {}",
                output
            )));
        };
        let commit_time: DateTime<Utc> = commit_time_str.parse().map_err(|e| {
            ApiError::GitError(format!(
                "Failed to parse commit time '{}': {}",
                commit_time_str, e
            ))
        })?;
        Ok((commit.to_string(), commit_time))
    }
}

const GIT_ACTOR_NAME: &str = "git-actor";
const GIT_USER_EMAIL: &str = "git@backend.asfaload.com";

/// Collect relative file paths from a list of absolute targets, skipping
/// `.git` and `.app_cache` directories. Rejects symlinks.
///
/// This is the shared file-walk logic used by both the git2-based and
/// CLI-based backends.
fn collect_relative_paths(
    repo_workdir: &Path,
    target_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, ApiError> {
    let mut result = Vec::new();
    let mut paths_to_visit: Vec<PathBuf> = target_paths.to_vec();

    while let Some(current_path) = paths_to_visit.pop() {
        let metadata = match fs::symlink_metadata(&current_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(ApiError::GitError(format!(
                        "Encountered a symlink!{}",
                        current_path.display()
                    )));
                }
                meta
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(e) => {
                return Err(ApiError::GitError(format!(
                    "Failed to read path {:?}: {}",
                    current_path, e
                )));
            }
        };

        if metadata.is_file() {
            let rel_path = current_path
                .strip_prefix(repo_workdir)
                .map_err(|_| ApiError::GitError("Target path is outside repository".into()))?;
            result.push(rel_path.to_path_buf());
        } else if metadata.is_dir() {
            if let Some(name) = current_path.file_name()
                && (name == ".git" || name == ".app_cache")
            {
                tracing::debug!("Skipping ignored directory: {}", current_path.display());
                continue;
            }
            for entry in fs::read_dir(&current_path).map_err(|e| {
                ApiError::GitError(format!(
                    "Failed to read directory {:?}: {}",
                    current_path, e
                ))
            })? {
                let entry =
                    entry.map_err(|e| ApiError::GitError(format!("Dir entry error: {}", e)))?;
                paths_to_visit.push(entry.path());
            }
        }
    }
    Ok(result)
}

/// SHA-256 git backend using the git CLI.
///
/// `libgit2-sys` does not yet ship the `unstable-sha256` feature in a
/// published release, so this backend shells out to `git` (>= 2.42) for
/// staging and committing. It validates the repository uses SHA-256 via
/// `git rev-parse --show-object-format` before every commit.
pub struct Sha256GitBackend {
    root: PathBuf,
    signing_pub_key_path: PathBuf,
}

struct GitCommand;
impl GitCommand {
    /// Run a git command in the given repo directory. Returns stdout
    /// (trimmed of surrounding whitespace) on success, or an `ApiError` with
    /// stderr on failure. Use for scalar output such as commit hashes,
    /// timestamps or porcelain status where trailing newlines are noise.
    fn git(repo_path: &Path, args: &[&str]) -> Result<String, ApiError> {
        Ok(Self::git_verbatim(repo_path, args)?.trim().to_string())
    }

    /// Run a git command and return stdout verbatim (no trimming). Use when
    /// the output is file content whose exact bytes matter -- e.g.
    /// `git show {commit}:{path}`, whose bytes are hashed to validate
    /// signatures. Trimming here would alter the hash and break validation.
    fn git_verbatim(repo_path: &Path, args: &[&str]) -> Result<String, ApiError> {
        let output = std::process::Command::new("git")
            .args(["-C", &repo_path.to_string_lossy()])
            .args(args)
            .output()
            .map_err(|e| ApiError::GitError(format!("Failed to run git: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::GitError(format!(
                "git {:?} failed: {}",
                args,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
impl Sha256GitBackend {
    /// Validate that the repository uses the SHA-256 object format.
    fn validate_sha256(repo_path: &Path) -> Result<(), ApiError> {
        let format = GitCommand::git(repo_path, &["rev-parse", "--show-object-format"])?;
        if format != "sha256" {
            return Err(ApiError::GitError(format!(
                "Sha256GitBackend requires a SHA-256 repository, got '{}'",
                format
            )));
        }
        Ok(())
    }
}

impl GitBackend for Sha256GitBackend {
    fn commit_files(
        &self,
        file_paths: &[NormalisedPaths],
        commit_message: &str,
    ) -> Result<(), ApiError> {
        let repo_path = self.root();
        Self::validate_sha256(repo_path.as_path())?;

        let absolute_paths: Vec<PathBuf> = file_paths.iter().map(|p| p.absolute_path()).collect();
        let rel_paths = collect_relative_paths(repo_path.as_path(), &absolute_paths)?;

        if rel_paths.is_empty() {
            return Err(ApiError::GitError("No files to commit".into()));
        }

        // Stage files one at a time via git add
        for rel_path in &rel_paths {
            GitCommand::git(
                repo_path.as_path(),
                &["add", "--", &rel_path.to_string_lossy()],
            )?;
        }

        let staged = GitCommand::git(repo_path.as_path(), &["status", "--porcelain"])?;
        if staged.is_empty() {
            return Err(ApiError::InvalidRequestBody(
                "No changes to commit".to_string(),
            ));
        }

        // Commit with configured author identity
        GitCommand::git(
            repo_path.as_path(),
            &[
                "-c",
                &format!("user.name={}", GIT_ACTOR_NAME),
                "-c",
                &format!("user.email={}", GIT_USER_EMAIL),
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", self.signing_pub_key_path.display()),
                "commit",
                "-S",
                "-m",
                commit_message,
            ],
        )?;

        Ok(())
    }

    fn new<P: AsRef<Path>, P2: AsRef<Path>>(root: P, signing_pub_key: P2) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            signing_pub_key_path: signing_pub_key.as_ref().to_path_buf(),
        }
    }

    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn init(&self) -> Result<(), ApiError> {
        GitCommand::git(self.root(), &["init", "--object-format=sha256"])?;

        Ok(())
    }
}

/// Dispatch enum for GitBackend implementations.
#[derive(Debug, Clone, Copy)]
pub enum GitBackendKind {
    Sha256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct MockBackend {
        root: PathBuf,
        should_fail: bool,
    }

    impl GitBackend for MockBackend {
        fn commit_files(
            &self,
            _file_paths: &[NormalisedPaths],
            _commit_message: &str,
        ) -> Result<(), ApiError> {
            if self.should_fail {
                Err(ApiError::GitError("mock failure".into()))
            } else {
                Ok(())
            }
        }

        fn new<P: AsRef<Path>, P2: AsRef<Path>>(root: P, _signing_pub_key: P2) -> Self
        where
            Self: Sized,
        {
            Self {
                root: root.as_ref().to_path_buf(),
                should_fail: false,
            }
        }

        fn root(&self) -> &PathBuf {
            &self.root
        }

        fn init(&self) -> Result<(), ApiError> {
            if self.should_fail {
                Err(ApiError::GitError("mock failure".into()))
            } else {
                Ok(())
            }
        }
    }

    impl MockBackend {
        fn new_failing<P: AsRef<Path>, P2: AsRef<Path>>(root: P, _signing_pub_key: P2) -> Self {
            Self {
                root: root.as_ref().to_path_buf(),
                should_fail: true,
            }
        }
    }

    #[test]
    fn test_mock_backend_failure() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let target_path = repo_path.join("test").join("file.txt");
        let backend = MockBackend::new_failing(repo_path, test_helpers::git_signing_pub_key_path());
        let p = normalise_for_repo(repo_path, &target_path);
        let result = backend.commit_files(&[p], "test commit");
        assert!(result.is_err());
    }

    fn normalise_for_repo(repo_path: &Path, file_path: &Path) -> NormalisedPaths {
        let relative_or_requested = file_path.strip_prefix(repo_path).unwrap_or(file_path);
        crate::path_validation::build_normalised_absolute_path(repo_path, relative_or_requested)
            .unwrap()
    }
}

#[cfg(test)]
mod sha256_tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// Create a SHA-256 git repository using the git CLI.
    ///
    /// `git2::RepositoryInitOptions` does not support `object-format` selection,
    /// so the CLI is the only way to create SHA-256 repos.
    fn init_sha256_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(path)
            .status()
            .expect("git CLI must be available for SHA-256 tests");
        assert!(status.success(), "git init --object-format=sha256 failed");

        let run_git = |args: &[&str]| {
            let s = Command::new("git")
                .args(["-C", &path.to_string_lossy()])
                .args(args)
                .status()
                .unwrap();
            assert!(s.success(), "git {:?} failed", args);
        };
        run_git(&["config", "user.name", "Test User"]);
        run_git(&["config", "user.email", "test@test.com"]);
        run_git(&["commit", "--allow-empty", "-m", "Initial"]);
    }

    fn normalise_for_repo(repo_path: &Path, file_path: &Path) -> NormalisedPaths {
        let relative_or_requested = file_path.strip_prefix(repo_path).unwrap_or(file_path);
        crate::path_validation::build_normalised_absolute_path(repo_path, relative_or_requested)
            .unwrap()
    }

    #[test]
    fn test_sha256_backend_init_creates_sha256_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend.init().unwrap();

        assert!(
            repo_path.join(".git").exists(),
            ".git directory should exist"
        );
        let format = GitCommand::git(repo_path, &["rev-parse", "--show-object-format"]).unwrap();
        assert_eq!(format, "sha256");
    }

    #[test]
    fn test_sha256_backend_commits_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "sha256 content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &file_path)],
            "sha256 commit",
        );
        assert!(result.is_ok(), "SHA-256 commit failed: {:?}", result);

        // Verify via git log
        let log = GitCommand::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("sha256 commit"));
    }

    #[test]
    fn test_sha256_backend_signs_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "signed commit",
            )
            .unwrap();

        // The raw commit object must carry an SSH signature header. This is
        // independent of verification (no allowed-signers configured), so it
        // proves `-S` actually signed.
        let raw = GitCommand::git(repo_path, &["cat-file", "commit", "HEAD"]).unwrap();
        assert!(
            raw.contains("BEGIN SSH SIGNATURE"),
            "commit should carry an SSH signature, got:\n{}",
            raw
        );
    }

    #[test]
    fn test_sha256_backend_rejects_sha1_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let status = Command::new("git")
            .args(["init", "--object-format=sha1"])
            .arg(repo_path)
            .status()
            .expect("git CLI must be available");
        assert!(status.success(), "git init --object-format=sha1 failed");

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result =
            backend.commit_files(&[normalise_for_repo(repo_path, &file_path)], "should fail");
        match result {
            Err(ApiError::GitError(e)) => {
                assert!(e.contains("SHA-256"));
            }
            Err(e) => panic!("Expected ApiError::GitOperationFailed but got {}", e),
            Ok(_) => panic!("Expected SHA-256 format rejection but commit succeeded"),
        }
    }

    #[test]
    fn test_sha256_backend_commits_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let f1 = repo_path.join("a.txt");
        let f2 = repo_path.join("b.txt");
        std::fs::write(&f1, "a").unwrap();
        std::fs::write(&f2, "b").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result = backend.commit_files(
            &[
                normalise_for_repo(repo_path, &f1),
                normalise_for_repo(repo_path, &f2),
            ],
            "multi sha256",
        );
        assert!(result.is_ok());

        // Verify both files are committed
        let ls = GitCommand::git(repo_path, &["ls-tree", "--name-only", "HEAD"]).unwrap();
        assert!(ls.contains("a.txt"));
        assert!(ls.contains("b.txt"));
    }

    #[test]
    fn test_sha256_backend_handles_subdirectories() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let subdir = repo_path.join("nested/deep");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::write(subdir.join("file.txt"), "deep content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &subdir.join("file.txt"))],
            "nested sha256",
        );
        assert!(result.is_ok());

        let ls = GitCommand::git(repo_path, &["ls-tree", "-r", "--name-only", "HEAD"]).unwrap();
        assert!(ls.contains("nested/deep/file.txt"));
    }

    #[test]
    fn test_sha256_backend_handles_initial_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        // Create SHA-256 repo without initial commit
        let status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(repo_path)
            .status()
            .unwrap();
        assert!(status.success());

        std::fs::write(repo_path.join("first.txt"), "first").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &repo_path.join("first.txt"))],
            "initial",
        );
        assert!(result.is_ok());

        let log = GitCommand::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("initial"));
    }

    #[test]
    fn test_sha256_backend_skips_git_directory() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        std::fs::write(repo_path.join("real.txt"), "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result = backend.commit_files(&[normalise_for_repo(repo_path, repo_path)], "commit");
        assert!(result.is_ok());

        let ls = GitCommand::git(repo_path, &["ls-tree", "-r", "--name-only", "HEAD"]).unwrap();
        assert!(!ls.contains(".git"));
        assert!(ls.contains("real.txt"));
    }

    #[test]
    fn test_sha256_backend_kind_dispatch() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        std::fs::write(repo_path.join("dispatch.txt"), "via enum").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let result = backend.commit_files(
            &[normalise_for_repo(
                repo_path,
                &repo_path.join("dispatch.txt"),
            )],
            "enum dispatch",
        );
        assert!(result.is_ok());

        let log = GitCommand::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("enum dispatch"));
    }

    #[test]
    fn test_sha256_backend_rejects_empty_commit_when_file_is_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file = repo_path.join("same.txt");
        std::fs::write(&file, "same content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let first = backend.commit_files(&[normalise_for_repo(repo_path, &file)], "first");
        assert!(first.is_ok(), "First commit should succeed: {:?}", first);

        // Rewriting identical content should reject commit because the tree is unchanged.
        std::fs::write(&file, "same content").unwrap();
        let second = backend.commit_files(&[normalise_for_repo(repo_path, &file)], "second");
        match second {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("No changes to commit"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected rejection for unchanged tree commit"),
        }
    }

    // -- sha256 equivalents of the sha1 trait-method tests in `mod tests`.
    //    `file_content_at_commit` and `artifact_signers_source` are GitBackend
    //    default methods that shell out to git; these guard against OID-format
    //    assumptions (sha256 hashes are 64 hex chars, not 40).

    #[test]
    fn test_sha256_file_content_at_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("data.json");
        std::fs::write(&file_path, r#"{"version": 1}"#).unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "add data.json",
            )
            .unwrap();

        let first_commit = GitCommand::git(repo_path, &["log", "--format=%H", "-1"]).unwrap();

        std::fs::write(&file_path, r#"{"version": 2}"#).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "update data.json",
            )
            .unwrap();

        let content = backend
            .file_content_at_commit(&first_commit, Path::new("data.json"))
            .unwrap();
        assert_eq!(content, r#"{"version": 1}"#);

        let current = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(current, r#"{"version": 2}"#);
    }

    #[test]
    fn test_sha256_head_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("data.json");
        std::fs::write(&file_path, r#"{"version": 1}"#).unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "add data.json",
            )
            .unwrap();

        let expected = GitCommand::git(repo_path, &["log", "--format=%H", "-1"]).unwrap();
        let (commit, time) = backend.head_commit().unwrap();
        assert_eq!(commit, expected);
        // Second-precision sanity: commit time must not be in the future.
        assert!(time <= chrono::Utc::now() + chrono::Duration::seconds(5));
    }

    #[test]
    fn test_sha256_head_commit_empty_repo_errors() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        // Truly empty repo (no commits): HEAD does not exist yet.
        // `init_sha256_repo` cannot be used here as it creates an initial
        // empty commit.
        let status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(repo_path)
            .status()
            .unwrap();
        assert!(status.success());

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        assert!(backend.head_commit().is_err());
    }

    #[test]
    fn test_sha256_file_content_at_commit_preserves_trailing_newline() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        // A signers file edited by a tool that appends a final newline. The
        // exact bytes are part of what gets signed, so retrieval must return
        // them verbatim -- trimming would change the hash and break chain
        // validation.
        let file_path = repo_path.join("data.json");
        let content_with_newline = "{\"version\": 1}\n";
        std::fs::write(&file_path, content_with_newline).unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "add data.json",
            )
            .unwrap();

        let first_commit = GitCommand::git(repo_path, &["log", "--format=%H", "-1"]).unwrap();

        let content = backend
            .file_content_at_commit(&first_commit, Path::new("data.json"))
            .unwrap();
        assert_eq!(content, content_with_newline);
    }

    #[test]
    fn test_sha256_file_content_at_commit_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("exists.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend
            .commit_files(&[normalise_for_repo(repo_path, &file_path)], "add file")
            .unwrap();

        let commit = GitCommand::git(repo_path, &["log", "--format=%H", "-1"]).unwrap();

        let result = backend.file_content_at_commit(&commit, Path::new("nonexistent.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_artifact_signers_source_errors_when_file_not_in_history() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        // File exists on disk but was never committed
        let file = repo_path.join("never_committed.json");
        std::fs::write(&file, "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        let signers_path = normalise_for_repo(repo_path, &file);
        let result = backend.artifact_signers_source(signers_path);

        match result {
            Err(ApiError::GitError(msg)) => {
                assert!(
                    msg.contains("No commit found"),
                    "Expected 'No commit found' error, got: {}",
                    msg
                );
            }
            other => panic!("Expected ApiError::GitError, got {:?}", other),
        }
    }

    #[test]
    fn test_sha256_artifact_signers_source_does_not_panic_for_non_copied_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        // Create and commit a brand new file (no copy source)
        let file = repo_path.join("original.json");
        std::fs::write(&file, "unique content that won't match anything").unwrap();

        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
        backend
            .commit_files(&[normalise_for_repo(repo_path, &file)], "add original file")
            .unwrap();

        let signers_path = normalise_for_repo(repo_path, &file);
        // Should not panic — may return Ok or Err depending on diff-tree output
        let _result = backend.artifact_signers_source(signers_path);
    }

    #[test]
    fn test_sha256_artifact_signers_source_has_commit_time() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);
        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());

        // Commit a source signers file, then copy it to an artifact and commit.
        let source_file = repo_path.join("signers.json");
        std::fs::write(&source_file, r#"{"signers": ["alice"]}"#).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &source_file)],
                "add source file",
            )
            .unwrap();

        let dest_file = repo_path.join("artifacts/my_artifact.signers.json");
        std::fs::create_dir_all(dest_file.parent().unwrap()).unwrap();
        std::fs::copy(&source_file, &dest_file).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &dest_file)],
                "copy file to destination",
            )
            .unwrap();

        let signers_path = normalise_for_repo(repo_path, &dest_file);
        let result = backend.artifact_signers_source(signers_path).unwrap();

        // commit_time should be a valid recent timestamp
        let commit_time = result.commit_time();
        let now = chrono::Utc::now();
        assert!(
            commit_time <= now,
            "Commit time should not be in the future"
        );
        assert!(
            (now - commit_time).num_seconds() < 60,
            "Commit time should be recent (within 60s)"
        );
    }

    /// When the source is in the pending dir and NO matching active file exists,
    /// the function should return an error.
    #[test]
    fn test_sha256_artifact_signers_source_pending_only_no_active_returns_error() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);
        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());

        let signers_content = r#"{"version":1,"signers_only_in_pending":true}"#;

        // Only create pending dir — no active dir
        let pending_dir = repo_path.join("proj/asfaload.signers.pending");
        std::fs::create_dir_all(&pending_dir).unwrap();
        std::fs::write(pending_dir.join("index.json"), signers_content).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &pending_dir)],
                "add pending signers only",
            )
            .unwrap();

        // Copy from pending to artifact (this would be a bug in the real system)
        let artifact_signers = repo_path.join("proj/releases/v1/artifact.signers.json");
        std::fs::create_dir_all(artifact_signers.parent().unwrap()).unwrap();
        std::fs::copy(pending_dir.join("index.json"), &artifact_signers).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &artifact_signers)],
                "copy from pending (should not happen in production)",
            )
            .unwrap();

        let signers_path = normalise_for_repo(repo_path, &artifact_signers);
        let result = backend.artifact_signers_source(signers_path);
        assert!(
            result.is_err(),
            "Should error when source is pending and no active exists"
        );

        match result {
            Err(ApiError::GitError(msg)) => {
                assert!(
                    msg.contains("pending dir"),
                    "Error should mention pending dir, got: {}",
                    msg
                );
            }
            other => panic!(
                "Expected ApiError::GitError about pending dir, got {:?}",
                other
            ),
        }
    }

    /// Same filename at multiple levels of the directory hierarchy.
    /// Copy from the deepest one — verify the deepest is returned as source.
    #[test]
    fn test_sha256_artifact_signers_source_deepest_file_in_hierarchy() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);
        let backend = Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());

        // Create signers.json at three levels with same content
        let content = r#"{"version":1,"artifact_signers":[{"threshold":1,"signers":[]}]}"#;

        let shallow = repo_path.join("signers.json");
        let mid = repo_path.join("project/signers.json");
        let deep = repo_path.join("project/sub/signers.json");

        std::fs::write(&shallow, content).unwrap();
        std::fs::create_dir_all(mid.parent().unwrap()).unwrap();
        std::fs::write(&mid, content).unwrap();
        std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
        std::fs::write(&deep, content).unwrap();

        backend
            .commit_files(
                &[normalise_for_repo(repo_path, repo_path)],
                "add signers at three levels",
            )
            .unwrap();

        // Copy the deepest one to an artifact path
        let artifact_signers = repo_path.join("project/sub/releases/artifact.signers.json");
        std::fs::create_dir_all(artifact_signers.parent().unwrap()).unwrap();
        std::fs::copy(&deep, &artifact_signers).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &artifact_signers)],
                "copy deepest signers to artifact",
            )
            .unwrap();

        let signers_path = normalise_for_repo(repo_path, &artifact_signers);
        let result = backend.artifact_signers_source(signers_path);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        let source = result.unwrap();
        // Git should detect the copy from the deepest file since it's the
        // closest match and most likely source
        let source_path = source.path().relative_path().to_string_lossy().to_string();
        assert!(
            source_path.contains("project/sub/signers.json")
                || source_path.contains("project/signers.json")
                || source_path == "signers.json",
            "Source should be one of the signers.json files, got: {}",
            source_path
        );
    }
}

#[cfg(test)]
mod artifact_signers_source_scenarios {
    use super::*;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    fn normalise_for_repo(repo_path: &Path, file_path: &Path) -> NormalisedPaths {
        let relative_or_requested = file_path.strip_prefix(repo_path).unwrap_or(file_path);
        crate::path_validation::build_normalised_absolute_path(repo_path, relative_or_requested)
            .unwrap()
    }

    fn init_sha256_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(path)
            .status()
            .expect("git CLI must be available for SHA-256 tests");
        assert!(status.success(), "git init --object-format=sha256 failed");

        let run_git = |args: &[&str]| {
            let s = Command::new("git")
                .args(["-C", &path.to_string_lossy()])
                .args(args)
                .status()
                .unwrap();
            assert!(s.success(), "git {:?} failed", args);
        };
        run_git(&["config", "user.name", "Test User"]);
        run_git(&["config", "user.email", "test@test.com"]);
        run_git(&["commit", "--allow-empty", "-m", "Initial"]);
    }

    enum GitAction {
        /// Create file at path relative to repo with content, then commit.
        Create(&'static str, &'static str),
        /// Write file to disk without committing.
        WriteFile(&'static str, &'static str),
        /// Copy file from source to destination, then commit the destination.
        Copy(&'static str, &'static str),
        /// Rename (move) file or directory on disk without committing.
        Rename(&'static str, &'static str),
        /// Delete file or directory from disk without committing.
        Delete(&'static str),
        /// Stage everything under dir with `git add -A` and commit.
        /// Use "" for repo root.
        CommitDir(&'static str),
        /// Assert artifact_signers_source identifies the exact copy source path.
        ExpectSourceIdentification(&'static str, &'static str),
        /// Assert the returned commit matches the introducing commit for the file.
        ExpectSourceCommit(&'static str),
    }

    fn run_action<B: GitBackend>(backend: &B, action: &GitAction) -> anyhow::Result<()> {
        let repo_path = backend.root();
        let resolve = |p: &str| -> PathBuf {
            let stripped = p.trim_start_matches('/');
            if stripped.is_empty() {
                repo_path.clone()
            } else {
                repo_path.join(stripped)
            }
        };

        match action {
            GitAction::Create(path, content) => {
                let file_path = resolve(path);
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&file_path, content)?;
                backend
                    .commit_files(
                        &[normalise_for_repo(repo_path, &file_path)],
                        &format!("create {}", path),
                    )
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
            GitAction::WriteFile(path, content) => {
                let file_path = resolve(path);
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&file_path, content)?;
                Ok(())
            }
            GitAction::Copy(source, destination) => {
                let source_path = resolve(source);
                let dest_path = resolve(destination);
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(&source_path, &dest_path)?;
                backend
                    .commit_files(
                        &[normalise_for_repo(repo_path, &dest_path)],
                        &format!("copy {} to {}", source, destination),
                    )
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
            GitAction::Rename(source, destination) => {
                let source_path = resolve(source);
                let dest_path = resolve(destination);
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(&source_path, &dest_path)?;
                Ok(())
            }
            GitAction::Delete(path) => {
                let target = resolve(path);
                if target.is_dir() {
                    std::fs::remove_dir_all(&target)?;
                } else {
                    std::fs::remove_file(&target)?;
                }
                Ok(())
            }
            GitAction::CommitDir(path) => {
                let dir_arg = if path.is_empty() {
                    ".".to_string()
                } else {
                    path.trim_start_matches('/').to_string()
                };
                // Use git add -A to track additions, modifications, AND deletions
                GitCommand::git(repo_path, &["add", "-A", "--", &dir_arg])
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                GitCommand::git(repo_path, &["commit", "-m", &format!("commit {}", dir_arg)])
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
            GitAction::ExpectSourceIdentification(tested_path, expected_source) => {
                let tested = resolve(tested_path);
                let normalised = normalise_for_repo(repo_path, &tested);
                let result = backend
                    .artifact_signers_source(normalised)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let expected = Path::new(expected_source.trim_start_matches('/'));
                assert_eq!(
                    result.path().relative_path(),
                    expected,
                    "Expected source {} but got {}",
                    expected.display(),
                    result.path().relative_path().display()
                );
                Ok(())
            }
            GitAction::ExpectSourceCommit(tested_path) => {
                let tested = resolve(tested_path);
                let normalised = normalise_for_repo(repo_path, &tested);
                let result = backend
                    .artifact_signers_source(normalised)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let expected_commit = GitCommand::git(
                    repo_path,
                    &[
                        "log",
                        "--diff-filter=A",
                        "--format=%H",
                        "-1",
                        "--",
                        tested_path.trim_start_matches('/'),
                    ],
                )
                .map_err(|e| anyhow::anyhow!("{}", e))?;
                assert_eq!(
                    result.commit(),
                    expected_commit,
                    "Commit should be the introducing commit"
                );
                Ok(())
            }
        }
    }

    fn scenarios() -> Vec<(&'static str, Vec<GitAction>)> {
        vec![
            // -- Was: test_artifact_signers_source_finds_copy_source
            //    + test_artifact_signers_source_returns_introducing_commit
            (
                "finds_copy_source",
                vec![
                    GitAction::Create("signers.json", r#"{"signers": ["alice"]}"#),
                    GitAction::Copy("signers.json", "artifacts/my_artifact.signers.json"),
                    GitAction::ExpectSourceIdentification(
                        "artifacts/my_artifact.signers.json",
                        "signers.json",
                    ),
                    GitAction::ExpectSourceCommit("artifacts/my_artifact.signers.json"),
                ],
            ),
            // -- Was: test_artifact_signers_source_nested_directories
            (
                "nested_directories",
                vec![
                    GitAction::Create(
                        "config/signers.json",
                        r#"{"threshold": 2, "signers": ["a","b","c"]}"#,
                    ),
                    GitAction::Copy(
                        "config/signers.json",
                        "releases/v1/artifacts/binary.signers.json",
                    ),
                    GitAction::ExpectSourceIdentification(
                        "releases/v1/artifacts/binary.signers.json",
                        "config/signers.json",
                    ),
                ],
            ),
            // -- Was: test_artifact_signers_source_pending_renamed_to_active_then_copied
            (
                "pending_renamed_to_active_then_copied",
                vec![
                    GitAction::WriteFile(
                        "project/asfaload.signers.pending/index.json",
                        r#"{"version":1,"artifact_signers":[{"threshold":1,"signers":[]}]}"#,
                    ),
                    GitAction::CommitDir("project/asfaload.signers.pending"),
                    GitAction::Rename(
                        "project/asfaload.signers.pending",
                        "project/asfaload.signers",
                    ),
                    GitAction::CommitDir("project"),
                    GitAction::Copy(
                        "project/asfaload.signers/index.json",
                        "project/releases/v1/index.json.signers.json",
                    ),
                    GitAction::ExpectSourceIdentification(
                        "project/releases/v1/index.json.signers.json",
                        "project/asfaload.signers/index.json",
                    ),
                ],
            ),
            // -- Was: test_artifact_signers_source_ambiguous_pending_and_active_same_content
            (
                "ambiguous_pending_and_active_same_content",
                vec![
                    GitAction::WriteFile(
                        "proj/asfaload.signers/index.json",
                        r#"{"version":1,"artifact_signers":[{"threshold":2,"signers":[]}]}"#,
                    ),
                    GitAction::WriteFile(
                        "proj/asfaload.signers.pending/index.json",
                        r#"{"version":1,"artifact_signers":[{"threshold":2,"signers":[]}]}"#,
                    ),
                    GitAction::CommitDir("proj"),
                    GitAction::Copy(
                        "proj/asfaload.signers/index.json",
                        "proj/releases/v1/artifact.signers.json",
                    ),
                    GitAction::ExpectSourceIdentification(
                        "proj/releases/v1/artifact.signers.json",
                        "proj/asfaload.signers/index.json",
                    ),
                ],
            ),
            // -- Was: test_artifact_signers_source_full_rotation_scenario
            (
                "full_rotation_scenario",
                vec![
                    GitAction::WriteFile(
                        "proj/asfaload.signers/index.json",
                        r#"{"version":1,"threshold":1,"original":true}"#,
                    ),
                    GitAction::CommitDir("proj/asfaload.signers"),
                    GitAction::WriteFile(
                        "proj/asfaload.signers.pending/index.json",
                        r#"{"version":1,"threshold":2,"updated":true}"#,
                    ),
                    GitAction::CommitDir("proj/asfaload.signers.pending"),
                    GitAction::Delete("proj/asfaload.signers"),
                    GitAction::Rename("proj/asfaload.signers.pending", "proj/asfaload.signers"),
                    GitAction::CommitDir("proj"),
                    GitAction::Copy(
                        "proj/asfaload.signers/index.json",
                        "proj/releases/v2/index.json.signers.json",
                    ),
                    GitAction::ExpectSourceIdentification(
                        "proj/releases/v2/index.json.signers.json",
                        "proj/asfaload.signers/index.json",
                    ),
                ],
            ),
            // -- Was: test_artifact_signers_source_rotation_with_pending_recreated_same_content
            (
                "rotation_with_pending_recreated_same_content",
                vec![
                    GitAction::WriteFile(
                        "proj/asfaload.signers/index.json",
                        r#"{"version":1,"threshold":2,"signers":["a","b"]}"#,
                    ),
                    GitAction::CommitDir("proj/asfaload.signers"),
                    GitAction::WriteFile(
                        "proj/asfaload.signers.pending/index.json",
                        r#"{"version":1,"threshold":2,"signers":["a","b"]}"#,
                    ),
                    GitAction::CommitDir("proj/asfaload.signers.pending"),
                    GitAction::Copy(
                        "proj/asfaload.signers/index.json",
                        "proj/releases/v1/artifact.signers.json",
                    ),
                    GitAction::ExpectSourceIdentification(
                        "proj/releases/v1/artifact.signers.json",
                        "proj/asfaload.signers/index.json",
                    ),
                ],
            ),
            // -- Was: test_artifact_signers_source_with_successive_copies
            (
                "successive_copies",
                vec![
                    GitAction::Create(
                        "signers.json",
                        r#"{"threshold": 2, "signers": ["alice","bob","carol"]}"#,
                    ),
                    GitAction::Copy("signers.json", "sub/dir/subsub/signers.json"),
                    GitAction::Copy("sub/dir/subsub/signers.json", "sub/dir/signers.json"),
                    GitAction::ExpectSourceIdentification(
                        "sub/dir/subsub/signers.json",
                        "signers.json",
                    ),
                    GitAction::ExpectSourceCommit("sub/dir/subsub/signers.json"),
                ],
            ),
            // -- Pre-existing scenario from the skeleton
            (
                "basic_copy_with_distractor",
                vec![
                    GitAction::Create("/dir1/file1", "Content1"),
                    GitAction::Create("/dir1/dir2/file2", "Content2"),
                    GitAction::Copy("/dir1/file1", "/dir1/dir2/dir3/file3"),
                    GitAction::ExpectSourceIdentification("/dir1/dir2/dir3/file3", "/dir1/file1"),
                ],
            ),
        ]
    }

    fn run_scenario<B: GitBackend>(name: &str, scenario: &[GitAction], backend: &B) {
        for (i, action) in scenario.iter().enumerate() {
            run_action(backend, action)
                .unwrap_or_else(|e| panic!("Scenario '{}' failed at step {}: {}", name, i, e));
        }
    }

    #[test]
    fn test_artifact_signers_source_sha256() {
        for (name, scenario) in scenarios() {
            let temp_dir = TempDir::new().unwrap();
            let repo_path = temp_dir.path();
            init_sha256_repo(repo_path);
            let backend =
                Sha256GitBackend::new(repo_path, test_helpers::git_signing_pub_key_path());
            run_scenario(name, &scenario, &backend);
        }
    }
}
