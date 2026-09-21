use std::path::{Path, PathBuf};

use constants::{
    METADATA_SUFFIX, PENDING_SIGNATURES_SUFFIX, PENDING_SIGNERS_DIR, PENDING_SUFFIX,
    REVOCATION_SUFFIX, REVOKED_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE,
    SIGNERS_HISTORY_FILE, SIGNERS_SUFFIX,
};

/// Find the active signers file by traversing parent directories
pub fn find_global_signers_for(file_path: &Path) -> Result<PathBuf, std::io::Error> {
    // We accept looking for the global signer for a directory.
    let mut current_dir = {
        if file_path.is_dir() {
            Ok(file_path)
        } else {
            file_path.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "File has no parent directory",
                )
            })
        }
    }?;

    // If we work on a signers file, we go up one level, so we do not
    // consider a signers file for itself
    current_dir = if file_path
        .file_name()
        .is_some_and(|name| name == SIGNERS_FILE)
        && file_path
            .parent()
            .is_some_and(|p| p.file_name().unwrap_or_default() == SIGNERS_DIR)
    {
        current_dir
            .parent()
            .and_then(|d| d.parent())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "File has no parent directory",
                )
            })?
    } else {
        current_dir
    };

    loop {
        let candidate = current_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        if candidate.exists() {
            return Ok(candidate);
        }

        // Move up to the parent directory
        current_dir = match current_dir.parent() {
            Some(parent) => parent,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No signers file found in parent directories",
                ));
            }
        };
    }
}

pub fn pending_signers_file_in_dir<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let path = path_in.as_ref();
    if !path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Looking for pending signers file in dir only works with a directory",
        ));
    }
    let p = path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
    if p.exists() && p.is_file() {
        Ok(p)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Pending signers file not found or is directory",
        ))
    }
}

pub fn create_local_signers_for<P: AsRef<Path>>(
    file_path_in: P,
) -> Result<PathBuf, std::io::Error> {
    let file_path = file_path_in.as_ref();

    // Not working on directories
    if file_path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Not creating local signers for a directory.",
        ));
    }

    let local_signers_path = local_signers_path_for(file_path)?;

    // Not overwriting existing files
    if local_signers_path.exists() {
        return Err({
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "Not overwriting existing local signers file at {}",
                    local_signers_path.to_string_lossy()
                ),
            )
        });
    }

    let global_signers = find_global_signers_for(file_path)?;
    std::fs::copy(global_signers, &local_signers_path)?;
    Ok(local_signers_path)
}

fn file_path_with_suffix<P: AsRef<Path>>(path_in: P, suffix: &str) -> std::io::Result<PathBuf> {
    let file_path = path_in.as_ref();
    file_path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Input path has no file name",
        )
    })?;
    let new_path_str = format!("{}.{}", file_path.to_string_lossy(), suffix);
    Ok(std::path::PathBuf::from(new_path_str))
}
// Get the signatures file path for a file path.
// It doesn't check on disk that the path received is effectively a file.
pub fn signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, SIGNATURES_SUFFIX)
}
pub fn pending_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, PENDING_SIGNATURES_SUFFIX)
}

/// Returns true of the path passed in corresponds to a pending signers file, checking directory
/// and file names. No IO is done.
pub fn is_pending_signers_file_path<P: AsRef<Path>>(path_in: P) -> bool {
    let path = path_in.as_ref();
    if let Some(file_name) = path.file_name()
        && let Some(parent_dir) = path.parent()
        && let Some(dir_name) = parent_dir.file_name()
    {
        file_name == SIGNERS_FILE && dir_name == PENDING_SIGNERS_DIR
    } else {
        false
    }
}

pub fn subject_path_from_pending_signatures<P: AsRef<Path>>(
    path_in: P,
) -> std::io::Result<PathBuf> {
    let suffix = format!(".{}", PENDING_SIGNATURES_SUFFIX);
    let path_str = path_in.as_ref().to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid path: cannot convert to string",
        )
    })?;
    let subject_str = path_str.trim_end_matches(&suffix);
    Ok(PathBuf::from(subject_str))
}
// Return the copy of the signers file taken when initialising the signature
// procedure for the file at path_in.
pub fn local_signers_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, SIGNERS_SUFFIX)
}

/// Get the history file path for a signers directory.
/// The history file lives in the parent of the signers directory.
pub fn history_file_path_for<P: AsRef<Path>>(signers_dir: P) -> PathBuf {
    let parent = signers_dir.as_ref().parent().unwrap_or(Path::new(""));
    parent.join(SIGNERS_HISTORY_FILE)
}

/// Get the metadata file path for a given file.
/// Appends the metadata suffix to the file path, e.g. `index.json` -> `index.json.metadata.json`.
pub fn metadata_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, METADATA_SUFFIX)
}

/// Get the metadata signatures file path for a given file.
/// Composes `metadata_path_for` with `signatures_path_for`:
/// e.g. `index.json` -> `index.json.metadata.json.signatures.json`
pub fn metadata_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let metadata = metadata_path_for(path_in)?;
    signatures_path_for(metadata)
}

/// Get the parent file path from a metadata file path.
/// Strips the metadata suffix, e.g. `index.json.metadata.json` -> `index.json`.
/// Returns an error if the path does not end with the metadata suffix.
pub fn subject_path_from_metadata<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let path = path_in.as_ref();
    let suffix = format!(".{}", METADATA_SUFFIX);
    let stripped = path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .and_then(|name| name.strip_suffix(&suffix))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("File does not end with {}", suffix),
            )
        })?;
    let mut result = path.to_path_buf();
    result.set_file_name(stripped);
    Ok(result)
}

pub fn revocation_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, REVOCATION_SUFFIX)
}

pub fn pending_revocation_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = revocation_path_for(path_in)?;
    file_path_with_suffix(rev_path, PENDING_SUFFIX)
}

pub fn has_revocation_file<P: AsRef<Path>>(signed_file_path_in: P) -> std::io::Result<bool> {
    let exists = revocation_path_for(signed_file_path_in.as_ref())?.exists();
    Ok(exists)
}

pub fn revocation_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = revocation_path_for(path_in)?;
    file_path_with_suffix(rev_path, SIGNATURES_SUFFIX)
}

pub fn pending_revocation_pending_signatures_path_for<P: AsRef<Path>>(
    path_in: P,
) -> std::io::Result<PathBuf> {
    let rev_path = pending_revocation_path_for(path_in)?;
    file_path_with_suffix(rev_path, PENDING_SIGNATURES_SUFFIX)
}

pub fn revocation_signers_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = revocation_path_for(path_in)?;
    file_path_with_suffix(rev_path, SIGNERS_SUFFIX)
}

pub fn revoked_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = signatures_path_for(path_in)?;
    file_path_with_suffix(rev_path, REVOKED_SUFFIX)
}

// If revocation happens during the artifact's signature process, we copy the signatures already
// collected in this path.
// artifact.<PENDING_SIGNATURES_SUFFIX>.<REVOKED_SUFFIX>
pub fn revoked_pending_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let pending_sig_path = pending_signatures_path_for(path_in)?;
    file_path_with_suffix(pending_sig_path, REVOKED_SUFFIX)
}
// Get the signatures file path for a file on disk. This chekcs on disk if the file
// exists.
pub fn signatures_path_on_disk_for<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
    let file_path = path_in.as_ref();
    // This checks on disk
    if !file_path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Input path is not a file: {}", file_path.to_string_lossy()),
        ));
    }
    file_path_with_suffix(path_in, SIGNATURES_SUFFIX)
}
#[cfg(test)]
mod asfaload_index_tests {

    use std::{fs, str::FromStr};

    use anyhow::Result;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    #[test]
    fn test_signature_path_on_disk_for() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "My data")?;
        let input_path = file.path().to_path_buf();
        let expected_str = format!(
            "{}.{}",
            input_path.clone().into_os_string().to_string_lossy(),
            SIGNATURES_SUFFIX
        );
        let expected_path = PathBuf::from_str(&expected_str)?;
        let signatures_path = signatures_path_on_disk_for(input_path)?;
        assert_eq!(signatures_path, expected_path);

        let input_path = TempDir::new().unwrap().path().to_path_buf();
        let res = signatures_path_on_disk_for(input_path);
        assert!(res.is_err());
        let error = res.err().unwrap();
        assert!(error.to_string().starts_with("Input path is not a file"));

        Ok(())
    }

    #[test]
    fn test_simple_signature_path_for() -> Result<()> {
        let input = Path::new("/my/path/to/file");
        let output = signatures_path_for(input)?;
        assert_eq!(
            output,
            PathBuf::from_str("/my/path/to/file.signatures.json")?
        );

        // FIXME: this should cause an error as it is clearly a path to a directory
        let input = Path::new("/my/path/to/file/");
        let output = signatures_path_for(input)?;
        assert_eq!(
            output,
            PathBuf::from_str("/my/path/to/file/.signatures.json")?
        );

        let input = Path::new("/");
        let result = signatures_path_for(input);
        assert!(result.is_err());
        match result.as_ref().unwrap_err().kind() {
            std::io::ErrorKind::InvalidInput => {}
            err => {
                panic!(
                    "Expected IoError with InvalidInput kind, got something else: {:?}",
                    err
                )
            }
        }
        Ok(())
    }
    // test pending_signers_file_in_dir
    // --------------------------------
    #[test]
    fn test_pending_signers_file_in_dir_success() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file = pending_dir.join(SIGNERS_FILE);
        fs::write(&pending_file, "{}")?;

        let result = pending_signers_file_in_dir(dir_path)?;

        let expected_path = pending_dir.join(SIGNERS_FILE);
        assert_eq!(result, expected_path);

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_path_is_a_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("not_a_dir.txt");
        fs::write(&file_path, "content")?;

        let result = pending_signers_file_in_dir(&file_path);

        // Should return an error
        match result.unwrap_err().kind() {
            std::io::ErrorKind::InvalidInput => {}
            k => panic!("Expected InvalidInput error, got {}", k),
        }

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_missing_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        // We don't create the PENDING_SIGNERS_FILE

        // Call the function
        let result = pending_signers_file_in_dir(dir_path);

        // Should return an error
        assert!(result.is_err());
        match result.unwrap_err().kind() {
            std::io::ErrorKind::NotFound => {}
            _ => panic!("Expected NotFound error"),
        }

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_file_is_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create the directory structure but make the pending file a directory
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file = pending_dir.join(SIGNERS_FILE);
        fs::create_dir(&pending_file)?; // Create as directory instead of file

        // Call the function
        let result = pending_signers_file_in_dir(dir_path);

        // Should return an error
        assert!(result.is_err());
        match result.unwrap_err().kind() {
            std::io::ErrorKind::NotFound => {} // It should report as not found since it's not a file
            _ => panic!("Expected NotFound error"),
        }

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_nested_path() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        fs::create_dir_all(&nested_dir)?;

        // Create the expected directory structure in the nested directory
        let pending_dir = nested_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file = pending_dir.join(SIGNERS_FILE);
        fs::write(&pending_file, "{}")?;

        // Call the function with the nested directory
        let result = pending_signers_file_in_dir(&nested_dir)?;

        // Verify the result
        let expected_path = pending_dir.join(SIGNERS_FILE);
        assert_eq!(result, expected_path);

        Ok(())
    }

    // test subject_path_from_pending_signatures
    // ----------------------------------------
    #[test]
    fn test_subject_path_from_pending_signatures_basic_path() -> Result<()> {
        let input = PathBuf::from_str("/my/path/to/file.signatures.json.pending")?;
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::from_str("/my/path/to/file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_pending_signatures_simple_filename() -> Result<()> {
        let input = PathBuf::from_str("file.signatures.json.pending")?;
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::from_str("file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_pending_signatures_without_suffix() -> Result<()> {
        let input = PathBuf::from_str("/my/path/to/file")?;
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::from_str("/my/path/to/file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_pending_signatures_empty_path() -> Result<()> {
        let input = PathBuf::new();
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::new();
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_has_revocation_file_returns_true_when_exists() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let artifact_path = temp_dir.path().join("my_artifact.bin");
        fs::write(&artifact_path, "content")?;

        let revocation_path = revocation_path_for(&artifact_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        assert!(has_revocation_file(&artifact_path)?);
        Ok(())
    }

    #[test]
    fn test_has_revocation_file_returns_false_when_pending_revocation_exists() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let artifact_path = temp_dir.path().join("my_artifact.bin");
        fs::write(&artifact_path, "content")?;

        let pending_revocation_path = pending_revocation_path_for(&artifact_path)?;
        fs::write(&pending_revocation_path, r#"{"revoked": true}"#)?;

        assert!(!has_revocation_file(&artifact_path)?);
        Ok(())
    }

    #[test]
    fn test_has_revocation_file_returns_false_when_not_exists() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let artifact_path = temp_dir.path().join("my_artifact.bin");
        fs::write(&artifact_path, "content")?;

        assert!(!has_revocation_file(&artifact_path)?);
        Ok(())
    }

    #[test]
    fn test_has_revocation_file_returns_false_for_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir)?;

        assert!(!has_revocation_file(&subdir)?);
        Ok(())
    }

    // test pending_revocation_pending_signatures_path_for
    // ---------------------------------------------------
    #[test]
    fn test_pending_revocation_pending_signatures_path_for_basic() -> Result<()> {
        let input = Path::new("/my/path/to/artifact.bin");
        let result = pending_revocation_pending_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from_str(
                "/my/path/to/artifact.bin.revocation.json.pending.signatures.json.pending"
            )?
        );
        Ok(())
    }

    #[test]
    fn test_pending_revocation_pending_signatures_path_for_relative() -> Result<()> {
        let input = Path::new("relative/artifact.bin");
        let result = pending_revocation_pending_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from_str(
                "relative/artifact.bin.revocation.json.pending.signatures.json.pending"
            )?
        );
        Ok(())
    }

    #[test]
    fn test_pending_revocation_pending_signatures_path_for_no_extension() -> Result<()> {
        let input = Path::new("/my/path/artifact");
        let result = pending_revocation_pending_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from_str("/my/path/artifact.revocation.json.pending.signatures.json.pending")?
        );
        Ok(())
    }

    #[test]
    fn test_pending_revocation_pending_signatures_path_for_empty_path() {
        let input = Path::new("");
        let result = pending_revocation_pending_signatures_path_for(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_pending_revocation_pending_signatures_path_for_root() {
        let input = Path::new("/");
        let result = pending_revocation_pending_signatures_path_for(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    // test revoked_pending_signatures_path_for
    // -----------------------------------------
    #[test]
    fn test_revoked_pending_signatures_path_for_basic() -> Result<()> {
        let input = Path::new("/my/path/to/artifact.bin");
        let result = revoked_pending_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from_str("/my/path/to/artifact.bin.signatures.json.pending.revoked")?
        );
        Ok(())
    }

    #[test]
    fn test_revoked_pending_signatures_path_for_relative() -> Result<()> {
        let input = Path::new("relative/artifact.bin");
        let result = revoked_pending_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from_str("relative/artifact.bin.signatures.json.pending.revoked")?
        );
        Ok(())
    }

    #[test]
    fn test_revoked_pending_signatures_path_for_no_extension() -> Result<()> {
        let input = Path::new("/my/path/artifact");
        let result = revoked_pending_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from_str("/my/path/artifact.signatures.json.pending.revoked")?
        );
        Ok(())
    }

    #[test]
    fn test_revoked_pending_signatures_path_for_empty_path() {
        let input = Path::new("");
        let result = revoked_pending_signatures_path_for(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_revoked_pending_signatures_path_for_root() {
        let input = Path::new("/");
        let result = revoked_pending_signatures_path_for(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    // test revocation_path_for
    // ------------------------
    #[test]
    fn test_revocation_path_for_basic() -> Result<()> {
        let test_path = PathBuf::from("/test/directory/file.txt");
        let result = revocation_path_for(&test_path)?;
        let expected = PathBuf::from("/test/directory/file.txt.revocation.json");
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_revocation_path_for_with_different_extensions() -> Result<()> {
        let test_cases = vec![
            ("file.txt", "file.txt.revocation.json"),
            ("file.tar.gz", "file.tar.gz.revocation.json"),
            ("file", "file.revocation.json"),
            ("file.with.dots.txt", "file.with.dots.txt.revocation.json"),
        ];
        for (input, expected_name) in test_cases {
            let test_path = PathBuf::from("/test/directory").join(input);
            let result = revocation_path_for(&test_path)?;
            let expected_path = PathBuf::from("/test/directory").join(expected_name);
            assert_eq!(result, expected_path);
        }
        Ok(())
    }

    #[test]
    fn test_revocation_path_for_invalid_path() {
        let empty_path = PathBuf::from("");
        assert!(revocation_path_for(&empty_path).is_err());

        let dot_dot_path = PathBuf::from("/test/directory/..");
        assert!(revocation_path_for(&dot_dot_path).is_err());
    }

    // test revocation_signatures_path_for
    // ------------------------------------
    #[test]
    fn test_revocation_signatures_path_for_basic() -> Result<()> {
        let test_path = PathBuf::from("/test/directory/file.txt");
        let result = revocation_signatures_path_for(&test_path)?;
        assert_eq!(
            result,
            PathBuf::from_str("/test/directory/file.txt.revocation.json.signatures.json")?
        );
        Ok(())
    }

    // test revocation_signers_path_for
    // --------------------------------
    #[test]
    fn test_revocation_signers_path_for_basic() -> Result<()> {
        let test_path = PathBuf::from("/test/directory/file.txt");
        let result = revocation_signers_path_for(&test_path)?;
        assert_eq!(
            result,
            PathBuf::from_str("/test/directory/file.txt.revocation.json.signers.json")?
        );
        Ok(())
    }

    // test revoked_signatures_path_for
    // --------------------------------
    #[test]
    fn test_revoked_signatures_path_for_basic() -> Result<()> {
        let test_path = PathBuf::from("/test/directory/file.txt");
        let result = revoked_signatures_path_for(&test_path)?;
        assert_eq!(
            result,
            PathBuf::from_str("/test/directory/file.txt.signatures.json.revoked")?
        );
        Ok(())
    }

    // test revocation path functions with unicode characters
    // ------------------------------------------------------
    #[test]
    fn test_revocation_path_functions_with_unicode_characters() -> Result<()> {
        let test_cases = vec![
            ("file_with_unicode_🚀.txt", "file_with_unicode_🚀.txt"),
            ("café.txt", "café.txt"),
            ("文件.txt", "文件.txt"),
        ];
        for (input, expected_base) in test_cases {
            let test_path = PathBuf::from("/test/directory").join(input);

            let revocation_path = revocation_path_for(&test_path)?;
            assert_eq!(
                revocation_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}", expected_base, REVOCATION_SUFFIX)
            );

            let sig_path = revocation_signatures_path_for(&test_path)?;
            assert_eq!(
                sig_path.file_name().unwrap().to_string_lossy(),
                format!(
                    "{}.{}.{}",
                    expected_base, REVOCATION_SUFFIX, SIGNATURES_SUFFIX
                )
            );

            let signers_path = revocation_signers_path_for(&test_path)?;
            assert_eq!(
                signers_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, REVOCATION_SUFFIX, SIGNERS_SUFFIX)
            );

            let revoked_path = revoked_signatures_path_for(&test_path)?;
            assert_eq!(
                revoked_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, SIGNATURES_SUFFIX, REVOKED_SUFFIX)
            );
        }
        Ok(())
    }

    // test revocation path functions with spaces and special chars
    // ------------------------------------------------------------
    #[test]
    fn test_revocation_path_functions_with_spaces_and_special_chars() -> Result<()> {
        let test_cases = vec![
            ("file with spaces.txt", "file with spaces.txt"),
            ("file-with-dashes.txt", "file-with-dashes.txt"),
            ("file_with_underscores.txt", "file_with_underscores.txt"),
            ("file(mixed)chars.txt", "file(mixed)chars.txt"),
        ];
        for (input, expected_base) in test_cases {
            let test_path = PathBuf::from("/test/directory").join(input);

            let revocation_path = revocation_path_for(&test_path)?;
            assert_eq!(
                revocation_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}", expected_base, REVOCATION_SUFFIX)
            );

            let sig_path = revocation_signatures_path_for(&test_path)?;
            assert_eq!(
                sig_path.file_name().unwrap().to_string_lossy(),
                format!(
                    "{}.{}.{}",
                    expected_base, REVOCATION_SUFFIX, SIGNATURES_SUFFIX
                )
            );

            let signers_path = revocation_signers_path_for(&test_path)?;
            assert_eq!(
                signers_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, REVOCATION_SUFFIX, SIGNERS_SUFFIX)
            );

            let revoked_path = revoked_signatures_path_for(&test_path)?;
            assert_eq!(
                revoked_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, SIGNATURES_SUFFIX, REVOKED_SUFFIX)
            );
        }
        Ok(())
    }

    // test revocation path functions with relative paths
    // --------------------------------------------------
    #[test]
    fn test_revocation_path_functions_with_relative_paths() -> Result<()> {
        let test_cases = vec![
            PathBuf::from("relative/file.txt"),
            PathBuf::from("./current/file.txt"),
            PathBuf::from("../parent/file.txt"),
        ];
        for test_path in test_cases {
            let revocation_path = revocation_path_for(&test_path)?;
            assert!(
                revocation_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}", REVOCATION_SUFFIX))
            );

            let sig_path = revocation_signatures_path_for(&test_path)?;
            assert!(
                sig_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}.{}", REVOCATION_SUFFIX, SIGNATURES_SUFFIX))
            );

            let signers_path = revocation_signers_path_for(&test_path)?;
            assert!(
                signers_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}.{}", REVOCATION_SUFFIX, SIGNERS_SUFFIX))
            );

            let revoked_path = revoked_signatures_path_for(&test_path)?;
            assert!(
                revoked_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}.{}", SIGNATURES_SUFFIX, REVOKED_SUFFIX))
            );
        }
        Ok(())
    }

    // test metadata_path_for
    // ----------------------
    #[test]
    fn test_metadata_path_for() -> Result<()> {
        let input = Path::new("/project/asfaload.signers/index.json");
        let result = metadata_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from(format!(
                "/project/asfaload.signers/index.json.{}",
                METADATA_SUFFIX
            ))
        );
        Ok(())
    }

    // test metadata_signatures_path_for
    // ----------------------------------
    #[test]
    fn test_metadata_signatures_path_for() -> Result<()> {
        let input = Path::new("/project/asfaload.signers/index.json");
        let result = metadata_signatures_path_for(input)?;
        assert_eq!(
            result,
            PathBuf::from(format!(
                "/project/asfaload.signers/index.json.{}.{}",
                METADATA_SUFFIX, SIGNATURES_SUFFIX
            ))
        );
        Ok(())
    }

    // test subject_path_from_metadata
    // --------------------------------
    #[test]
    fn test_subject_path_from_metadata_basic() -> Result<()> {
        let input = PathBuf::from_str(&format!("/my/path/to/file.{}", METADATA_SUFFIX))?;
        let result = subject_path_from_metadata(&input)?;
        let expected = PathBuf::from_str("/my/path/to/file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_metadata_without_suffix() {
        let input = PathBuf::from_str("/my/path/to/file").unwrap();
        let result = subject_path_from_metadata(&input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_subject_path_from_metadata_signers_file() -> Result<()> {
        let signers_path = PathBuf::from_str(&format!(
            "/project/asfaload.signers.pending/{}.{}",
            SIGNERS_FILE, METADATA_SUFFIX
        ))?;
        let result = subject_path_from_metadata(&signers_path)?;
        let expected = PathBuf::from_str(&format!(
            "/project/asfaload.signers.pending/{}",
            SIGNERS_FILE
        ))?;
        assert_eq!(result, expected);
        Ok(())
    }
}
