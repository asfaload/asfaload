use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

use anstyle::Style;
use client_lib::config::ConfigAccessor;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, errors::keys::append_pub_extension,
    is_public_key_head, is_secret_key_head,
};
use serde::Serialize;

use crate::{commands::signers_submission_output::BOLD, error::ClientCliError};

const INTRO: &str = "Keys in your keys dir and config file. To use a key file in a different location, give its path to the command.";

// Enough to hold the longest key marker.
pub(crate) const HEAD_SIZE: u64 = 64;

#[derive(Debug, Serialize, PartialEq)]
pub struct AliasedKey {
    alias: String,
    public_key: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PublicKeyFile {
    file_name: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
pub struct KeysListing {
    keys_dir: PathBuf,
    config_file: PathBuf,
    secret_keys: Vec<String>,
    my_public_keys: Vec<PublicKeyFile>,
    public_key_aliases: Vec<AliasedKey>,
    #[serde(skip)]
    keys_dir_exists: bool,
    #[serde(skip)]
    config_file_exists: bool,
}

// Names of the files, given as (file name, first bytes), whose first bytes match `is_key_head`.
// Sorted.
fn key_file_names(files: &[(String, String)], is_key_head: fn(&str) -> bool) -> Vec<String> {
    let mut names: Vec<String> = files
        .iter()
        .filter(|(_, head)| is_key_head(head.trim_start()))
        .map(|(name, _)| name.clone())
        .collect();
    names.sort();
    names
}

fn aliased_keys(aliases: &BTreeMap<String, AsfaloadPublicKeys>) -> Vec<AliasedKey> {
    aliases
        .iter()
        .map(|(alias, key)| AliasedKey {
            alias: alias.clone(),
            public_key: key.to_base64(),
        })
        .collect()
}

fn location_line(label: &str, path: &Path, exists: bool) -> String {
    let missing = if exists { "" } else { " (does not exist)" };
    format!("{label}: {}{missing}", path.display())
}

// A titled section of the text output, with `none` when it has no row.
fn section(title: &str, rows: Vec<String>, bold: Style) -> Vec<String> {
    let rows = if rows.is_empty() {
        vec!["none".to_string()]
    } else {
        rows
    };
    std::iter::once(format!("{bold}{title}:{bold:#}"))
        .chain(rows.into_iter().map(|row| format!("  {row}")))
        .collect()
}

// Rows of two columns, the first one padded to the same width.
fn aligned_rows<'a>(rows: impl Iterator<Item = (&'a str, String)> + Clone) -> Vec<String> {
    let width = rows
        .clone()
        .map(|(first, _)| first.len())
        .max()
        .unwrap_or(0);
    rows.map(|(first, second)| format!("{first:width$}  {second}"))
        .collect()
}

fn render_text(listing: &KeysListing, with_ansi: bool) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let mut lines = vec![
        format!("{bold}Local keys{bold:#}"),
        INTRO.to_string(),
        String::new(),
        location_line("Keys dir", &listing.keys_dir, listing.keys_dir_exists),
        location_line(
            "Config file",
            &listing.config_file,
            listing.config_file_exists,
        ),
        String::new(),
    ];
    lines.extend(section("My secret keys", listing.secret_keys.clone(), bold));
    lines.push(String::new());
    lines.extend(section(
        "My public keys",
        aligned_rows(
            listing
                .my_public_keys
                .iter()
                .map(|key| (key.file_name.as_str(), format!("({})", key.public_key))),
        ),
        bold,
    ));
    lines.push(String::new());
    lines.extend(section(
        "Public key aliases",
        aligned_rows(
            listing
                .public_key_aliases
                .iter()
                .map(|key| (key.alias.as_str(), key.public_key.clone())),
        ),
        bold,
    ));
    lines.join("\n")
}

// The first bytes of one file: the marker of a secret or a public key.
fn read_file_head(path: &Path) -> Result<String, ClientCliError> {
    let mut head = Vec::new();
    std::fs::File::open(path).and_then(|file| file.take(HEAD_SIZE).read_to_end(&mut head))?;
    Ok(String::from_utf8_lossy(&head).to_string())
}

// The first bytes of each regular file of `dir`, without subdirectories. A missing dir has no
// files, and a file that cannot be read is skipped.
fn read_file_heads(dir: &Path) -> Result<Vec<(String, String)>, ClientCliError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut heads = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        if let (Ok(head), Some(name)) = (read_file_head(&path), path.file_name()) {
            heads.push((name.to_string_lossy().to_string(), head));
        }
    }
    Ok(heads)
}

// The row for one file that starts like a public key. `None` for a file that does not parse.
fn public_key_row(file_name: &str, path: &Path) -> Option<PublicKeyFile> {
    let head = read_file_head(path).ok()?;
    if !is_public_key_head(head.trim_start()) {
        return None;
    }
    AsfaloadPublicKeys::from_file(path)
        .ok()
        .map(|key| PublicKeyFile {
            file_name: file_name.to_string(),
            public_key: key.to_base64(),
        })
}

/// Lists the key files of `keys_dir` and the aliases of the config file. The text output has
/// styles: print it with `anstream`, which removes them when stdout is not a terminal.
pub fn list_keys(
    keys_dir: &Path,
    config_accessor: &ConfigAccessor,
    json: bool,
) -> Result<String, ClientCliError> {
    let heads = read_file_heads(keys_dir)?;
    // A file that starts like a public key but does not parse is not a public key.
    let my_public_keys = key_file_names(&heads, is_public_key_head)
        .into_iter()
        .filter_map(|file_name| public_key_row(&file_name, &keys_dir.join(&file_name)))
        .collect();
    let config_file = config_accessor.path()?;
    let listing = KeysListing {
        keys_dir_exists: keys_dir.exists(),
        keys_dir: keys_dir.to_path_buf(),
        config_file_exists: config_file.exists(),
        config_file,
        secret_keys: key_file_names(&heads, is_secret_key_head),
        public_key_aliases: aliased_keys(config_accessor.get()?.aliases()),
        my_public_keys,
    };
    render(&listing, json)
}

// The first bytes of one file, like read_file_heads does for a directory.
// The rows for one key file: a secret key row plus its .pub sibling from disk, for a secret
// key; a public key row for a public key. A file that is there but is not a key yields no rows,
// like in the full listing.
fn key_file_rows(
    name: &str,
    path: &Path,
    cwd: bool,
) -> Result<(Vec<String>, Vec<PublicKeyFile>), ClientCliError> {
    let head = read_file_head(path)?;
    // A cwd match keeps its relative path in the row, so the location is visible.
    let row_name = if cwd {
        format!("./{name}")
    } else {
        name.to_string()
    };
    if is_secret_key_head(head.trim_start()) {
        // Report the .pub sibling from disk only: the keys command never produces nor derives
        // from the secret key.
        let mut public_keys = Vec::new();
        let pub_path = append_pub_extension(path)?;
        if pub_path.is_file() {
            let pub_name = if cwd {
                format!("./{}", pub_path.to_string_lossy())
            } else {
                pub_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| pub_path.to_string_lossy().to_string())
            };
            if let Some(row) = public_key_row(&pub_name, &pub_path) {
                public_keys.push(row);
            }
        }
        Ok((vec![row_name], public_keys))
    } else if is_public_key_head(head.trim_start()) {
        // A file that starts like a public key but does not parse is not a public key.
        let row = public_key_row(&row_name, path);
        Ok((Vec::new(), row.into_iter().collect()))
    } else {
        Ok((Vec::new(), Vec::new()))
    }
}

fn render(listing: &KeysListing, json: bool) -> Result<String, ClientCliError> {
    if json {
        Ok(serde_json::to_string(listing)?)
    } else {
        Ok(render_text(listing, true))
    }
}

/// Displays every match of one name: the file found in the current directory, the file found in
/// the keys dir, and the alias in the config file. Nothing is hidden, so this is a tool for
/// debugging. A name that is not found shows the same layout with all sections empty.
pub(crate) fn display_key(
    name: &str,
    keys_dir: &Path,
    config_accessor: &ConfigAccessor,
    json: bool,
) -> Result<String, ClientCliError> {
    let config_file = config_accessor.path()?;
    let keys_dir_exists = keys_dir.exists();
    let cwd_path = PathBuf::from(name);
    let dir_path = keys_dir.join(name);
    // The same file in both places is displayed once.
    let same_file = cwd_path.is_file()
        && dir_path.is_file()
        && cwd_path.canonicalize().ok() == dir_path.canonicalize().ok();
    let mut secret_keys = Vec::new();
    let mut my_public_keys = Vec::new();
    if cwd_path.is_file() {
        let (s, p) = key_file_rows(name, &cwd_path, true)?;
        secret_keys.extend(s);
        my_public_keys.extend(p);
    }
    if dir_path.is_file() && !same_file {
        let (s, p) = key_file_rows(name, &dir_path, false)?;
        secret_keys.extend(s);
        my_public_keys.extend(p);
    }
    secret_keys.sort();
    my_public_keys.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    // Last resort: the alias in the config file.
    let config = config_accessor.get()?;
    let public_key_aliases = match config.get_key(name) {
        Some(key) => vec![AliasedKey {
            alias: name.to_string(),
            public_key: key.to_base64(),
        }],
        None => Vec::new(),
    };
    render(
        &KeysListing {
            keys_dir_exists,
            keys_dir: keys_dir.to_path_buf(),
            config_file_exists: config_file.exists(),
            config_file,
            secret_keys,
            my_public_keys,
            public_key_aliases,
        },
        json,
    )
}

#[cfg(test)]
mod tests {
    use test_helpers::TestKeys;

    use super::*;

    fn files(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(name, head)| (name.to_string(), head.to_string()))
            .collect()
    }

    #[test]
    fn key_file_names_selects_by_marker_sorted() {
        let heads = files(&[
            ("zed", "asfaload-priv:QVNGQUxPQUQB"),
            ("zed.pub", "asfaload-pub:b5S+CxuqICIUn"),
            ("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl"),
            ("id_ed25519.pub", "ssh-ed25519 AAAAC3Nza"),
            ("spaced", "\n  asfaload-priv:QVNGQUxPQUQB"),
            ("notes.txt", "some text"),
            ("empty", ""),
        ]);
        type Case<'a> = (&'a str, fn(&str) -> bool, Vec<&'a str>);
        // (description, marker check, expected names)
        let cases: [Case<'_>; 2] = [
            (
                "secret keys",
                is_secret_key_head,
                vec!["id_ed25519", "spaced", "zed"],
            ),
            (
                "public keys",
                is_public_key_head,
                vec!["id_ed25519.pub", "zed.pub"],
            ),
        ];
        for (description, is_key_head, expected) in cases {
            assert_eq!(
                key_file_names(&heads, is_key_head),
                expected,
                "case {description}"
            );
        }
    }

    #[test]
    fn aliased_keys_lists_aliases_with_their_keys() {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        let aliases = BTreeMap::from([
            ("me".to_string(), key_0.clone()),
            ("alice".to_string(), key_1.clone()),
        ]);

        assert_eq!(
            aliased_keys(&aliases),
            vec![
                AliasedKey {
                    alias: "alice".to_string(),
                    public_key: key_1.to_base64(),
                },
                AliasedKey {
                    alias: "me".to_string(),
                    public_key: key_0.to_base64(),
                },
            ]
        );
    }

    #[test]
    fn render_text_shows_aligned_sections() {
        let listing = KeysListing {
            keys_dir: PathBuf::from("/keys"),
            config_file: PathBuf::from("/config.toml"),
            secret_keys: vec!["mykey".to_string(), "release".to_string()],
            public_key_aliases: vec![
                AliasedKey {
                    alias: "alice".to_string(),
                    public_key: "asfaload-pub:A".to_string(),
                },
                AliasedKey {
                    alias: "me".to_string(),
                    public_key: "asfaload-pub:B".to_string(),
                },
            ],
            my_public_keys: vec![
                PublicKeyFile {
                    file_name: "mykey.pub".to_string(),
                    public_key: "asfaload-pub:B".to_string(),
                },
                PublicKeyFile {
                    file_name: "release.pub".to_string(),
                    public_key: "asfaload-pub:C".to_string(),
                },
            ],
            keys_dir_exists: true,
            config_file_exists: true,
        };

        let expected = format!(
            "Local keys\n{INTRO}\n\nKeys dir: /keys
Config file: /config.toml

My secret keys:
  mykey
  release

My public keys:
  mykey.pub    (asfaload-pub:B)
  release.pub  (asfaload-pub:C)

Public key aliases:
  alice  asfaload-pub:A
  me     asfaload-pub:B"
        );
        assert_eq!(render_text(&listing, false), expected);
    }

    #[test]
    fn render_text_reports_missing_locations_and_empty_sections() {
        let listing = KeysListing {
            keys_dir: PathBuf::from("/keys"),
            config_file: PathBuf::from("/config.toml"),
            secret_keys: vec![],
            public_key_aliases: vec![],
            my_public_keys: vec![],
            keys_dir_exists: false,
            config_file_exists: false,
        };

        let expected = format!(
            "Local keys\n{INTRO}\n\nKeys dir: /keys (does not exist)
Config file: /config.toml (does not exist)

My secret keys:
  none

My public keys:
  none

Public key aliases:
  none"
        );
        assert_eq!(render_text(&listing, false), expected);
    }

    #[test]
    fn render_text_with_ansi_makes_section_titles_bold() {
        let listing = KeysListing {
            keys_dir: PathBuf::from("/keys"),
            config_file: PathBuf::from("/config.toml"),
            secret_keys: vec![],
            public_key_aliases: vec![],
            my_public_keys: vec![],
            keys_dir_exists: true,
            config_file_exists: true,
        };

        assert!(!render_text(&listing, false).contains('\x1b'));
        assert!(render_text(&listing, true).contains(&format!("{BOLD}My secret keys:{BOLD:#}")));
    }
}
