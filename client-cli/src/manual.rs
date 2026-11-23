//! Manual pages from `docs/manual/`, embedded at compile time and rendered for the terminal.

pub const INDEX_PAGE: &str = "index";

macro_rules! page {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("../docs/manual/", $name, ".md")),
        )
    };
}

/// Name and Markdown source of each manual page.
pub const PAGES: &[(&str, &str)] = &[
    page!("index"),
    page!("alias"),
    page!("check-index"),
    page!("check-pending-signers"),
    page!("complete"),
    page!("download"),
    page!("fetch-file"),
    page!("get-digest"),
    page!("list-pending"),
    page!("new-keys"),
    page!("new-signers-file"),
    page!("ping"),
    page!("register-assets"),
    page!("register-repo"),
    page!("revoke"),
    page!("share-key"),
    page!("shell"),
    page!("sign-pending"),
    page!("signature-status"),
    page!("update-signers"),
];

pub fn page_names() -> impl Iterator<Item = &'static str> {
    PAGES.iter().map(|(name, _)| *name)
}

pub fn page_source(name: &str) -> Option<&'static str> {
    PAGES
        .iter()
        .find(|(page, _)| *page == name)
        .map(|(_, source)| *source)
}

/// Rewrites the Markdown links, because termimad does not render them.
/// A link to another manual page refers to the `manual` subcommand, other links keep only their
/// text. Indented code blocks do not change.
pub fn rewrite_links(markdown: &str, bin_name: &str) -> String {
    markdown
        .split_inclusive('\n')
        .map(|line| {
            if line.starts_with("    ") {
                line.to_string()
            } else {
                rewrite_line_links(line, bin_name)
            }
        })
        .collect()
}

fn rewrite_line_links(line: &str, bin_name: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find('[') {
        output.push_str(&rest[..start]);
        let candidate = &rest[start..];
        match parse_link(candidate) {
            Some((text, target, length)) => {
                output.push_str(&link_replacement(text, target, bin_name));
                rest = &candidate[length..];
            }
            None => {
                output.push('[');
                rest = &candidate[1..];
            }
        }
    }
    output.push_str(rest);
    output
}

// Parses `[text](target)` at the start of `input`, and returns the text, the target and the
// length in bytes of the link.
fn parse_link(input: &str) -> Option<(&str, &str, usize)> {
    let text_end = input.find("](")?;
    let text = &input[1..text_end];
    if text.contains(['[', ']']) {
        return None;
    }
    let target_start = text_end + 2;
    let target_length = input[target_start..].find(')')?;
    let target = &input[target_start..target_start + target_length];
    Some((text, target, target_start + target_length + 1))
}

fn link_replacement(text: &str, target: &str, bin_name: &str) -> String {
    match linked_page(target) {
        Some(page) => format!("{text} (see: `{bin_name} manual {page}`)"),
        None => text.to_string(),
    }
}

// Returns the page name of a link target `name.md` or `name.md#section`.
fn linked_page(target: &str) -> Option<&str> {
    let file = target.split('#').next()?;
    let page = file.strip_suffix(".md")?;
    (!page.is_empty() && !page.contains('/')).then_some(page)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::cli::Cli;

    #[test]
    fn index_page_exists() {
        assert!(page_source(INDEX_PAGE).is_some());
    }

    #[test]
    fn each_subcommand_has_a_page() {
        let missing: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_string())
            .filter(|name| page_source(name).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "subcommands without a manual page: {missing:?}"
        );
    }

    #[test]
    fn no_page_links_to_the_source_code() {
        for (name, source) in PAGES {
            assert!(
                !source.contains("**Source**"),
                "source code link in page {name}"
            );
        }
    }

    #[test]
    fn each_long_flag_is_in_the_page_of_its_subcommand() {
        let missing: Vec<String> = Cli::command()
            .get_subcommands()
            .flat_map(|subcommand| {
                let name = subcommand.get_name();
                let source = page_source(name).unwrap_or_default();
                subcommand
                    .get_arguments()
                    .filter_map(|arg| arg.get_long())
                    .filter(|long| !["help", "manual"].contains(long))
                    .filter(|long| !source.contains(&format!("--{long}")))
                    .map(|long| format!("{name} --{long}"))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            missing.is_empty(),
            "flags missing in their manual page: {missing:?}"
        );
    }

    #[test]
    fn rewrite_links_keeps_readable_text() {
        let cases = vec![
            (
                "See [alias](alias.md).",
                "See alias (see: `asfaload-cli manual alias`).",
            ),
            (
                "Refer to [the index](index.md#passwords).",
                "Refer to the index (see: `asfaload-cli manual index`).",
            ),
            ("Go to [section](#passwords).", "Go to section."),
            ("Code in [file](../../src/main.rs).", "Code in file."),
            ("Site [docs](https://example.com/a.md).", "Site docs."),
            (
                "[a](a.md) and [b](b.md)",
                "a (see: `asfaload-cli manual a`) and b (see: `asfaload-cli manual b`)",
            ),
            (
                "- [`ping`](ping.md) — check",
                "- `ping` (see: `asfaload-cli manual ping`) — check",
            ),
            ("No link here.\n", "No link here.\n"),
            ("An array [0] and [1](x", "An array [0] and [1](x"),
            ("[a] b [c](c.md)", "[a] b c (see: `asfaload-cli manual c`)"),
            ("    [code](code.md)\n", "    [code](code.md)\n"),
            (
                "line one\n[x](x.md)\n",
                "line one\nx (see: `asfaload-cli manual x`)\n",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                rewrite_links(input, "asfaload-cli"),
                expected,
                "input: {input}"
            );
        }
    }

    #[test]
    fn each_page_has_no_raw_link_after_rewrite() {
        for (name, source) in PAGES {
            assert!(
                !rewrite_links(source, "asfaload-cli").contains("]("),
                "raw link in page {name}"
            );
        }
    }
}
