//! Manual pages from `docs/manual/`, embedded at compile time and rendered for the terminal.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};

use clap::CommandFactory;
use termimad::crossterm::style::Color;
use termimad::minimad::Alignment;
use termimad::{CompoundStyle, MadSkin};

use crate::cli::Cli;

pub const INDEX_PAGE: &str = "index";
const MANUAL_FLAG: &str = "--manual";
const END_OF_OPTIONS: &str = "--";
// Width used when the output is not a terminal, or when the terminal width is not available.
const DEFAULT_WIDTH: usize = 80;
const BODY_INDENT: usize = 7;
const NESTED_INDENT: usize = 4;
// Below this width the indentation takes too much space.
const MIN_INDENTED_WIDTH: usize = 40;

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
    page!("keys"),
    page!("list-pending"),
    page!("manual"),
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
    page!("workflow"),
];

/// Markdown source of the workflow overview, shown by the `workflow` subcommand.
pub const WORKFLOW: &str = include_str!("../docs/workflow.md");
const SEE_LINE_START: &str = "See [";

/// Removes the lines that start with `See [`, and the empty line after each of them. These lines
/// link to the how-to guides, which are available on the web only.
pub fn remove_see_lines(markdown: &str) -> String {
    let mut output = String::with_capacity(markdown.len());
    let mut lines = markdown.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.starts_with(SEE_LINE_START) {
            lines.next_if(|next| next.trim().is_empty());
        } else {
            output.push_str(line);
        }
    }
    output
}

pub fn page_names() -> impl Iterator<Item = &'static str> {
    PAGES.iter().map(|(name, _)| *name)
}

pub fn page_source(name: &str) -> Option<&'static str> {
    PAGES
        .iter()
        .find(|(page, _)| *page == name)
        .map(|(_, source)| *source)
}

fn page_name(name: &str) -> Option<&'static str> {
    page_names().find(|page| *page == name)
}

/// Returns the manual page that `--manual` requests, or `None` when the arguments
/// do not request a manual page. Required arguments of the subcommand are not
/// necessary, because clap errors are ignored here.
pub fn requested_page(args: &[OsString]) -> Option<&'static str> {
    let user_args: Vec<&OsString> = args
        .iter()
        .skip(1)
        .take_while(|arg| *arg != END_OF_OPTIONS)
        .collect();
    if !user_args.iter().any(|arg| *arg == MANUAL_FLAG) {
        return None;
    }
    let matches = Cli::command()
        .ignore_errors(true)
        .try_get_matches_from(args)
        .ok()?;
    match matches.subcommand_name() {
        Some(name) => Some(page_name(name).unwrap_or(INDEX_PAGE)),
        // The top-level command takes no option value, so an argument that is not
        // an option is an unknown subcommand: let the normal parsing report it.
        None if user_args
            .iter()
            .any(|arg| !arg.to_string_lossy().starts_with('-')) =>
        {
            None
        }
        None => Some(INDEX_PAGE),
    }
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

/// Renders Markdown as terminal text, wrapped at `width` columns, with the indentation of
/// man pages. Without `styled`, the text has no ANSI escape codes.
pub fn render(markdown: &str, styled: bool, width: usize) -> String {
    let mut skin = if styled {
        styled_skin()
    } else {
        MadSkin::no_style()
    };
    skin.headers[0].align = Alignment::Center;
    if width < MIN_INDENTED_WIDTH {
        return skin.text(markdown, Some(width)).to_string();
    }
    let mut output = String::new();
    let mut body = String::new();
    let mut body_indent = BODY_INDENT;
    for line in markdown.split_inclusive('\n') {
        match heading_level(line) {
            Some(level) => {
                output.push_str(&render_indented(&skin, &body, width, body_indent));
                body.clear();
                let (heading_indent, next_body_indent) = indents_for(level);
                output.push_str(&render_indented(&skin, line, width, heading_indent));
                body_indent = next_body_indent;
            }
            None => body.push_str(line),
        }
    }
    output.push_str(&render_indented(&skin, &body, width, body_indent));
    output
}

fn heading_level(line: &str) -> Option<usize> {
    let level = line.chars().take_while(|c| *c == '#').count();
    (level > 0 && line[level..].starts_with(' ')).then_some(level)
}

// Returns the indentation of a heading and of the text under it, as in `man git`.
fn indents_for(level: usize) -> (usize, usize) {
    match level {
        1 | 2 => (0, BODY_INDENT),
        _ => {
            let heading_indent = BODY_INDENT + NESTED_INDENT * (level - 3);
            (heading_indent, heading_indent + NESTED_INDENT)
        }
    }
}

fn render_indented(skin: &MadSkin, markdown: &str, width: usize, indent: usize) -> String {
    let prefix = " ".repeat(indent);
    skin.text(markdown, Some(width - indent))
        .to_string()
        .lines()
        .map(str::trim_end)
        .map(|line| {
            if line.is_empty() {
                "\n".to_string()
            } else {
                format!("{prefix}{line}\n")
            }
        })
        .collect()
}

// The default skin gives code a gray background, which is hard to read with light terminal themes.
fn styled_skin() -> MadSkin {
    let mut skin = MadSkin {
        inline_code: CompoundStyle::with_fg(Color::Yellow),
        ..Default::default()
    };
    skin.code_block.compound_style = CompoundStyle::with_fg(Color::Yellow);
    skin
}

/// Shows a manual page: in a pager when stdout is a terminal, else as plain text.
pub fn show(page: &str) -> anyhow::Result<()> {
    let source = page_source(page).ok_or_else(|| anyhow::anyhow!("No manual page {page}"))?;
    show_markdown(source)
}

/// Shows a Markdown document: in a pager when stdout is a terminal, else as plain text.
pub fn show_markdown(source: &str) -> anyhow::Result<()> {
    let markdown = rewrite_links(source, Cli::command().get_name());
    let to_terminal = std::io::stdout().is_terminal();
    let styled = to_terminal && std::env::var_os("NO_COLOR").is_none();
    let width = if to_terminal {
        terminal_width()
    } else {
        DEFAULT_WIDTH
    };
    let text = render(&markdown, styled, width);
    // If the pager fails, the text is printed directly.
    if to_terminal && page_text(&text).is_ok() {
        return Ok(());
    }
    write_text(&mut std::io::stdout().lock(), &text)
}

fn terminal_width() -> usize {
    termimad::crossterm::terminal::size()
        .map(|(columns, _)| usize::from(columns))
        .unwrap_or(DEFAULT_WIDTH)
}

// A text that fits on the screen is printed without the pager.
fn page_text(text: &str) -> Result<(), minus::MinusError> {
    let pager = minus::Pager::new();
    pager.set_text(text)?;
    minus::page_all(pager)
}

// A closed pipe (for example `| head`) is a normal end of the output.
fn write_text(writer: &mut impl Write, text: &str) -> anyhow::Result<()> {
    match writer
        .write_all(text.as_bytes())
        .and_then(|()| writer.flush())
    {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        result => Ok(result?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn render_without_style_has_no_escape_codes_and_fits_the_width() {
        let markdown = "# Title\n\nSome **bold** and `code` text in a paragraph that is much longer than the width.\n\n| a | b |\n|---|---|\n| one | two |\n";
        let text = render(markdown, false, 30);
        assert!(!text.contains('\x1b'), "escape code in: {text:?}");
        assert!(
            text.lines().all(|line| line.chars().count() <= 30),
            "line too wide in: {text}"
        );
        assert!(text.contains('│'), "no table in: {text}");
    }

    #[test]
    fn render_with_style_has_escape_codes() {
        assert!(render("Some **bold** text", true, 80).contains('\x1b'));
    }

    #[test]
    fn heading_level_detects_markdown_headings() {
        let cases = vec![
            ("# Title\n", Some(1)),
            ("### `-o --output`\n", Some(3)),
            ("#### Sub\n", Some(4)),
            ("#no space\n", None),
            ("text # not a heading\n", None),
            ("    # comment in code\n", None),
            ("", None),
        ];
        for (line, expected) in cases {
            assert_eq!(heading_level(line), expected, "line: {line:?}");
        }
    }

    // Column of the first character of the line that contains `text`.
    fn column_of(rendered: &str, text: &str) -> usize {
        let line = rendered
            .lines()
            .find(|line| line.contains(text))
            .unwrap_or_else(|| panic!("{text} not in: {rendered}"));
        line.len() - line.trim_start().len()
    }

    #[test]
    fn render_indents_like_man_pages() {
        let markdown = "# Title\n\nIntro text.\n\n## Options\n\n### `-o`\n\nOption text.\n\n    code line\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n#### Sub\n\nSub text.\n\n## Notes\n\nNote text.\n";
        let text = render(markdown, false, 60);
        let cases = vec![
            ("Intro text.", 7),
            ("Options", 0),
            ("-o", 7),
            ("Option text.", 11),
            ("code line", 11),
            ("│ a", 11),
            ("Sub", 11),
            ("Sub text.", 15),
            ("Notes", 0),
            ("Note text.", 7),
        ];
        for (content, column) in cases {
            assert_eq!(column_of(&text, content), column, "{content} in: {text}");
        }
        assert!(
            column_of(&text, "Title") > 20,
            "title not centered in: {text}"
        );
        assert!(
            text.lines().all(|line| line == line.trim_end()),
            "trailing spaces in: {text:?}"
        );
    }

    #[test]
    fn render_does_not_indent_in_narrow_terminals() {
        let text = render("## Options\n\nOption text.\n", false, 30);
        assert_eq!(column_of(&text, "Option text."), 0, "{text}");
    }

    #[test]
    fn each_page_fits_the_width() {
        for width in [40, 60, 80] {
            for (name, source) in PAGES {
                let text = render(&rewrite_links(source, "asfaload-cli"), false, width);
                assert!(
                    text.lines().all(|line| line.chars().count() <= width),
                    "line wider than {width} in page {name}"
                );
            }
        }
    }

    #[test]
    fn workflow_fits_the_width_and_has_no_raw_link() {
        let markdown = rewrite_links(&remove_see_lines(WORKFLOW), "asfaload-cli");
        assert!(!markdown.contains("]("), "raw link in workflow");
        for width in [40, 60, 80] {
            let text = render(&markdown, false, width);
            assert!(
                text.lines().all(|line| line.chars().count() <= width),
                "line wider than {width} in workflow"
            );
        }
    }

    #[test]
    fn remove_see_lines_removes_only_see_lines() {
        let cases = vec![
            ("Text.\n\nSee [a](a.md).\n\n## Next\n", "Text.\n\n## Next\n"),
            ("See [a](a.md).\n", ""),
            ("See [a](a.md).\nText.\n", "Text.\n"),
            ("We See [a](a.md).\n", "We See [a](a.md).\n"),
            ("See the guide.\n", "See the guide.\n"),
            ("    See [a](a.md).\n", "    See [a](a.md).\n"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(remove_see_lines(input), expected, "input: {input:?}");
        }
    }

    fn args(line: &str) -> Vec<OsString> {
        std::iter::once("asfaload-cli")
            .chain(line.split_whitespace())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn requested_page_finds_the_page_to_show() {
        let cases = vec![
            ("download https://example.com/f", None),
            ("--manual", Some(INDEX_PAGE)),
            ("download --manual", Some("download")),
            ("download --manual -o x", Some("download")),
            (
                "download https://example.com/f --json --manual",
                Some("download"),
            ),
            ("downlaod --manual", None),
            ("shell -- --manual", None),
            ("help --manual", None),
            ("download --manual=x", None),
        ];
        for (line, expected) in cases {
            assert_eq!(requested_page(&args(line)), expected, "arguments: {line}");
        }
    }

    struct FailingWriter(std::io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_text_ignores_only_broken_pipe() {
        assert!(write_text(&mut FailingWriter(std::io::ErrorKind::BrokenPipe), "x").is_ok());
        assert!(
            write_text(
                &mut FailingWriter(std::io::ErrorKind::PermissionDenied),
                "x"
            )
            .is_err()
        );
    }

    #[test]
    fn each_page_link_points_to_an_embedded_page() {
        for (name, source) in PAGES {
            for line in source.lines().filter(|line| !line.starts_with("    ")) {
                let mut rest = line;
                while let Some(start) = rest.find('[') {
                    let candidate = &rest[start..];
                    if let Some((_, target, _)) = parse_link(candidate)
                        && let Some(page) = linked_page(target)
                    {
                        assert!(
                            page_source(page).is_some(),
                            "page {name} links to unknown page {page}"
                        );
                    }
                    rest = &candidate[1..];
                }
            }
        }
    }
}
