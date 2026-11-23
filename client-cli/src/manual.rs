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
}
