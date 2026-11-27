use std::ffi::OsString;

use anyhow::Result;
use clap::Parser;
use client_cli::{
    cli::{Cli, with_help_usage},
    commands::handle_command,
    manual,
    output::JsonError,
};

fn main() -> Result<()> {
    // `--manual` must work without the required arguments of the subcommand, so it is
    // handled before the parse validates them.
    let args: Vec<OsString> = std::env::args_os().collect();
    if let Some(page) = manual::requested_page(&args) {
        return manual::show(page);
    }
    let cli = Cli::try_parse_from(&args).unwrap_or_else(|e| with_help_usage(e, &args).exit());
    let json = cli.command.json_output();

    if let Err(e) = handle_command(&cli) {
        if json {
            let json_err = JsonError {
                error: e.to_string(),
            };
            eprintln!(
                "{}",
                serde_json::to_string(&json_err).unwrap_or_else(|_| {
                    // This fallback ensures we always output valid JSON, even if serializing
                    // the original error fails. It avoids injecting a raw error string
                    // that might contain characters that would break the JSON structure.
                    r#"{"error":"An unexpected error occurred and it could not be serialized."}"#
                        .to_string()
                })
            );
        } else {
            eprintln!("{}", e);
        }
        std::process::exit(1);
    }

    Ok(())
}
