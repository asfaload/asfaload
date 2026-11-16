use crate::{cli::Cli, error::Result};
use clap::CommandFactory;
pub fn handle_complete(
    shell: clap_complete_command::Shell,
    output: &mut dyn std::io::Write,
) -> Result<()> {
    shell.generate(&mut Cli::command(), output);
    Ok(())
}
