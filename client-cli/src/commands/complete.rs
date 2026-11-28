use crate::{
    cli::Cli,
    error::{ClientCliError, Result},
};
use clap::CommandFactory;

mod keys;

pub fn handle_complete(
    shell: clap_complete_command::Shell,
    output: &mut dyn std::io::Write,
) -> Result<()> {
    let mut cmd = Cli::command();
    let mut script = Vec::new();
    shell.generate(&mut cmd, &mut script);
    let mut script = String::from_utf8(script).map_err(|e| {
        ClientCliError::InvalidInput(format!("completion script is not valid UTF-8: {e}"))
    })?;
    if matches!(shell, clap_complete_command::Shell::Bash) {
        script = fix_bash_subcommand_labels(&script, cmd.get_name());
    }
    let script = keys::with_key_completion(shell, &script, &cmd)?;
    output.write_all(script.as_bytes())?;
    Ok(())
}

// clap_complete bug: the case labels escape '-' in the binary name as "__subcmd__",
// the cmd variable as "__", so bash never completes subcommand options.
fn fix_bash_subcommand_labels(script: &str, bin_name: &str) -> String {
    script.replace(
        &bin_name.replace('-', "__subcmd__"),
        &bin_name.replace('-', "__"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_bash_subcommand_labels_uses_the_escaping_of_the_cmd_variable() {
        let cases = vec![
            (
                "asfaload-cli",
                "asfaload__cli,new-keys)\n cmd=\"asfaload__cli__subcmd__new__subcmd__keys\"\n asfaload__subcmd__cli__subcmd__new__subcmd__keys)\n",
                "asfaload__cli,new-keys)\n cmd=\"asfaload__cli__subcmd__new__subcmd__keys\"\n asfaload__cli__subcmd__new__subcmd__keys)\n",
            ),
            (
                "my-big-cli",
                "my__subcmd__big__subcmd__cli__subcmd__run)",
                "my__big__cli__subcmd__run)",
            ),
            ("tool", "tool__subcmd__run)", "tool__subcmd__run)"),
        ];
        for (bin_name, script, expected) in cases {
            assert_eq!(
                fix_bash_subcommand_labels(script, bin_name),
                expected,
                "bin name {bin_name}"
            );
        }
    }

    #[test]
    fn bash_script_has_subcommand_labels_that_match_the_cmd_variable() -> anyhow::Result<()> {
        let mut output = Vec::new();
        handle_complete(clap_complete_command::Shell::Bash, &mut output)?;
        let script = String::from_utf8(output)?;
        assert!(
            !script.contains("asfaload__subcmd__cli"),
            "script still has the wrong subcommand labels"
        );
        assert!(script.contains("cmd=\"asfaload__cli__subcmd__new__subcmd__keys\""));
        assert!(script.contains("asfaload__cli__subcmd__new__subcmd__keys)"));
        Ok(())
    }
}
