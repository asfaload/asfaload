use anstyle::Style;
use client_lib::config::CliConfig;
use features_lib::SignersConfig;
use signers_file_types::SignerGroup;

/// Describe a signer group for the human overview, e.g. "2 of 3 keys must sign".
fn group_summary(keys_count: usize, threshold: u32) -> String {
    let noun = if keys_count == 1 { "key" } else { "keys" };
    format!("{threshold} of {keys_count} {noun} must sign")
}

/// The heading and one block per signer group, with the keys and their aliases.
pub(crate) fn signer_groups_lines(
    signers: &SignersConfig,
    cli_config: &CliConfig,
    bold: Style,
) -> Vec<String> {
    let proposal = signers.as_proposal();
    let mut lines = vec![format!("{bold}Signer groups{bold:#}")];
    lines.extend(groups_lines(
        "Artifact signers",
        &proposal.artifact_signers,
        "none",
        cli_config,
    ));
    lines.extend(groups_lines(
        "Admin keys",
        proposal.admin_keys.as_deref().unwrap_or_default(),
        "none (fallback to artifact signers)",
        cli_config,
    ));
    lines.extend(groups_lines(
        "Master keys",
        proposal.master_keys.as_deref().unwrap_or_default(),
        "none",
        cli_config,
    ));
    // The backend uses the admin keys when no revocation keys are set.
    lines.extend(groups_lines(
        "Revocation keys",
        proposal.revocation_keys.as_deref().unwrap_or_default(),
        "none (fallback to admin keys)",
        cli_config,
    ));
    lines
}

fn groups_lines(
    label: &str,
    groups: &[SignerGroup],
    empty: &str,
    cli_config: &CliConfig,
) -> Vec<String> {
    if groups.is_empty() {
        return vec![format!("  {label:<18} {empty}")];
    }
    groups
        .iter()
        .flat_map(|group| {
            let summary = group_summary(group.signers.len(), group.threshold);
            std::iter::once(format!("  {label:<18} {summary}")).chain(
                group
                    .signers
                    .iter()
                    .map(|signer| format!("    {}", cli_config.humanise_key(&signer.data.pubkey))),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
    use signers_file_types::SignersConfigProposal;
    use test_helpers::TestKeys;

    fn keys(keys: &TestKeys, range: std::ops::Range<usize>) -> Vec<AsfaloadPublicKeys> {
        range.map(|n| keys.pub_key(n).unwrap().clone()).collect()
    }

    #[test]
    fn group_summary_cases() {
        let cases = [
            (3, 2, "2 of 3 keys must sign"),
            (1, 1, "1 of 1 key must sign"),
        ];
        for (keys_count, threshold, expected) in cases {
            assert_eq!(
                group_summary(keys_count, threshold),
                expected,
                "unexpected summary for {keys_count} keys and threshold {threshold}"
            );
        }
    }

    #[test]
    fn artifact_only_shows_fallbacks_and_alias() {
        let test_keys = TestKeys::new(2);
        let artifact = keys(&test_keys, 0..2);
        let signers = SignersConfig::with_keys(1, (artifact.clone(), 2), None, None, None).unwrap();
        let mut cli_config = CliConfig::default();
        cli_config.add_alias(&artifact[0], "alice", false).unwrap();
        assert_eq!(
            signer_groups_lines(&signers, &cli_config, Style::new()),
            vec![
                "Signer groups".to_string(),
                "  Artifact signers   2 of 2 keys must sign".to_string(),
                format!("    {} (alice)", artifact[0].to_base64()),
                format!("    {}", artifact[1].to_base64()),
                "  Admin keys         none (fallback to artifact signers)".to_string(),
                "  Master keys        none".to_string(),
                "  Revocation keys    none (fallback to admin keys)".to_string(),
            ]
        );
    }

    #[test]
    fn all_groups_list_their_keys() {
        let test_keys = TestKeys::new(4);
        let signers = SignersConfig::with_keys(
            1,
            (keys(&test_keys, 0..1), 1),
            Some((keys(&test_keys, 1..2), 1)),
            Some((keys(&test_keys, 2..3), 1)),
            Some((keys(&test_keys, 3..4), 1)),
        )
        .unwrap();
        let key = |n: usize| test_keys.pub_key(n).unwrap().to_base64();
        assert_eq!(
            signer_groups_lines(&signers, &CliConfig::default(), Style::new()),
            vec![
                "Signer groups".to_string(),
                "  Artifact signers   1 of 1 key must sign".to_string(),
                format!("    {}", key(0)),
                "  Admin keys         1 of 1 key must sign".to_string(),
                format!("    {}", key(1)),
                "  Master keys        1 of 1 key must sign".to_string(),
                format!("    {}", key(2)),
                "  Revocation keys    1 of 1 key must sign".to_string(),
                format!("    {}", key(3)),
            ]
        );
    }

    #[test]
    fn several_groups_in_one_category() {
        let test_keys = TestKeys::new(3);
        let base = SignersConfig::with_keys(1, (keys(&test_keys, 0..2), 2), None, None, None)
            .unwrap()
            .as_proposal();
        let second = SignersConfig::with_keys(1, (keys(&test_keys, 2..3), 1), None, None, None)
            .unwrap()
            .as_proposal();
        let proposal = SignersConfigProposal {
            artifact_signers: [base.artifact_signers, second.artifact_signers].concat(),
            ..base
        };
        let signers = proposal.build().unwrap();
        let key = |n: usize| test_keys.pub_key(n).unwrap().to_base64();
        let lines = signer_groups_lines(&signers, &CliConfig::default(), Style::new());
        assert_eq!(
            lines,
            vec![
                "Signer groups".to_string(),
                "  Artifact signers   2 of 2 keys must sign".to_string(),
                format!("    {}", key(0)),
                format!("    {}", key(1)),
                "  Artifact signers   1 of 1 key must sign".to_string(),
                format!("    {}", key(2)),
                "  Admin keys         none (fallback to artifact signers)".to_string(),
                "  Master keys        none".to_string(),
                "  Revocation keys    none (fallback to admin keys)".to_string(),
            ]
        );
    }
}
