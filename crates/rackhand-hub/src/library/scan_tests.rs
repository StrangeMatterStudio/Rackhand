use super::{Finding, scan};

#[test]
fn refuses_each_secret_kind() {
    let vault_value = b"s3cr3t-webhook-token-value".to_vec();
    let cases: Vec<(&str, String, Finding)> = vec![
        ("vault value", "url = \"https://example.invalid/?t=s3cr3t-webhook-token-value\"".into(), Finding::VaultValue),
        (
            "PEM",
            "key = '''\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'''".into(),
            Finding::PrivateKey,
        ),
        ("RSA PEM", "-----BEGIN RSA PRIVATE KEY-----".into(), Finding::PrivateKey),
        ("OpenSSH", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl".into(), Finding::PrivateKey),
        ("Discord", "webhook = \"https://discord.com/api/webhooks/1/abc\"".into(), Finding::DiscordWebhook),
        ("Discordapp", "https://discordapp.com/api/webhooks/2/def".into(), Finding::DiscordWebhook),
        ("AWS", "aws = \"AKIAABCDEFGHIJKLMNOP\"".into(), Finding::AwsKey),
        ("password", "password = \"hunter2\"".into(), Finding::Password),
        ("password spacing", "smtp_password=\"x\"".into(), Finding::Password),
    ];
    for (what, text, want) in cases {
        let found = scan(&text, std::slice::from_ref(&vault_value));
        assert!(found.contains(&want), "{what}: {found:?}");
    }
}

#[test]
fn allows_secret_references() {
    let text = "password = \"secret:smtp\"\nwebhook = \"secret:discord-ops\"\ndescription = \"rotates the password\"\n";
    assert!(scan(text, &[b"long-enough-value".to_vec()]).is_empty());
    // Short Vault values would match by accident and aren't treated as findings.
    assert!(scan("rev = 1", &[b"1".to_vec()]).is_empty());
}
