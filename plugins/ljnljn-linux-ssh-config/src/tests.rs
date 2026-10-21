use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

const ED25519_BLOB: &str =
    "AAAAC3NzaC1lZDI1NTE5AAAAIJ5DqqWUSBHrXhQt7BcQaZaSnXKZDX6V76rMTPbf1gIf";
const ED25519_FINGERPRINT: &str = "SHA256:OQRV4zewMV5e2i4ithwuXk3G+2o667AE9prUBsOMUT4";

struct Root {
    path: PathBuf,
}

impl Root {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-ssh-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn run(&self, analyzer: &str, inputs: &[&str]) -> TestRun {
        Harness::new(super::plugin)
            .run_with_inputs(
                analyzer,
                Fixture::system("linux", &self.path),
                inputs,
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run")
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn server_config_keeps_match_sections_and_drop_in_sources() {
    let root = Root::new("sshd");
    root.write(
        "etc/ssh/sshd_config",
        "Port 22\nPermitRootLogin prohibit-password\nInclude sshd_config.d/*.conf\nMatch User backup\n  PasswordAuthentication no\n",
    );
    root.write(
        "etc/ssh/sshd_config.d/50-custom.conf",
        "PasswordAuthentication yes\nAllowUsers alice\n",
    );
    let run = root.run(
        "sshd_config",
        &["etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*.conf"],
    );

    assert_eq!(run.count("linux.ssh.server_setting"), 7);
    let records = run.of_type("linux.ssh.server_setting");
    let matched = records
        .iter()
        .find(|record| {
            record.text("keyword") == Some("passwordauthentication")
                && record.text("section") == Some("User backup")
        })
        .expect("match-scoped setting");
    assert_eq!(matched.text("value"), Some("no"));
    let drop_in = records
        .iter()
        .find(|record| {
            record.text("source") == Some("etc/ssh/sshd_config.d/50-custom.conf")
                && record.text("keyword") == Some("passwordauthentication")
        })
        .expect("drop-in setting");
    assert_eq!(drop_in.text("section"), Some("(global)"));
    assert_eq!(drop_in.text("value"), Some("yes"));
    assert!(records.iter().any(|record| record.text("keyword") == Some("include")));
    assert!(run.summary.as_deref().unwrap_or("").contains("2 个文件"));
}

#[test]
fn client_config_keeps_host_context() {
    let root = Root::new("sshclient");
    root.write(
        "etc/ssh/ssh_config",
        "Host *\n  User alice\nHost example.com\n  ProxyJump bastion\n  User bob\n",
    );
    let run = root.run("ssh_config", &["etc/ssh/ssh_config"]);

    assert_eq!(run.count("linux.ssh.client_setting"), 5);
    let records = run.of_type("linux.ssh.client_setting");
    let proxy = records
        .iter()
        .find(|record| record.text("keyword") == Some("proxyjump"))
        .expect("proxyjump");
    assert_eq!(proxy.text("host"), Some("example.com"));
    assert_eq!(proxy.text("value"), Some("bastion"));
    let global_user = records
        .iter()
        .find(|record| {
            record.text("host") == Some("*") && record.text("keyword") == Some("user")
        })
        .expect("global user");
    assert_eq!(global_user.text("value"), Some("alice"));
}

#[test]
fn authorized_keys_extract_options_fingerprint_and_bits() {
    let root = Root::new("authorized");
    root.write(
        "root/.ssh/authorized_keys",
        &format!(
            "from=\"192.0.2.0/24\",no-port-forwarding ssh-ed25519 {ED25519_BLOB} test@example\n"
        ),
    );
    root.write(
        "home/alice/.ssh/authorized_keys",
        &format!("ssh-ed25519 {ED25519_BLOB} alice@example\n"),
    );
    let run = root.run(
        "authorized_keys",
        &["root/.ssh/authorized_keys", "home/*/.ssh/authorized_keys"],
    );

    assert_eq!(run.count("linux.ssh.authorized_key"), 2);
    let records = run.of_type("linux.ssh.authorized_key");
    let root_key = records
        .iter()
        .find(|record| record.text("user") == Some("root"))
        .expect("root key");
    assert_eq!(root_key.text("key_type"), Some("ssh-ed25519"));
    assert_eq!(root_key.int("bits"), Some(256));
    assert_eq!(
        root_key.text("fingerprint_sha256"),
        Some(ED25519_FINGERPRINT)
    );
    assert_eq!(
        root_key.text("options"),
        Some("from=\"192.0.2.0/24\",no-port-forwarding")
    );
    assert_eq!(root_key.text("comment"), Some("test@example"));
    let alice_key = records
        .iter()
        .find(|record| record.text("user") == Some("alice"))
        .expect("alice key");
    assert_eq!(alice_key.text("comment"), Some("alice@example"));
    assert_eq!(alice_key.sources.len(), 1);
}

#[test]
fn host_public_keys_are_typed() {
    let root = Root::new("hostkey");
    root.write(
        "etc/ssh/ssh_host_ed25519_key.pub",
        &format!("ssh-ed25519 {ED25519_BLOB} host@example\n"),
    );
    let run = root.run(
        "host_keys",
        &["etc/ssh/ssh_host_*_key.pub"],
    );

    assert_eq!(run.count("linux.ssh.host_key"), 1);
    let record = run.of_type("linux.ssh.host_key")[0];
    assert_eq!(record.text("key_type"), Some("ssh-ed25519"));
    assert_eq!(record.int("bits"), Some(256));
    assert_eq!(
        record.text("fingerprint_sha256"),
        Some(ED25519_FINGERPRINT)
    );
}

#[test]
fn malformed_authorized_key_is_a_warning() {
    let root = Root::new("badkey");
    root.write("root/.ssh/authorized_keys", "not-a-key\n");
    let run = root.run("authorized_keys", &["root/.ssh/authorized_keys"]);

    assert_eq!(run.count("linux.ssh.authorized_key"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INVALID_KEY_LINE"));
}

#[test]
fn missing_input_is_a_warning_not_empty_success() {
    let root = Root::new("missing");
    let run = root.run("sshd_config", &["etc/ssh/sshd_config"]);
    assert_eq!(run.count("linux.ssh.server_setting"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}
