//! Linux OpenSSH configuration, authorized-key and host-key analyzer (LPP v2).
//!
//! The host runs these analyzers against a Linux system view. Server/client
//! configuration is emitted as source-attributed keyword/value records; the
//! `Match` / `Host` context is kept on every record. Authorized keys and
//! host public keys are parsed into type, bit length, SHA256 fingerprint and
//! options. Include directives are recorded but not followed: the standard
//! `sshd_config.d` and `ssh_config.d` drop-ins are declared as inputs.

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use lovelycarve_plugin::{export_plugin, Plugin, Record, Result, Run};
use sha2::{Digest, Sha256};

mod key;
#[cfg(test)]
mod tests;

/// Largest text configuration file read into memory.
const TEXT_CAP: u64 = 16 * 1024 * 1024;

#[derive(Record)]
#[record(
    id = "linux.ssh.server_setting",
    label = "SSH 服务端配置项",
    title = "{keyword} = {value}"
)]
struct ServerSetting {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    line: i64,
    #[field(label = "作用域")]
    section: String,
    #[field(label = "关键字", key)]
    keyword: String,
    #[field(label = "值")]
    value: String,
}

#[derive(Record)]
#[record(
    id = "linux.ssh.client_setting",
    label = "SSH 客户端配置项",
    title = "{host}: {keyword} = {value}"
)]
struct ClientSetting {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    line: i64,
    #[field(label = "Host 模式", key)]
    host: String,
    #[field(label = "关键字", key)]
    keyword: String,
    #[field(label = "值")]
    value: String,
}

#[derive(Record)]
#[record(
    id = "linux.ssh.authorized_key",
    label = "SSH 授权公钥",
    title = "{user} / {key_type}"
)]
struct AuthorizedKey {
    #[field(label = "用户", key)]
    user: String,
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    line: i64,
    #[field(label = "密钥类型")]
    key_type: String,
    #[field(label = "位数")]
    bits: Option<i64>,
    #[field(label = "SHA256 指纹")]
    fingerprint_sha256: String,
    #[field(label = "注释")]
    comment: Option<String>,
    #[field(label = "授权选项")]
    options: Option<String>,
}

#[derive(Record)]
#[record(
    id = "linux.ssh.host_key",
    label = "SSH 主机公钥",
    title = "{source}"
)]
struct HostKey {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "密钥类型")]
    key_type: String,
    #[field(label = "位数")]
    bits: Option<i64>,
    #[field(label = "SHA256 指纹")]
    fingerprint_sha256: String,
    #[field(label = "注释")]
    comment: Option<String>,
}

fn sshd_config(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut settings = 0usize;
    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let source = source_path(file);
        let text = match file.read_text(TEXT_CAP) {
            Ok(text) => text,
            Err(error) => {
                run.warn_file(file, &error.code, error.message.clone())?;
                continue;
            }
        };
        let mut section = "(global)".to_owned();
        for (index, line) in text.lines().enumerate() {
            let Some((keyword, value)) = parse_setting(line) else {
                continue;
            };
            if keyword.eq_ignore_ascii_case("match") {
                section = value.clone();
            }
            run.record(&ServerSetting {
                source: source.clone(),
                line: index as i64 + 1,
                section: section.clone(),
                keyword: keyword.to_ascii_lowercase(),
                value,
            })
            .from(file)
            .note(format!("第 {} 行", index + 1))
            .emit()?;
            settings += 1;
        }
    }
    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未找到 etc/ssh/sshd_config 或 drop-in 配置")?;
    }
    run.set_summary(format!(
        "SSH 服务端配置：{files} 个文件，{settings} 个配置项"
    ));
    Ok(())
}

fn ssh_config(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut settings = 0usize;
    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let source = source_path(file);
        let text = match file.read_text(TEXT_CAP) {
            Ok(text) => text,
            Err(error) => {
                run.warn_file(file, &error.code, error.message.clone())?;
                continue;
            }
        };
        let mut host = "(global)".to_owned();
        for (index, line) in text.lines().enumerate() {
            let Some((keyword, value)) = parse_setting(line) else {
                continue;
            };
            if keyword.eq_ignore_ascii_case("host") {
                host = value.clone();
            }
            run.record(&ClientSetting {
                source: source.clone(),
                line: index as i64 + 1,
                host: host.clone(),
                keyword: keyword.to_ascii_lowercase(),
                value,
            })
            .from(file)
            .note(format!("第 {} 行", index + 1))
            .emit()?;
            settings += 1;
        }
    }
    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未找到 etc/ssh/ssh_config 或用户 SSH 配置")?;
    }
    run.set_summary(format!(
        "SSH 客户端配置：{files} 个文件，{settings} 个配置项"
    ));
    Ok(())
}

fn authorized_keys(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut keys = 0usize;
    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let source = source_path(file);
        let user = user_from_path(&source);
        let text = match file.read_text(TEXT_CAP) {
            Ok(text) => text,
            Err(error) => {
                run.warn_file(file, &error.code, error.message.clone())?;
                continue;
            }
        };
        for (index, line) in text.lines().enumerate() {
            let line_number = index as i64 + 1;
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let Some(parsed) = parse_public_key(line) else {
                run.warn_file(
                    file,
                    "INVALID_KEY_LINE",
                    format!("第 {} 行不是可识别的 OpenSSH 公钥", index + 1),
                )?;
                continue;
            };
            let Some(blob) = decode_blob(&parsed.blob) else {
                run.warn_file(
                    file,
                    "INVALID_KEY_BASE64",
                    format!("第 {} 行公钥 Base64 无效", index + 1),
                )?;
                continue;
            };
            run.record(&AuthorizedKey {
                user: user.clone(),
                source: source.clone(),
                line: line_number,
                key_type: parsed.key_type.clone(),
                bits: key::bits(&blob),
                fingerprint_sha256: fingerprint(&blob),
                comment: parsed.comment,
                options: parsed.options,
            })
            .from(file)
            .note(format!("第 {} 行", index + 1))
            .emit()?;
            keys += 1;
        }
    }
    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未找到 root/home/* 的 authorized_keys")?;
    }
    run.set_summary(format!(
        "SSH 授权公钥：{files} 个文件，{keys} 条公钥"
    ));
    Ok(())
}

fn host_keys(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut keys = 0usize;
    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let source = source_path(file);
        let text = match file.read_text(TEXT_CAP) {
            Ok(text) => text,
            Err(error) => {
                run.warn_file(file, &error.code, error.message.clone())?;
                continue;
            }
        };
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let Some(parsed) = parse_public_key(line) else {
                run.warn_file(
                    file,
                    "INVALID_KEY_LINE",
                    format!("第 {} 行不是可识别的 OpenSSH 公钥", index + 1),
                )?;
                continue;
            };
            let Some(blob) = decode_blob(&parsed.blob) else {
                run.warn_file(
                    file,
                    "INVALID_KEY_BASE64",
                    format!("第 {} 行公钥 Base64 无效", index + 1),
                )?;
                continue;
            };
            run.record(&HostKey {
                source: source.clone(),
                key_type: parsed.key_type,
                bits: key::bits(&blob),
                fingerprint_sha256: fingerprint(&blob),
                comment: parsed.comment,
            })
            .from(file)
            .note(format!("第 {} 行", index + 1))
            .emit()?;
            keys += 1;
        }
    }
    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未找到 SSH 主机公钥")?;
    }
    run.set_summary(format!("SSH 主机公钥：{files} 个文件，{keys} 条公钥"));
    Ok(())
}

fn source_path(file: &lovelycarve_plugin::FileRef) -> String {
    file.view_path().unwrap_or_else(|| file.name()).to_owned()
}

fn user_from_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("home/") {
        return rest.split('/').next().unwrap_or_default().to_owned();
    }
    if path.starts_with("root/") {
        return "root".to_owned();
    }
    String::new()
}

/// Parses `Key value` and `Key=value` lines; comments and blank lines are skipped.
fn parse_setting(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Some((key, value)) = line.split_once('=') {
        let key = key.trim();
        if !key.is_empty() && !key.chars().any(char::is_whitespace) {
            return Some((key.to_owned(), value.trim().to_owned()));
        }
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next()?.trim();
    if key.is_empty() {
        return None;
    }
    let value = parts.next().unwrap_or_default().trim().to_owned();
    Some((key.to_owned(), value))
}

struct ParsedKey {
    options: Option<String>,
    key_type: String,
    blob: String,
    comment: Option<String>,
}

/// Finds the key-type token, so options (which may contain spaces) stay intact.
fn parse_public_key(line: &str) -> Option<ParsedKey> {
    let tokens = split_tokens(line);
    let index = tokens.iter().position(|token| key::is_type(token))?;
    let blob = tokens.get(index + 1)?.clone();
    let options = (index > 0).then(|| tokens[..index].join(" "));
    let comment = tokens
        .get(index + 2..)
        .map(|rest| rest.join(" "))
        .filter(|text| !text.is_empty());
    Some(ParsedKey {
        options,
        key_type: tokens[index].clone(),
        blob,
        comment,
    })
}

fn split_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            current.push(character);
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
                current.push(character);
            } else {
                current.push(character);
            }
        } else if character == '"' || character == '\'' {
            quote = Some(character);
            current.push(character);
        } else if character.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn decode_blob(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

fn fingerprint(blob: &[u8]) -> String {
    let digest = Sha256::digest(blob);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.linux-ssh-config")
        .record::<ServerSetting>()
        .record::<ClientSetting>()
        .record::<AuthorizedKey>()
        .record::<HostKey>()
        .analyzer("sshd_config", sshd_config)
        .analyzer("ssh_config", ssh_config)
        .analyzer("authorized_keys", authorized_keys)
        .analyzer("host_keys", host_keys)
}

export_plugin!(plugin);
