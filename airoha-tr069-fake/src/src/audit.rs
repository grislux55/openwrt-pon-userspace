// SPDX-License-Identifier: GPL-2.0-only

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_AUDIT_LOG_PATH: &str = "/tmp/tr069-fake.log";
pub const MAX_AUDIT_ENTRIES: usize = 200;
pub const MAX_AUDIT_FILE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct AuditLogger {
    inner: Arc<Mutex<AuditInner>>,
}

#[derive(Debug)]
struct AuditInner {
    path: PathBuf,
    max_entries: usize,
    max_bytes: usize,
    entries: VecDeque<String>,
}

impl AuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_limits(path, MAX_AUDIT_ENTRIES, MAX_AUDIT_FILE_BYTES)
    }

    pub fn with_limits(path: impl Into<PathBuf>, max_entries: usize, max_bytes: usize) -> Self {
        let path = path.into();
        assert!(
            path.starts_with("/tmp/"),
            "audit log must remain in /tmp memory tmpfs, got {}",
            path.display()
        );
        let max_entries = max_entries.max(1);
        let max_bytes = max_bytes.max(512);
        let entries = load_entries_from_path(&path, max_entries, max_bytes);
        Self {
            inner: Arc::new(Mutex::new(AuditInner {
                path,
                max_entries,
                max_bytes,
                entries,
            })),
        }
    }

    pub fn record(&self, level: &str, category: &str, message: &str) {
        let ts = now_secs();
        let sanitized = redact_secrets(message);
        let line = format!("[{ts}] [{level}] [{category}] {sanitized}");
        let mut guard = self.inner.lock().expect("audit mutex poisoned");
        guard.entries = load_entries_from_path(&guard.path, guard.max_entries, guard.max_bytes);
        if guard.entries.len() >= guard.max_entries {
            guard.entries.pop_front();
        }
        guard.entries.push_back(line);
        while total_bytes(&guard.entries) > guard.max_bytes && guard.entries.len() > 1 {
            guard.entries.pop_front();
        }
        let _ = flush_to_tmp(&guard.path, &guard.entries);
    }

    pub fn snapshot(&self) -> Vec<String> {
        let mut guard = self.inner.lock().expect("audit mutex poisoned");
        guard.entries = load_entries_from_path(&guard.path, guard.max_entries, guard.max_bytes);
        guard.entries.iter().cloned().collect()
    }

    pub fn clear(&self) {
        let mut guard = self.inner.lock().expect("audit mutex poisoned");
        guard.entries.clear();
        let _ = flush_to_tmp(&guard.path, &guard.entries);
    }
}

fn load_entries_from_path(path: &Path, max_entries: usize, max_bytes: usize) -> VecDeque<String> {
    let mut entries = VecDeque::new();
    if let Ok(existing) = fs::read_to_string(path) {
        for line in existing.lines() {
            if !line.is_empty() {
                if entries.len() >= max_entries {
                    entries.pop_front();
                }
                entries.push_back(line.to_owned());
            }
        }
        while total_bytes(&entries) > max_bytes && entries.len() > 1 {
            entries.pop_front();
        }
    }
    entries
}

fn total_bytes(entries: &VecDeque<String>) -> usize {
    entries.iter().map(|line| line.len() + 1).sum()
}

fn flush_to_tmp(path: &Path, entries: &VecDeque<String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("log.{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    for line in entries {
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    fs::rename(&tmp_path, path)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Redacts passwords, HTTP Basic/Digest Authorization headers, and XML secret tags.
pub fn redact_secrets(input: &str) -> String {
    let mut out = input.to_owned();

    out = redact_case_insensitive_header(&out, "authorization:");
    out = redact_case_insensitive_header(&out, "proxy-authorization:");

    for key in [
        "acs_password",
        "conn_req_password",
        "password",
        "passwd",
        "secret",
        "response",
    ] {
        out = redact_kv(&out, key);
    }

    out = redact_xml_tag(&out, "Password");
    out = redact_cwmp_password_param(&out);
    out
}

fn redact_case_insensitive_header(input: &str, prefix_lower: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut idx = 0;
    while let Some(pos) = lower[idx..].find(prefix_lower) {
        let abs = idx + pos;
        result.push_str(&input[idx..abs + prefix_lower.len()]);
        let rest = &input[abs + prefix_lower.len()..];
        let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        let header_val = &rest[..end];
        let trimmed = header_val.trim_start();
        let scheme = trimmed.split_whitespace().next().unwrap_or("");
        if !scheme.is_empty() {
            result.push(' ');
            result.push_str(scheme);
            result.push_str(" ***");
        } else {
            result.push_str(" ***");
        }
        idx = abs + prefix_lower.len() + end;
    }
    result.push_str(&input[idx..]);
    result
}

fn redact_kv(input: &str, key_lower: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut idx = 0;
    while let Some(pos) = lower[idx..].find(key_lower) {
        let abs = idx + pos;
        if abs > 0 {
            let prev = input.as_bytes()[abs - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                out.push_str(&input[idx..abs + key_lower.len()]);
                idx = abs + key_lower.len();
                continue;
            }
        }
        let after_key = abs + key_lower.len();
        let rest = &input[after_key..];
        if let Some(sep_len) = match_kv_sep(rest) {
            out.push_str(&input[idx..after_key + sep_len]);
            let val_rest = &rest[sep_len..];
            if let Some(after_quoted) = val_rest.strip_prefix('"') {
                let end_q = after_quoted.find('"').unwrap_or(after_quoted.len());
                out.push_str("\"***\"");
                let advance = if end_q < after_quoted.len() {
                    1 + end_q + 1
                } else {
                    val_rest.len()
                };
                idx = after_key + sep_len + advance;
            } else if let Some(after_sq) = val_rest.strip_prefix('\'') {
                let end_q = after_sq.find('\'').unwrap_or(after_sq.len());
                out.push_str("'***'");
                let advance = if end_q < after_sq.len() {
                    1 + end_q + 1
                } else {
                    val_rest.len()
                };
                idx = after_key + sep_len + advance;
            } else {
                let end = val_rest
                    .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '&' | ')' | '}'))
                    .unwrap_or(val_rest.len());
                out.push_str("***");
                idx = after_key + sep_len + end;
            }
        } else {
            out.push_str(&input[idx..after_key]);
            idx = after_key;
        }
    }
    out.push_str(&input[idx..]);
    out
}

fn match_kv_sep(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if i < bytes.len() && (bytes[i] == b'=' || bytes[i] == b':') {
        i += 1;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        Some(i)
    } else {
        None
    }
}

fn redact_xml_tag(input: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(input.len());
    let mut idx = 0;
    while let Some(pos) = input[idx..].find(&open) {
        let abs = idx + pos;
        let content_start = abs + open.len();
        if let Some(end_rel) = input[content_start..].find(&close) {
            out.push_str(&input[idx..content_start]);
            out.push_str("***");
            out.push_str(&close);
            idx = content_start + end_rel + close.len();
        } else {
            break;
        }
    }
    out.push_str(&input[idx..]);
    out
}

fn redact_cwmp_password_param(input: &str) -> String {
    let mut out = input.to_owned();
    for marker in ["Password</Name>", "PasswordKey</Name>"] {
        let mut next_out = String::with_capacity(out.len());
        let mut idx = 0;
        while let Some(pos) = out[idx..].find(marker) {
            let abs = idx + pos + marker.len();
            if let Some(val_rel) = out[abs..].find("<Value") {
                let val_tag_start = abs + val_rel;
                if let Some(gt_rel) = out[val_tag_start..].find('>') {
                    let content_start = val_tag_start + gt_rel + 1;
                    if let Some(close_rel) = out[content_start..].find("</Value>") {
                        next_out.push_str(&out[idx..content_start]);
                        next_out.push_str("***</Value>");
                        idx = content_start + close_rel + "</Value>".len();
                        continue;
                    }
                }
            }
            next_out.push_str(&out[idx..abs]);
            idx = abs;
        }
        next_out.push_str(&out[idx..]);
        out = next_out;
    }
    out
}
