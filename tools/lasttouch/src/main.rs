use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cliutil::{error, warn};
use fsmeta::format_systemtime_ago;

#[derive(Parser, Debug)]
#[command(name = "lasttouch")]
struct Args {
    path: String,
}

#[derive(Clone, Debug)]
struct TouchInfo {
    user: String,
    process: String,
    time: SystemTime,
    source: String,
    metadata_only: bool,
}

fn main() {
    if let Err(e) = run() {
        error(&e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();

    let input = PathBuf::from(args.path);
    let path = if input.is_absolute() {
        input
    } else {
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        cwd.join(input)
    };

    let md = fs::metadata(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let mtime = md.modified().map_err(|e| e.to_string())?;

    if let Some(info) = try_audit_log(&path)? {
        print_info(&info);
        return Ok(());
    }

    if let Some(info) = try_journalctl(&path)? {
        print_info(&info);
        return Ok(());
    }

    let info = TouchInfo {
        user: "unknown".to_string(),
        process: "unknown".to_string(),
        time: mtime,
        source: "metadata".to_string(),
        metadata_only: true,
    };

    print_info(&info);

    Ok(())
}

fn print_info(info: &TouchInfo) {
    println!("Last modified by:");
    println!("User: {}", info.user);
    println!("Process: {}", info.process);
    println!("Time: {}", format_systemtime_ago(info.time));
    println!("Source: {}", info.source);

    if info.metadata_only {
        println!("Modification source unknown (metadata only).");
    }
}

fn parse_passwd() -> io::Result<HashMap<u32, String>> {
    let f = fs::File::open("/etc/passwd")?;
    let reader = io::BufReader::new(f);

    let mut out = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split(':');
        let name = match parts.next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let _passwd = parts.next();
        let uid = match parts.next() {
            Some(s) => s.parse::<u32>().ok(),
            None => None,
        };
        if let Some(uid) = uid {
            out.insert(uid, name);
        }
    }

    Ok(out)
}

fn uid_to_user(uid: u32, passwd: &HashMap<u32, String>) -> String {
    passwd.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
}

fn try_audit_log(path: &Path) -> Result<Option<TouchInfo>, String> {
    let audit_path = Path::new("/var/log/audit/audit.log");
    if !audit_path.exists() {
        return Ok(None);
    }

    let f = match fs::File::open(audit_path) {
        Ok(f) => f,
        Err(e) => {
            warn(&format!("audit log not readable: {e}"));
            return Ok(None);
        }
    };

    let passwd = parse_passwd().unwrap_or_default();

    let reader = io::BufReader::new(f);

    let target = path.to_string_lossy().to_string();

    #[derive(Default)]
    struct AuditEvent {
        sec: u64,
        uid: Option<u32>,
        comm: Option<String>,
        syscall: Option<u64>,
        a1: Option<u64>,
        a2: Option<u64>,
        has_target_path: bool,
        success: Option<bool>,
    }

    let mut events: HashMap<String, AuditEvent> = HashMap::new();
    let mut last_match: Option<(u64, String)> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let Some(msg_id) = extract_audit_msg_id(&line) else {
            continue;
        };

        let entry = events.entry(msg_id.clone()).or_default();

        if entry.sec == 0 {
            if let Some(sec) = extract_audit_seconds(&line) {
                entry.sec = sec;
            }
        }

        if line.contains("type=SYSCALL") {
            entry.syscall = extract_kv_u64(&line, "syscall");
            entry.uid = extract_kv_u32(&line, "uid");
            entry.comm = extract_kv_string(&line, "comm");
            entry.a1 = extract_kv_hex_u64(&line, "a1");
            entry.a2 = extract_kv_hex_u64(&line, "a2");
            entry.success = extract_kv_string(&line, "success").map(|s| s == "yes");
        }

        if line.contains("type=PATH") {
            if let Some(name) = extract_kv_string(&line, "name") {
                if name == target {
                    entry.has_target_path = true;
                }
            }
        }

        if entry.has_target_path {
            if let Some(true) = entry.success {
                if let Some(syscall) = entry.syscall {
                    if audit_event_is_modification(syscall, entry.a1, entry.a2) {
                        let sec = entry.sec;
                        if sec > 0 {
                            let update = match &last_match {
                                Some((last_sec, _)) => sec >= *last_sec,
                                None => true,
                            };
                            if update {
                                last_match = Some((sec, msg_id.clone()));
                            }
                        }
                    }
                }
            }
        }
    }

    let Some((sec, id)) = last_match else {
        return Ok(None);
    };

    let Some(ev) = events.get(&id) else {
        return Ok(None);
    };

    let uid = ev.uid.unwrap_or(0);
    let user = uid_to_user(uid, &passwd);
    let process = ev.comm.clone().unwrap_or_else(|| "unknown".to_string());
    let time = UNIX_EPOCH + Duration::from_secs(sec);

    Ok(Some(TouchInfo {
        user,
        process,
        time,
        source: "audit".to_string(),
        metadata_only: false,
    }))
}

fn audit_event_is_modification(syscall: u64, a1: Option<u64>, a2: Option<u64>) -> bool {
    match syscall {
        2 => {
            let flags = a1.unwrap_or(0);
            open_flags_modify(flags)
        }
        257 => {
            let flags = a2.unwrap_or(0);
            open_flags_modify(flags)
        }
        76 | 77 | 82 | 87 | 90 | 92 | 260 | 263 | 264 | 268 | 280 | 316 => true,
        _ => false,
    }
}

fn open_flags_modify(flags: u64) -> bool {
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_TRUNC: u64 = 0o1000;
    const O_CREAT: u64 = 0o100;

    (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_CREAT)) != 0
}

fn extract_audit_msg_id(line: &str) -> Option<String> {
    let start = line.find("msg=audit(")?;
    let rest = &line[start + "msg=audit(".len()..];
    let end = rest.find(')')?;
    Some(rest[..end].to_string())
}

fn extract_audit_seconds(line: &str) -> Option<u64> {
    let start = line.find("msg=audit(")?;
    let rest = &line[start + "msg=audit(".len()..];
    let end = rest.find(':')?;
    let sec_part = &rest[..end];
    let sec_part = sec_part.split('.').next().unwrap_or(sec_part);
    sec_part.parse::<u64>().ok()
}

fn extract_kv_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let idx = line.find(&needle)?;
    let rest = &line[idx + needle.len()..];

    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }

    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn extract_kv_u64(line: &str, key: &str) -> Option<u64> {
    extract_kv_string(line, key)?.parse::<u64>().ok()
}

fn extract_kv_u32(line: &str, key: &str) -> Option<u32> {
    extract_kv_string(line, key)?.parse::<u32>().ok()
}

fn extract_kv_hex_u64(line: &str, key: &str) -> Option<u64> {
    let s = extract_kv_string(line, key)?;
    u64::from_str_radix(&s, 16).ok()
}

fn try_journalctl(path: &Path) -> Result<Option<TouchInfo>, String> {
    let escaped = escape_journal_regex(&path.to_string_lossy());

    let output = Command::new("journalctl")
        .arg("--no-pager")
        .arg("-o")
        .arg("export")
        .arg("-r")
        .arg("--grep")
        .arg(escaped)
        .arg("-n")
        .arg("1")
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            warn(&format!("journalctl unavailable: {e}"));
            return Ok(None);
        }
    };

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(None);
    }

    let mut fields = HashMap::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once('=') {
            fields.insert(k.to_string(), v.to_string());
        }
    }

    let ts_us = fields
        .get("__REALTIME_TIMESTAMP")
        .and_then(|s| s.parse::<u64>().ok());

    let uid = fields.get("_UID").and_then(|s| s.parse::<u32>().ok());

    let process = fields
        .get("_COMM")
        .cloned()
        .or_else(|| fields.get("SYSLOG_IDENTIFIER").cloned())
        .unwrap_or_else(|| "unknown".to_string());

    let passwd = parse_passwd().unwrap_or_default();
    let user = uid
        .map(|u| uid_to_user(u, &passwd))
        .unwrap_or_else(|| "unknown".to_string());

    let time = match ts_us {
        Some(us) => UNIX_EPOCH + Duration::from_micros(us),
        None => SystemTime::now(),
    };

    Ok(Some(TouchInfo {
        user,
        process,
        time,
        source: "journal".to_string(),
        metadata_only: false,
    }))
}

fn escape_journal_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '.' | '^' | '$' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\'
            | '-' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}
