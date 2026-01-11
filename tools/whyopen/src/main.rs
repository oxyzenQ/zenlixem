use clap::Parser;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use cliutil::{
    error, print_header, print_info, print_version, privilege_mode, privilege_mode_message,
};
use fsmeta::{dev_major_minor, file_id_for_metadata, file_id_for_path, FileId};
use procscan::{
    list_pids, read_comm_access, read_fd_links_access, read_proc_maps_access,
    read_proc_net_sockets, ProcAccess, ProcNetProto,
};

const COMMAND_COL_WIDTH: usize = 16;

#[derive(Parser, Debug)]
#[command(name = "whyopen", disable_version_flag = true)]
struct Args {
    #[arg(short = 'v', long = "version")]
    version: bool,

    #[arg(short = 'i', long = "info")]
    info: bool,

    #[arg(long = "json")]
    json: bool,

    target: Option<String>,
}

enum AppError {
    InvalidInput(String),
    Fatal(String),
}

#[derive(Serialize)]
struct JsonError {
    kind: &'static str,
    error: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ProcResult {
    pid: i32,
    command: String,
    reasons: Vec<String>,
}

fn read_comm_best_effort(pid: i32) -> String {
    match read_comm_access(pid) {
        ProcAccess::Ok(s) => s,
        ProcAccess::PermissionDenied | ProcAccess::Gone | ProcAccess::Fatal(_) => {
            "<unknown>".to_string()
        }
    }
}

fn main() {
    let json_requested = std::env::args().any(|a| a == "--json");

    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            if json_requested {
                print_json_error(AppError::InvalidInput(e.to_string()));
            } else {
                error(&e.to_string());
            }
            std::process::exit(1);
        }
    };

    match run(args) {
        Ok(()) => std::process::exit(0),
        Err(AppError::InvalidInput(e)) => {
            if json_requested {
                print_json_error(AppError::InvalidInput(e));
            } else {
                error(&e);
            }
            std::process::exit(1);
        }
        Err(AppError::Fatal(e)) => {
            if json_requested {
                print_json_error(AppError::Fatal(e));
            } else {
                error(&e);
            }
            std::process::exit(2);
        }
    }
}

fn print_json_error(err: AppError) {
    let (kind, msg) = match err {
        AppError::InvalidInput(e) => ("invalid_input", e),
        AppError::Fatal(e) => ("fatal", e),
    };
    let payload = JsonError { kind, error: msg };
    println!(
        "{}",
        serde_json::to_string(&payload).unwrap_or_else(|_| {
            "{\"kind\":\"fatal\",\"error\":\"json serialization failed\"}".to_string()
        })
    );
}

fn run(args: Args) -> Result<(), AppError> {
    if args.version {
        print_version();
        return Ok(());
    }

    if args.info {
        print_info();
        return Ok(());
    }

    let target = args
        .target
        .ok_or_else(|| AppError::InvalidInput("missing target".to_string()))?;

    if let Ok(port) = target.parse::<u16>() {
        return whyopen_port(port, args.json);
    }

    let path = PathBuf::from(&target);
    whyopen_path(&path, args.json)
}

fn whyopen_path(path: &Path, json_out: bool) -> Result<(), AppError> {
    let target_id = match file_id_for_path(path) {
        Ok(id) => id,
        Err(e) => {
            let msg = format!("{}: {}", path.display(), e);
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(AppError::InvalidInput(msg));
            }
            return Err(AppError::Fatal(msg));
        }
    };

    let (tmaj, tmin) = dev_major_minor(target_id.dev);

    let mut results: BTreeMap<i32, ProcResult> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    for pid in pids {
        let mut any_denied = false;
        let mut reasons: Vec<String> = Vec::new();
        let mut comm: Option<String> = None;

        match scan_pid_open_fd_file(pid, target_id) {
            ProcAccess::Ok(true) => {
                reasons.push("open fd".to_string());
                comm = Some(read_comm_best_effort(pid));
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                any_denied = true;
            }
            ProcAccess::Gone => continue,
            ProcAccess::Fatal(e) => return Err(AppError::Fatal(e.to_string())),
        }

        match scan_pid_mmap_file(pid, tmaj, tmin, target_id.inode) {
            ProcAccess::Ok(true) => {
                reasons.push("memory mapped".to_string());
                if comm.is_none() {
                    comm = Some(read_comm_best_effort(pid));
                }
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                any_denied = true;
            }
            ProcAccess::Gone => continue,
            ProcAccess::Fatal(e) => return Err(AppError::Fatal(e.to_string())),
        }

        if reasons.is_empty() {
            if any_denied {
                skipped_permission_denied.insert(pid);
            }
            continue;
        }

        reasons.sort();
        reasons.dedup();

        let comm = comm.unwrap_or_else(|| "<unknown>".to_string());

        results.insert(
            pid,
            ProcResult {
                pid,
                command: comm,
                reasons,
            },
        );
    }

    if json_out {
        print_json(
            "path",
            path.display().to_string(),
            results,
            skipped_permission_denied.len(),
        );
    } else {
        print_human(
            "path",
            &path.display().to_string(),
            results,
            skipped_permission_denied.len(),
        );
    }

    Ok(())
}

fn whyopen_port(port: u16, json_out: bool) -> Result<(), AppError> {
    let sockets = read_proc_net_sockets().map_err(|e| AppError::Fatal(e.to_string()))?;

    let mut inode_to_labels: HashMap<u64, Vec<String>> = HashMap::new();

    for s in sockets {
        if s.local_port != port {
            continue;
        }
        let label = format!(
            "socket {} {}",
            proto_label(s.proto),
            socket_state_label(s.proto, s.state)
        );
        inode_to_labels.entry(s.inode).or_default().push(label);
    }

    let target_inodes: HashSet<u64> = inode_to_labels.keys().copied().collect();

    let mut results: BTreeMap<i32, ProcResult> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    if target_inodes.is_empty() {
        if json_out {
            print_json("port", port.to_string(), results, 0);
        } else {
            print_human("port", &port.to_string(), results, 0);
        }
        return Ok(());
    }

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    for pid in pids {
        let links = match read_fd_links_access(pid) {
            ProcAccess::Ok(v) => v,
            ProcAccess::PermissionDenied => {
                skipped_permission_denied.insert(pid);
                continue;
            }
            ProcAccess::Gone => continue,
            ProcAccess::Fatal(e) => return Err(AppError::Fatal(e.to_string())),
        };

        let mut reasons: Vec<String> = Vec::new();
        let mut comm: Option<String> = None;

        for (_fd, _fd_path, link) in links {
            let Some(inode) = parse_socket_inode(&link) else {
                continue;
            };
            if !target_inodes.contains(&inode) {
                continue;
            }

            if comm.is_none() {
                comm = Some(read_comm_best_effort(pid));
            }

            if let Some(labels) = inode_to_labels.get(&inode) {
                reasons.extend(labels.iter().cloned());
            } else {
                reasons.push("socket".to_string());
            }
        }

        if reasons.is_empty() {
            continue;
        }

        reasons.sort();
        reasons.dedup();

        let comm = comm.unwrap_or_else(|| "<unknown>".to_string());

        results.insert(
            pid,
            ProcResult {
                pid,
                command: comm,
                reasons,
            },
        );
    }

    if json_out {
        print_json(
            "port",
            port.to_string(),
            results,
            skipped_permission_denied.len(),
        );
    } else {
        print_human(
            "port",
            &port.to_string(),
            results,
            skipped_permission_denied.len(),
        );
    }

    Ok(())
}

fn scan_pid_open_fd_file(pid: i32, target: FileId) -> ProcAccess<bool> {
    let links = match read_fd_links_access(pid) {
        ProcAccess::Ok(v) => v,
        ProcAccess::PermissionDenied => return ProcAccess::PermissionDenied,
        ProcAccess::Gone => return ProcAccess::Gone,
        ProcAccess::Fatal(e) => return ProcAccess::Fatal(e),
    };

    for (_fd, fd_path, _link) in links {
        let md = match fs::metadata(&fd_path) {
            Ok(md) => md,
            Err(_) => continue,
        };

        if file_id_for_metadata(&md) == target {
            return ProcAccess::Ok(true);
        }
    }

    ProcAccess::Ok(false)
}

fn scan_pid_mmap_file(
    pid: i32,
    target_major: u32,
    target_minor: u32,
    target_inode: u64,
) -> ProcAccess<bool> {
    let maps = match read_proc_maps_access(pid) {
        ProcAccess::Ok(v) => v,
        ProcAccess::PermissionDenied => return ProcAccess::PermissionDenied,
        ProcAccess::Gone => return ProcAccess::Gone,
        ProcAccess::Fatal(e) => return ProcAccess::Fatal(e),
    };

    for entry in maps {
        if entry.inode == 0 {
            continue;
        }

        if entry.inode == target_inode
            && entry.dev_major == target_major
            && entry.dev_minor == target_minor
        {
            return ProcAccess::Ok(true);
        }
    }

    ProcAccess::Ok(false)
}

fn parse_socket_inode(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("socket:[")?;
    let rest = rest.strip_suffix(']')?;
    rest.parse::<u64>().ok()
}

fn proto_label(proto: ProcNetProto) -> &'static str {
    match proto {
        ProcNetProto::Tcp | ProcNetProto::Tcp6 => "tcp",
        ProcNetProto::Udp | ProcNetProto::Udp6 => "udp",
    }
}

fn socket_state_label(proto: ProcNetProto, state: u8) -> String {
    let label = match proto {
        ProcNetProto::Tcp | ProcNetProto::Tcp6 => match state {
            0x01 => "established",
            0x0A => "listening",
            _ => "",
        },
        ProcNetProto::Udp | ProcNetProto::Udp6 => match state {
            0x07 => "listening",
            _ => "",
        },
    };

    if label.is_empty() {
        format!("0x{state:02X}")
    } else {
        label.to_string()
    }
}

fn print_human(
    mode: &'static str,
    target: &str,
    results: BTreeMap<i32, ProcResult>,
    skipped: usize,
) {
    println!("{}", privilege_mode_message());
    if skipped > 0 {
        println!("Partial result: {skipped} processes skipped (permission denied)");
    }

    match mode {
        "path" => println!("Target path: {target}"),
        "port" => println!("Target port: {target}"),
        _ => println!("Target: {target}"),
    }
    println!();

    if results.is_empty() {
        println!("No active reasons detected.");
        return;
    }

    print_header("Because:");

    for (_pid, r) in results {
        println!(
            "{pid:<5} {comm:<width$}",
            pid = r.pid,
            comm = r.command,
            width = COMMAND_COL_WIDTH
        );
        for reason in r.reasons {
            println!("  - {reason}");
        }
    }
}

fn print_json(
    mode: &'static str,
    target: String,
    results: BTreeMap<i32, ProcResult>,
    skipped: usize,
) {
    let partial = skipped > 0;
    let mut rows: Vec<ProcResult> = Vec::new();
    for (_pid, r) in results {
        rows.push(r);
    }

    let payload = json!({
        "privilege": privilege_mode(),
        "mode_message": privilege_mode_message(),
        "mode": "whyopen",
        "target_mode": mode,
        "target": target,
        "partial": partial,
        "skipped": skipped,
        "results": rows,
    });

    println!(
        "{}",
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
    );
}
