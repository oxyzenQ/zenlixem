use clap::{error::ErrorKind, Parser};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use cliutil::{
    error, print_header, print_info, print_json_error, print_json_payload, print_version,
    privilege_mode, privilege_mode_message, AppError,
};
use fsmeta::{dev_major_minor, file_id_for_path};
use procscan::{
    list_pids, parse_socket_inode, proto_label_and_sort, read_comm_access, read_comm_best_effort,
    read_fd_links_access, read_proc_net_sockets, scan_pid_mmap_file, scan_pid_open_fd_file,
    scan_pid_open_fd_socket, socket_state_label, ProcAccess, ProcNetProto, TCP_ESTABLISHED,
    TCP_LISTEN, UDP_LISTEN,
};

const COMMAND_COL_WIDTH: usize = 16;

#[derive(Parser, Debug)]
#[command(
    name = "whoholds",
    disable_version_flag = true,
    about = "Show which processes hold a path or port",
    long_about = "whoholds inspects procfs to report which processes hold a file/device path or a TCP/UDP port.\n\nWhen procfs access is restricted, results may be partial.",
    after_help = r#"EXAMPLES:
  whoholds /mnt/data
  whoholds 8080
  whoholds --ports --listening
  whoholds --json 8080
"#
)]
struct Args {
    #[arg(short = 'v', long = "version", help = "Print version information")]
    version: bool,

    #[arg(
        short = 'i',
        long = "info",
        help = "Show build and version information"
    )]
    info: bool,

    #[arg(
        long = "json",
        conflicts_with_all = ["version", "info"],
        help = "Output result as JSON"
    )]
    json: bool,

    #[arg(long = "ports", help = "Scan all ports")]
    ports: bool,

    #[arg(
        long = "listening",
        requires = "ports",
        conflicts_with = "established",
        help = "Filter to listening sockets (used with --ports)"
    )]
    listening: bool,

    #[arg(
        long = "established",
        requires = "ports",
        conflicts_with = "listening",
        help = "Filter to established TCP sockets (used with --ports)"
    )]
    established: bool,

    #[arg(
        value_name = "TARGET",
        required_unless_present_any = ["version", "info", "ports"],
        help = "File path or port number to inspect"
    )]
    target: Option<String>,
}

fn print_json_ports(
    rows: Vec<PortRow>,
    skipped_permission_denied: usize,
    listening: bool,
    established: bool,
) {
    let partial = skipped_permission_denied > 0;
    let payload = json!({
        "privilege": privilege_mode(),
        "mode_message": privilege_mode_message(),
        "mode": "ports",
        "listening": listening,
        "established": established,
        "partial": partial,
        "skipped": skipped_permission_denied,
        "results": rows,
    });
    print_json_payload(&payload);
}

fn print_json_holders(
    mode: &'static str,
    target: String,
    holders: BTreeMap<i32, (Vec<Reason>, String)>,
    skipped_permission_denied: usize,
) {
    let partial = skipped_permission_denied > 0;
    let mut rows: Vec<HolderRow> = Vec::new();

    for (pid, (reasons, comm)) in holders {
        let reason_str = reasons
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        rows.push(HolderRow {
            pid,
            command: comm,
            reason: reason_str,
        });
    }

    let payload = json!({
        "privilege": privilege_mode(),
        "mode_message": privilege_mode_message(),
        "mode": mode,
        "target": target,
        "partial": partial,
        "skipped": skipped_permission_denied,
        "results": rows,
    });
    print_json_payload(&payload);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Reason {
    OpenFd,
    Mmap,
}

impl Reason {
    fn as_str(&self) -> &'static str {
        match self {
            Reason::OpenFd => "open fd",
            Reason::Mmap => "mmap",
        }
    }
}

fn main() {
    let json_requested = std::env::args().any(|a| a == "--json");

    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let _ = e.print();
                std::process::exit(0);
            }
            if json_requested {
                print_json_error(AppError::InvalidInput(e.to_string()));
            } else {
                let _ = e.print();
            }
            std::process::exit(1);
        }
    };

    match run(args) {
        Ok(()) => {}
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

fn run(args: Args) -> Result<(), AppError> {
    if args.version {
        print_version();
        return Ok(());
    }

    if args.info {
        print_info();
        return Ok(());
    }

    if args.ports {
        return whoholds_ports(args.listening, args.established, args.json);
    }

    let target = args
        .target
        .ok_or_else(|| AppError::InvalidInput("missing target".to_string()))?;

    if let Ok(port) = target.parse::<u16>() {
        return whoholds_port(port, args.json);
    }

    let path = PathBuf::from(&target);
    whoholds_path(&path, args.json)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PortRow {
    port: u16,
    proto: &'static str,
    #[serde(skip_serializing)]
    proto_sort: u8,
    pid: i32,
    command: String,
    state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct HolderRow {
    pid: i32,
    command: String,
    reason: String,
}

fn whoholds_ports(listening: bool, established: bool, json_out: bool) -> Result<(), AppError> {
    let mut sockets = read_proc_net_sockets().map_err(|e| AppError::Fatal(e.to_string()))?;

    sockets.retain(|s| {
        if listening {
            if matches!(s.proto, ProcNetProto::Tcp | ProcNetProto::Tcp6) {
                return s.state == TCP_LISTEN;
            }
            if matches!(s.proto, ProcNetProto::Udp | ProcNetProto::Udp6) {
                return s.state == UDP_LISTEN;
            }
            return false;
        }
        if established {
            return matches!(s.proto, ProcNetProto::Tcp | ProcNetProto::Tcp6)
                && s.state == TCP_ESTABLISHED;
        }
        true
    });

    let target_inodes: HashSet<u64> = sockets.iter().map(|s| s.inode).collect();

    let mut inode_to_pids: BTreeMap<u64, Vec<i32>> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    if target_inodes.is_empty() {
        if json_out {
            print_json_ports(
                Vec::new(),
                skipped_permission_denied.len(),
                listening,
                established,
            );
        } else {
            print_ports(Vec::new(), skipped_permission_denied.len());
        }
        return Ok(());
    }

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    let mut comm_cache: HashMap<i32, String> = HashMap::new();

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

        for (_fd, _fd_path, link) in links {
            let Some(inode) = parse_socket_inode(&link) else {
                continue;
            };
            if !target_inodes.contains(&inode) {
                continue;
            }

            comm_cache
                .entry(pid)
                .or_insert_with(|| match read_comm_access(pid) {
                    ProcAccess::Ok(s) => s,
                    ProcAccess::PermissionDenied | ProcAccess::Gone | ProcAccess::Fatal(_) => {
                        "<unknown>".to_string()
                    }
                });
            inode_to_pids.entry(inode).or_default().push(pid);
        }
    }

    for pids in inode_to_pids.values_mut() {
        pids.sort_unstable();
        pids.dedup();
    }

    let mut rows: Vec<PortRow> = Vec::new();

    for s in sockets {
        let Some(pids) = inode_to_pids.get(&s.inode) else {
            continue;
        };

        for pid in pids {
            let command = comm_cache
                .get(pid)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());

            let (proto, proto_sort) = proto_label_and_sort(s.proto);

            rows.push(PortRow {
                port: s.local_port,
                proto,
                proto_sort,
                pid: *pid,
                command,
                state: socket_state_label(s.proto, s.state),
            });
        }
    }

    rows.sort_by_key(|a| (a.port, a.proto_sort, a.pid));
    rows.dedup_by(|a, b| {
        a.port == b.port && a.proto_sort == b.proto_sort && a.pid == b.pid && a.state == b.state
    });

    if json_out {
        print_json_ports(
            rows,
            skipped_permission_denied.len(),
            listening,
            established,
        );
    } else {
        print_ports(rows, skipped_permission_denied.len());
    }
    Ok(())
}

fn whoholds_path(path: &Path, json_out: bool) -> Result<(), AppError> {
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

    let mut holders: BTreeMap<i32, (Vec<Reason>, String)> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    for pid in pids {
        let mut reasons: Vec<Reason> = Vec::new();
        let mut any_denied = false;
        let mut comm: Option<String> = None;

        match scan_pid_open_fd_file(pid, target_id) {
            ProcAccess::Ok(true) => {
                reasons.push(Reason::OpenFd);
                comm = Some(read_comm_best_effort(pid));
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                any_denied = true;
            }
            ProcAccess::Gone => continue,
            ProcAccess::Fatal(e) => {
                return Err(AppError::Fatal(e.to_string()));
            }
        }

        match scan_pid_mmap_file(pid, tmaj, tmin, target_id.inode) {
            ProcAccess::Ok(true) => {
                reasons.push(Reason::Mmap);
                if comm.is_none() {
                    comm = Some(read_comm_best_effort(pid));
                }
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                any_denied = true;
            }
            ProcAccess::Gone => continue,
            ProcAccess::Fatal(e) => {
                return Err(AppError::Fatal(e.to_string()));
            }
        }

        if reasons.is_empty() {
            if any_denied {
                skipped_permission_denied.insert(pid);
            }
            continue;
        }

        let comm = comm.unwrap_or_else(|| "<unknown>".to_string());
        holders.insert(pid, (reasons, comm));
    }

    if json_out {
        print_json_holders(
            "path",
            path.display().to_string(),
            holders,
            skipped_permission_denied.len(),
        );
    } else {
        print_holders(holders, skipped_permission_denied.len());
    }
    Ok(())
}

fn whoholds_port(port: u16, json_out: bool) -> Result<(), AppError> {
    let sockets = read_proc_net_sockets().map_err(|e| AppError::Fatal(e.to_string()))?;

    let target_inodes: HashSet<u64> = sockets
        .into_iter()
        .filter(|s| s.local_port == port)
        .map(|s| s.inode)
        .collect();

    let mut holders: BTreeMap<i32, (Vec<Reason>, String)> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    if target_inodes.is_empty() {
        if json_out {
            print_json_holders(
                "port",
                port.to_string(),
                holders,
                skipped_permission_denied.len(),
            );
        } else {
            print_holders(holders, skipped_permission_denied.len());
        }
        return Ok(());
    }

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    for pid in pids {
        match scan_pid_open_fd_socket(pid, &target_inodes) {
            ProcAccess::Ok(true) => {
                let comm = read_comm_best_effort(pid);
                holders.insert(pid, (vec![Reason::OpenFd], comm));
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                skipped_permission_denied.insert(pid);
            }
            ProcAccess::Gone => {}
            ProcAccess::Fatal(e) => {
                return Err(AppError::Fatal(e.to_string()));
            }
        }
    }

    if json_out {
        print_json_holders(
            "port",
            port.to_string(),
            holders,
            skipped_permission_denied.len(),
        );
    } else {
        print_holders(holders, skipped_permission_denied.len());
    }
    Ok(())
}

fn print_ports(rows: Vec<PortRow>, skipped_permission_denied: usize) {
    println!("{}", privilege_mode_message());
    if skipped_permission_denied > 0 {
        println!(
            "Partial result: {skipped_permission_denied} processes skipped (permission denied)"
        );
    }

    if rows.is_empty() {
        println!("No active holders detected.");
        return;
    }

    print_header(&format!(
        "{:<5} {:<5} {:<5} {:<width$} {}",
        "PORT",
        "PROTO",
        "PID",
        "COMMAND",
        "STATE",
        width = COMMAND_COL_WIDTH
    ));
    for r in rows {
        println!(
            "{:<5} {:<5} {:<5} {:<width$} {}",
            r.port,
            r.proto,
            r.pid,
            r.command,
            r.state,
            width = COMMAND_COL_WIDTH
        );
    }
}

fn print_holders(holders: BTreeMap<i32, (Vec<Reason>, String)>, skipped_permission_denied: usize) {
    println!("{}", privilege_mode_message());
    if skipped_permission_denied > 0 {
        println!(
            "Partial result: {skipped_permission_denied} processes skipped (permission denied)"
        );
    }

    if holders.is_empty() {
        println!("No active holders detected.");
        return;
    }

    print_header("Held by:");
    print_header(&format!(
        "{:<5} {:<width$} {}",
        "PID",
        "COMMAND",
        "REASON",
        width = COMMAND_COL_WIDTH
    ));

    for (pid, (reasons, comm)) in holders {
        let reason_str = reasons
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{pid:<5} {comm:<width$} {reason_str}",
            width = COMMAND_COL_WIDTH
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_as_str() {
        assert_eq!(Reason::OpenFd.as_str(), "open fd");
        assert_eq!(Reason::Mmap.as_str(), "mmap");
    }

    #[test]
    fn reason_ordering() {
        assert!(Reason::Mmap > Reason::OpenFd);
    }

    #[test]
    fn holder_row_serializes_json() {
        let row = HolderRow {
            pid: 1234,
            command: "bash".to_string(),
            reason: "open fd".to_string(),
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["pid"], 1234);
        assert_eq!(json["command"], "bash");
        assert_eq!(json["reason"], "open fd");
    }

    #[test]
    fn port_row_serializes_json() {
        let row = PortRow {
            port: 8080,
            proto: "tcp",
            proto_sort: 0,
            pid: 42,
            command: "nginx".to_string(),
            state: "listening".to_string(),
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["port"], 8080);
        assert_eq!(json["proto"], "tcp");
        assert_eq!(json["pid"], 42);
        assert_eq!(json["command"], "nginx");
        assert_eq!(json["state"], "listening");
        // proto_sort should be skipped
        assert!(json.get("proto_sort").is_none());
    }

    #[test]
    fn target_parse_port() {
        assert!("8080".parse::<u16>().is_ok());
        assert!("0".parse::<u16>().is_ok());
        assert!("65535".parse::<u16>().is_ok());
        assert!("65536".parse::<u16>().is_err());
        assert!("-1".parse::<u16>().is_err());
        assert!("abc".parse::<u16>().is_err());
    }
}
