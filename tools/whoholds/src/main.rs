use clap::Parser;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use cliutil::{error, print_info, print_version};
use fsmeta::{dev_major_minor, file_id_for_metadata, file_id_for_path, FileId};
use procscan::{
    list_pids, read_comm_access, read_fd_links_access, read_proc_maps_access,
    read_proc_net_sockets, ProcAccess, ProcNetProto,
};

#[derive(Parser, Debug)]
#[command(name = "whoholds", disable_version_flag = true)]
struct Args {
    #[arg(short = 'v', long = "version")]
    version: bool,

    #[arg(short = 'i', long = "info")]
    info: bool,

    #[arg(long = "ports")]
    ports: bool,

    #[arg(long = "listening", requires = "ports", conflicts_with = "established")]
    listening: bool,

    #[arg(long = "established", requires = "ports", conflicts_with = "listening")]
    established: bool,

    #[arg(required_unless_present_any = ["version", "info", "ports"])]
    target: Option<String>,
}

enum AppError {
    InvalidInput(String),
    Fatal(String),
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
    match run() {
        Ok(()) => {}
        Err(AppError::InvalidInput(e)) => {
            error(&e);
            std::process::exit(1);
        }
        Err(AppError::Fatal(e)) => {
            error(&e);
            std::process::exit(2);
        }
    }
}

fn run() -> Result<(), AppError> {
    let args = Args::try_parse().map_err(|e| AppError::InvalidInput(e.to_string()))?;

    if args.version {
        print_version();
        return Ok(());
    }

    if args.info {
        print_info();
        return Ok(());
    }

    if args.ports {
        return whoholds_ports(args.listening, args.established);
    }

    let target = args
        .target
        .ok_or_else(|| AppError::InvalidInput("missing target".to_string()))?;

    if let Ok(port) = target.parse::<u16>() {
        return whoholds_port(port);
    }

    let path = PathBuf::from(&target);
    whoholds_path(&path)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PortRow {
    port: u16,
    proto: &'static str,
    proto_sort: u8,
    pid: i32,
    command: String,
    state: String,
}

fn whoholds_ports(listening: bool, established: bool) -> Result<(), AppError> {
    let mut sockets = read_proc_net_sockets().map_err(|e| AppError::Fatal(e.to_string()))?;

    sockets.retain(|s| {
        if listening {
            if matches!(s.proto, ProcNetProto::Tcp | ProcNetProto::Tcp6) {
                return s.state == 0x0A;
            }
            if matches!(s.proto, ProcNetProto::Udp | ProcNetProto::Udp6) {
                return s.state == 0x07;
            }
            return false;
        }
        if established {
            return matches!(s.proto, ProcNetProto::Tcp | ProcNetProto::Tcp6) && s.state == 0x01;
        }
        true
    });

    let target_inodes: HashSet<u64> = sockets.iter().map(|s| s.inode).collect();

    let mut inode_to_pids: BTreeMap<u64, Vec<i32>> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    if target_inodes.is_empty() {
        print_ports(Vec::new(), skipped_permission_denied.len());
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

        for (_fd, _fd_path, link) in links {
            let Some(inode) = parse_socket_inode(&link) else {
                continue;
            };
            if !target_inodes.contains(&inode) {
                continue;
            }
            inode_to_pids.entry(inode).or_default().push(pid);
        }
    }

    for pids in inode_to_pids.values_mut() {
        pids.sort_unstable();
        pids.dedup();
    }

    let mut comm_cache: HashMap<i32, String> = HashMap::new();
    let mut rows: Vec<PortRow> = Vec::new();

    for s in sockets {
        let Some(pids) = inode_to_pids.get(&s.inode) else {
            continue;
        };

        for pid in pids {
            let command = comm_cache
                .entry(*pid)
                .or_insert_with(|| match read_comm_access(*pid) {
                    ProcAccess::Ok(s) => s,
                    ProcAccess::PermissionDenied | ProcAccess::Gone | ProcAccess::Fatal(_) => {
                        "<unknown>".to_string()
                    }
                })
                .clone();

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

    rows.sort_by(|a, b| (a.port, a.proto_sort, a.pid).cmp(&(b.port, b.proto_sort, b.pid)));
    rows.dedup_by(|a, b| {
        a.port == b.port && a.proto_sort == b.proto_sort && a.pid == b.pid && a.state == b.state
    });

    print_ports(rows, skipped_permission_denied.len());
    Ok(())
}

fn proto_label_and_sort(proto: ProcNetProto) -> (&'static str, u8) {
    match proto {
        ProcNetProto::Tcp | ProcNetProto::Tcp6 => ("tcp", 0),
        ProcNetProto::Udp | ProcNetProto::Udp6 => ("udp", 1),
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

fn whoholds_path(path: &Path) -> Result<(), AppError> {
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

    let mut holders: BTreeMap<i32, Reason> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    for pid in pids {
        let mut open_fd_denied = false;
        match scan_pid_open_fd_file(pid, target_id) {
            ProcAccess::Ok(true) => {
                holders.insert(pid, Reason::OpenFd);
                continue;
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                open_fd_denied = true;
            }
            ProcAccess::Gone => {
                continue;
            }
            ProcAccess::Fatal(e) => {
                return Err(AppError::Fatal(e.to_string()));
            }
        }

        let mut maps_denied = false;
        match scan_pid_mmap_file(pid, tmaj, tmin, target_id.inode) {
            ProcAccess::Ok(true) => {
                holders.insert(pid, Reason::Mmap);
            }
            ProcAccess::Ok(false) => {}
            ProcAccess::PermissionDenied => {
                maps_denied = true;
            }
            ProcAccess::Gone => {
                continue;
            }
            ProcAccess::Fatal(e) => {
                return Err(AppError::Fatal(e.to_string()));
            }
        }

        if open_fd_denied && maps_denied {
            skipped_permission_denied.insert(pid);
        }
    }

    print_holders(holders, skipped_permission_denied.len());
    Ok(())
}

fn whoholds_port(port: u16) -> Result<(), AppError> {
    let sockets = read_proc_net_sockets().map_err(|e| AppError::Fatal(e.to_string()))?;

    let target_inodes: HashSet<u64> = sockets
        .into_iter()
        .filter(|s| s.local_port == port)
        .map(|s| s.inode)
        .collect();

    let mut holders: BTreeMap<i32, Reason> = BTreeMap::new();
    let mut skipped_permission_denied: HashSet<i32> = HashSet::new();

    if target_inodes.is_empty() {
        print_holders(holders, skipped_permission_denied.len());
        return Ok(());
    }

    let pids = list_pids().map_err(|e| AppError::Fatal(e.to_string()))?;

    for pid in pids {
        match scan_pid_open_fd_socket(pid, &target_inodes) {
            ProcAccess::Ok(true) => {
                holders.insert(pid, Reason::OpenFd);
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

    print_holders(holders, skipped_permission_denied.len());
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

fn scan_pid_open_fd_socket(pid: i32, inodes: &HashSet<u64>) -> ProcAccess<bool> {
    let links = match read_fd_links_access(pid) {
        ProcAccess::Ok(v) => v,
        ProcAccess::PermissionDenied => return ProcAccess::PermissionDenied,
        ProcAccess::Gone => return ProcAccess::Gone,
        ProcAccess::Fatal(e) => return ProcAccess::Fatal(e),
    };

    for (_fd, _fd_path, link) in links {
        let Some(inode) = parse_socket_inode(&link) else {
            continue;
        };

        if inodes.contains(&inode) {
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

fn print_ports(rows: Vec<PortRow>, skipped_permission_denied: usize) {
    if skipped_permission_denied > 0 {
        println!(
            "Partial result: {skipped_permission_denied} processes skipped (permission denied)"
        );
    }

    if rows.is_empty() {
        println!("No active holders detected.");
        return;
    }

    println!("PORT  PROTO PID   COMMAND     STATE");
    for r in rows {
        println!(
            "{:<5} {:<5} {:<5} {:<11} {}",
            r.port, r.proto, r.pid, r.command, r.state
        );
    }
}

fn print_holders(holders: BTreeMap<i32, Reason>, skipped_permission_denied: usize) {
    if skipped_permission_denied > 0 {
        println!(
            "Partial result: {skipped_permission_denied} processes skipped (permission denied)"
        );
    }

    if holders.is_empty() {
        println!("No active holders detected.");
        return;
    }

    println!("Held by:");
    println!("PID   COMMAND     REASON");

    for (pid, reason) in holders {
        let comm = match read_comm_access(pid) {
            ProcAccess::Ok(s) => s,
            ProcAccess::PermissionDenied | ProcAccess::Gone | ProcAccess::Fatal(_) => {
                "<unknown>".to_string()
            }
        };
        println!("{pid:<5} {comm:<11} {}", reason.as_str());
    }
}
