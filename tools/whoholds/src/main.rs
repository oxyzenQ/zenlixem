use clap::Parser;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use cliutil::error;
use fsmeta::{dev_major_minor, file_id_for_metadata, file_id_for_path, FileId};
use procscan::{
    list_pids, read_comm_access, read_fd_links_access, read_proc_maps_access,
    read_proc_net_sockets, ProcAccess,
};

#[derive(Parser, Debug)]
#[command(name = "whoholds")]
struct Args {
    target: String,
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

    if let Ok(port) = args.target.parse::<u16>() {
        return whoholds_port(port);
    }

    let path = PathBuf::from(&args.target);
    whoholds_path(&path)
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
