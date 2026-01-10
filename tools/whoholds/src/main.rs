use clap::Parser;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cliutil::{error, warn};
use fsmeta::{dev_major_minor, file_id_for_metadata, file_id_for_path, FileId};
use procscan::{list_pids, read_comm, read_fd_links, read_proc_maps, read_proc_net_sockets};

#[derive(Parser, Debug)]
#[command(name = "whoholds")]
struct Args {
    target: String,
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
    if let Err(e) = run() {
        error(&e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();

    if let Ok(port) = args.target.parse::<u16>() {
        return whoholds_port(port);
    }

    let path = PathBuf::from(&args.target);
    whoholds_path(&path)
}

fn whoholds_path(path: &Path) -> Result<(), String> {
    let target_id = file_id_for_path(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let (tmaj, tmin) = dev_major_minor(target_id.dev);

    let mut holders: BTreeMap<i32, BTreeSet<Reason>> = BTreeMap::new();

    let pids = list_pids().map_err(|e| e.to_string())?;

    for pid in pids {
        match scan_pid_open_fd_file(pid, target_id) {
            Ok(true) => {
                holders.entry(pid).or_default().insert(Reason::OpenFd);
            }
            Ok(false) => {}
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    warn(&format!("PID {pid}: permission denied"));
                }
            }
        }

        match scan_pid_mmap_file(pid, tmaj, tmin, target_id.inode) {
            Ok(true) => {
                holders.entry(pid).or_default().insert(Reason::Mmap);
            }
            Ok(false) => {}
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    warn(&format!("PID {pid}: permission denied"));
                }
            }
        }
    }

    print_holders(holders);
    Ok(())
}

fn whoholds_port(port: u16) -> Result<(), String> {
    let sockets = read_proc_net_sockets().map_err(|e| e.to_string())?;

    let target_inodes: HashSet<u64> = sockets
        .into_iter()
        .filter(|s| s.local_port == port)
        .map(|s| s.inode)
        .collect();

    let mut holders: BTreeMap<i32, BTreeSet<Reason>> = BTreeMap::new();

    if target_inodes.is_empty() {
        print_holders(holders);
        return Ok(());
    }

    let pids = list_pids().map_err(|e| e.to_string())?;

    for pid in pids {
        match scan_pid_open_fd_socket(pid, &target_inodes) {
            Ok(true) => {
                holders.entry(pid).or_default().insert(Reason::OpenFd);
            }
            Ok(false) => {}
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    warn(&format!("PID {pid}: permission denied"));
                }
            }
        }
    }

    print_holders(holders);
    Ok(())
}

fn scan_pid_open_fd_file(pid: i32, target: FileId) -> io::Result<bool> {
    let links = read_fd_links(pid)?;

    for (_fd, fd_path, _link) in links {
        let md = match fs::metadata(&fd_path) {
            Ok(md) => md,
            Err(_) => continue,
        };

        if file_id_for_metadata(&md) == target {
            return Ok(true);
        }
    }

    Ok(false)
}

fn scan_pid_mmap_file(
    pid: i32,
    target_major: u32,
    target_minor: u32,
    target_inode: u64,
) -> io::Result<bool> {
    let maps = read_proc_maps(pid)?;

    for entry in maps {
        if entry.inode == 0 {
            continue;
        }

        if entry.inode == target_inode
            && entry.dev_major == target_major
            && entry.dev_minor == target_minor
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn scan_pid_open_fd_socket(pid: i32, inodes: &HashSet<u64>) -> io::Result<bool> {
    let links = read_fd_links(pid)?;

    for (_fd, _fd_path, link) in links {
        let Some(inode) = parse_socket_inode(&link) else {
            continue;
        };

        if inodes.contains(&inode) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn parse_socket_inode(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("socket:[")?;
    let rest = rest.strip_suffix(']')?;
    rest.parse::<u64>().ok()
}

fn print_holders(holders: BTreeMap<i32, BTreeSet<Reason>>) {
    if holders.is_empty() {
        println!("No active holders detected.");
        return;
    }

    println!("Held by:");
    println!("PID   COMMAND     REASON");

    for (pid, reasons) in holders {
        let comm = read_comm(pid).unwrap_or_else(|_| "<unknown>".to_string());
        let reason_str = reasons
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        println!("{pid:<5} {comm:<11} {reason_str}");
    }
}
