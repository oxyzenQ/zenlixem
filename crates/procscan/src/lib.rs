use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ProcAccess<T> {
    Ok(T),
    PermissionDenied,
    Gone,
    Fatal(io::Error),
}

fn classify_proc_io_error<T>(e: io::Error) -> ProcAccess<T> {
    match e.kind() {
        io::ErrorKind::NotFound => ProcAccess::Gone,
        io::ErrorKind::PermissionDenied => ProcAccess::PermissionDenied,
        _ => ProcAccess::Fatal(e),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcMapEntry {
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub pathname: Option<String>,
}

pub fn list_pids() -> io::Result<Vec<i32>> {
    let mut pids = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let s = file_name.to_string_lossy();
        if let Ok(pid) = s.parse::<i32>() {
            pids.push(pid);
        }
    }

    pids.sort_unstable();
    Ok(pids)
}

pub fn read_comm(pid: i32) -> io::Result<String> {
    let path = format!("/proc/{pid}/comm");
    let contents = fs::read_to_string(path)?;
    Ok(contents.trim_end_matches(['\n', '\r']).to_string())
}

pub fn read_comm_access(pid: i32) -> ProcAccess<String> {
    let path = format!("/proc/{pid}/comm");
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return classify_proc_io_error(e),
    };
    ProcAccess::Ok(contents.trim_end_matches(['\n', '\r']).to_string())
}

pub fn fd_dir(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/fd"))
}

pub fn read_fd_links(pid: i32) -> io::Result<Vec<(i32, PathBuf, String)>> {
    let dir = fd_dir(pid);
    let mut out = Vec::new();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let fd_str = name.to_string_lossy();
        let Ok(fd) = fd_str.parse::<i32>() else {
            continue;
        };

        let fd_path = entry.path();
        match fs::read_link(&fd_path) {
            Ok(target) => out.push((fd, fd_path, target.to_string_lossy().to_string())),
            Err(_) => out.push((fd, fd_path, String::new())),
        }
    }

    out.sort_by_key(|(fd, _, _)| *fd);
    Ok(out)
}

pub fn read_fd_links_access(pid: i32) -> ProcAccess<Vec<(i32, PathBuf, String)>> {
    let dir = fd_dir(pid);
    let mut out = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => return classify_proc_io_error(e),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let fd_str = name.to_string_lossy();
        let Ok(fd) = fd_str.parse::<i32>() else {
            continue;
        };

        let fd_path = entry.path();
        match fs::read_link(&fd_path) {
            Ok(target) => out.push((fd, fd_path, target.to_string_lossy().to_string())),
            Err(_) => out.push((fd, fd_path, String::new())),
        }
    }

    out.sort_by_key(|(fd, _, _)| *fd);
    ProcAccess::Ok(out)
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    u16::from_str_radix(s, 16).ok()
}

fn parse_hex_u8(s: &str) -> Option<u8> {
    u8::from_str_radix(s, 16).ok()
}

pub fn parse_dev_hex(dev: &str) -> Option<(u32, u32)> {
    let mut it = dev.split(':');
    let major = parse_hex_u32(it.next()?)?;
    let minor = parse_hex_u32(it.next()?)?;
    Some((major, minor))
}

pub fn read_proc_maps(pid: i32) -> io::Result<Vec<ProcMapEntry>> {
    let path = format!("/proc/{pid}/maps");
    let f = fs::File::open(path)?;
    let reader = io::BufReader::new(f);

    let mut out = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace();

        let _addr = parts.next();
        let _perms = parts.next();
        let _offset = parts.next();
        let dev = parts.next();
        let inode = parts.next();

        let (Some(dev), Some(inode)) = (dev, inode) else {
            continue;
        };

        let Some((dev_major, dev_minor)) = parse_dev_hex(dev) else {
            continue;
        };

        let Ok(inode) = inode.parse::<u64>() else {
            continue;
        };

        let pathname = parts.next().map(|s| s.to_string());

        out.push(ProcMapEntry {
            dev_major,
            dev_minor,
            inode,
            pathname,
        });
    }

    Ok(out)
}

pub fn read_proc_maps_access(pid: i32) -> ProcAccess<Vec<ProcMapEntry>> {
    let path = format!("/proc/{pid}/maps");
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return classify_proc_io_error(e),
    };
    let reader = io::BufReader::new(f);

    let mut out = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => return classify_proc_io_error(e),
        };
        let mut parts = line.split_whitespace();

        let _addr = parts.next();
        let _perms = parts.next();
        let _offset = parts.next();
        let dev = parts.next();
        let inode = parts.next();

        let (Some(dev), Some(inode)) = (dev, inode) else {
            continue;
        };

        let Some((dev_major, dev_minor)) = parse_dev_hex(dev) else {
            continue;
        };

        let Ok(inode) = inode.parse::<u64>() else {
            continue;
        };

        let pathname = parts.next().map(|s| s.to_string());

        out.push(ProcMapEntry {
            dev_major,
            dev_minor,
            inode,
            pathname,
        });
    }

    ProcAccess::Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcNetProto {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcNetSocketEntry {
    pub proto: ProcNetProto,
    pub local_port: u16,
    pub inode: u64,
    pub state: u8,
}

fn parse_proc_net_file(path: &Path, proto: ProcNetProto) -> io::Result<Vec<ProcNetSocketEntry>> {
    let f = fs::File::open(path)?;
    let reader = io::BufReader::new(f);

    let mut out = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if idx == 0 {
            continue;
        }

        let mut it = line.split_whitespace();
        let _sl = it.next();
        let Some(local_address) = it.next() else {
            continue;
        };
        let _rem_address = it.next();
        let Some(state_hex) = it.next() else {
            continue;
        };

        let mut ok = true;
        for _ in 0..5 {
            if it.next().is_none() {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        let Some(inode_field) = it.next() else {
            continue;
        };

        let Some((_addr_hex, port_hex)) = local_address.split_once(':') else {
            continue;
        };

        let Some(local_port) = parse_hex_u16(port_hex) else {
            continue;
        };

        let Some(state) = parse_hex_u8(state_hex) else {
            continue;
        };

        let Ok(inode) = inode_field.parse::<u64>() else {
            continue;
        };

        out.push(ProcNetSocketEntry {
            proto,
            local_port,
            inode,
            state,
        });
    }

    Ok(out)
}

pub fn read_proc_net_sockets() -> io::Result<Vec<ProcNetSocketEntry>> {
    let mut out = Vec::new();

    if let Ok(v) = parse_proc_net_file(Path::new("/proc/net/tcp"), ProcNetProto::Tcp) {
        out.extend(v);
    }
    if let Ok(v) = parse_proc_net_file(Path::new("/proc/net/tcp6"), ProcNetProto::Tcp6) {
        out.extend(v);
    }
    if let Ok(v) = parse_proc_net_file(Path::new("/proc/net/udp"), ProcNetProto::Udp) {
        out.extend(v);
    }
    if let Ok(v) = parse_proc_net_file(Path::new("/proc/net/udp6"), ProcNetProto::Udp6) {
        out.extend(v);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dev_hex_ok() {
        assert_eq!(parse_dev_hex("08:01"), Some((8, 1)));
    }

    #[test]
    fn parse_dev_hex_bad() {
        assert_eq!(parse_dev_hex("zz:01"), None);
    }

    #[test]
    fn access_gone_on_nonexistent_pid() {
        match read_comm_access(-1) {
            ProcAccess::Gone => {}
            other => panic!("unexpected result: {other:?}"),
        }
        match read_fd_links_access(-1) {
            ProcAccess::Gone => {}
            other => panic!("unexpected result: {other:?}"),
        }
        match read_proc_maps_access(-1) {
            ProcAccess::Gone => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn parse_proc_net_file_reads_state_and_inode() {
        let path = std::env::temp_dir().join(format!(
            "zenlixem_proc_net_test_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let contents = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 46743 2 0000000000000000 100 0 0 10 0\n";
        fs::write(&path, contents).unwrap();

        let v = parse_proc_net_file(&path, ProcNetProto::Tcp).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].local_port, 53);
        assert_eq!(v[0].inode, 46743);
        assert_eq!(v[0].state, 0x0A);

        let _ = fs::remove_file(&path);
    }
}
