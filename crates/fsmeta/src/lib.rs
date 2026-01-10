use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FileId {
    pub dev: u64,
    pub inode: u64,
}

pub fn file_id_for_path(path: &Path) -> io::Result<FileId> {
    let md = fs::metadata(path)?;
    Ok(file_id_for_metadata(&md))
}

pub fn file_id_for_metadata(md: &fs::Metadata) -> FileId {
    FileId {
        dev: md.dev(),
        inode: md.ino(),
    }
}

pub fn dev_major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32);
    let minor = (dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0000_fff0_0000) >> 12);
    (major as u32, minor as u32)
}

pub fn format_duration_ago(d: Duration) -> String {
    let secs = d.as_secs();

    if secs < 60 {
        return format!("{}s ago", secs);
    }

    if secs < 60 * 60 {
        return format!("{}m ago", secs / 60);
    }

    if secs < 60 * 60 * 24 {
        return format!("{}h ago", secs / (60 * 60));
    }

    format!("{}d ago", secs / (60 * 60 * 24))
}

pub fn format_systemtime_ago(t: SystemTime) -> String {
    let now = SystemTime::now();
    let d = now.duration_since(t).unwrap_or(Duration::from_secs(0));
    format_duration_ago(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration_ago(Duration::from_secs(5)), "5s ago");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration_ago(Duration::from_secs(60)), "1m ago");
        assert_eq!(format_duration_ago(Duration::from_secs(119)), "1m ago");
        assert_eq!(format_duration_ago(Duration::from_secs(120)), "2m ago");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration_ago(Duration::from_secs(3600)), "1h ago");
        assert_eq!(format_duration_ago(Duration::from_secs(7200)), "2h ago");
    }

    #[test]
    fn format_duration_days() {
        assert_eq!(format_duration_ago(Duration::from_secs(86400)), "1d ago");
    }

    #[test]
    fn dev_major_minor_smoke() {
        let (_maj, _min) = dev_major_minor(0);
    }
}
