use clap::Parser;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cliutil::{error, warn};

enum AppError {
    InvalidInput(String),
    #[allow(dead_code)]
    Fatal(String),
}

#[derive(Parser, Debug)]
#[command(name = "envpath")]
struct Args {
    command: String,
}

fn is_executable(path: &Path) -> bool {
    let md = match fs::metadata(path) {
        Ok(md) => md,
        Err(_) => return false,
    };

    if !md.is_file() {
        return false;
    }

    (md.permissions().mode() & 0o111) != 0
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

    if args.command.contains('/') {
        return Err(AppError::InvalidInput(
            "command must be a bare name (no path separators)".to_string(),
        ));
    }

    let path_var = env::var_os("PATH").unwrap_or_default();
    let path_str = path_var.to_string_lossy();

    let mut path_entries: Vec<PathBuf> = Vec::new();
    for part in path_str.split(':') {
        if part.is_empty() {
            continue;
        }
        path_entries.push(PathBuf::from(part));
    }

    if path_entries.is_empty() {
        warn("PATH is empty");
    }

    let mut resolved: Option<PathBuf> = None;
    let mut selected_index: Option<usize> = None;

    for (idx, dir) in path_entries.iter().enumerate() {
        let candidate = dir.join(&args.command);
        if is_executable(&candidate) {
            resolved = Some(candidate);
            selected_index = Some(idx);
            break;
        }
    }

    println!("Command: {}", args.command);
    println!();
    println!("Resolved to:");
    match &resolved {
        Some(p) => println!("{}", p.display()),
        None => println!("<not found>"),
    }
    println!();
    println!("PATH order:");

    for (idx, dir) in path_entries.iter().enumerate() {
        let n = idx + 1;
        if Some(idx) == selected_index {
            println!("{n}. {}   ← selected", dir.display());
        } else {
            println!("{n}. {}", dir.display());
        }
    }

    if resolved.is_none() {
        return Err(AppError::InvalidInput(
            "command not found in PATH".to_string(),
        ));
    }

    Ok(())
}
