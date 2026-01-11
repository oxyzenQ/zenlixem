use clap::{error::ErrorKind, Parser};
use serde::Serialize;
use serde_json::json;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cliutil::{
    error, print_header, print_info, print_version, privilege_mode, privilege_mode_message, warn,
};

enum AppError {
    InvalidInput(String),
    #[allow(dead_code)]
    Fatal(String),
}

#[derive(Serialize)]
struct JsonError {
    kind: &'static str,
    error: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "envpath",
    disable_version_flag = true,
    about = "Explain PATH resolution for a command",
    long_about = "envpath shows which PATH entry selected the resolved executable for a bare command name.\n\nCOMMAND must be a bare command name (no '/' characters).",
    after_help = r#"EXAMPLES:
  envpath gcc
  envpath --json gcc
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

    #[arg(
        value_name = "COMMAND",
        required_unless_present_any = ["version", "info"],
        help = "Command name to resolve using $PATH"
    )]
    command: Option<String>,
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

    let command = args
        .command
        .ok_or_else(|| AppError::InvalidInput("missing command".to_string()))?;

    if command.contains('/') {
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
        let candidate = dir.join(&command);
        if is_executable(&candidate) {
            resolved = Some(candidate);
            selected_index = Some(idx);
            break;
        }
    }

    if resolved.is_none() {
        return Err(AppError::InvalidInput(
            "command not found in PATH".to_string(),
        ));
    }

    if args.json {
        let mut order: Vec<serde_json::Value> = Vec::new();
        for (idx, dir) in path_entries.iter().enumerate() {
            order.push(json!({
                "index": idx + 1,
                "dir": dir.display().to_string(),
                "selected": Some(idx) == selected_index,
            }));
        }

        let payload = json!({
            "privilege": privilege_mode(),
            "mode_message": privilege_mode_message(),
            "mode": "envpath",
            "command": command,
            "partial": false,
            "skipped": 0,
            "results": {
                "resolved": resolved.as_ref().map(|p| p.display().to_string()),
                "path_order": order,
            }
        });

        println!(
            "{}",
            serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
        );
        return Ok(());
    }

    println!("{}", privilege_mode_message());
    println!("Command: {}", command);
    println!();
    print_header("Resolved to:");
    match &resolved {
        Some(p) => println!("{}", p.display()),
        None => println!("<not found>"),
    }
    println!();
    print_header("PATH order:");

    for (idx, dir) in path_entries.iter().enumerate() {
        let n = idx + 1;
        if Some(idx) == selected_index {
            println!("{n}. {}   <- selected", dir.display());
        } else {
            println!("{n}. {}", dir.display());
        }
    }

    Ok(())
}
