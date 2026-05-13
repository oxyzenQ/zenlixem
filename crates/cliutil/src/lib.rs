use std::io::{self, IsTerminal, Write};

use serde::Serialize;

/// Common error type for CLI tools.
///
/// `InvalidInput` exits code 1; `Fatal` exits code 2.
#[derive(Debug)]
pub enum AppError {
    InvalidInput(String),
    Fatal(String),
}

/// JSON error payload used by `print_json_error`.
#[derive(Serialize)]
pub struct JsonError {
    pub kind: &'static str,
    pub error: String,
}

/// Print a JSON-formatted error to stdout.
///
/// Used when `--json` was requested and an error must be reported
/// in machine-readable form instead of human-readable stderr.
pub fn print_json_error(err: AppError) {
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

fn effective_uid() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut it = rest.split_whitespace();
        let _real = it.next();
        let effective = it.next()?;
        return effective.parse::<u32>().ok();
    }
    None
}

const ANSI_DIM: &str = "\x1b[2m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

const SUITE_NAME: &str = "zenlixem";

pub fn warn(message: &str) {
    let mut stderr = io::stderr();
    if stderr.is_terminal() {
        let _ = writeln!(stderr, "{ANSI_YELLOW}Warning:{ANSI_RESET} {message}");
    } else {
        let _ = writeln!(stderr, "Warning: {message}");
    }
}

pub fn error(message: &str) {
    let mut stderr = io::stderr();
    if stderr.is_terminal() {
        let _ = writeln!(stderr, "{ANSI_RED}Error:{ANSI_RESET} {message}");
    } else {
        let _ = writeln!(stderr, "Error: {message}");
    }
}

pub fn print_header(message: &str) {
    let mut stdout = io::stdout();
    if stdout.is_terminal() {
        let _ = writeln!(stdout, "{ANSI_DIM}{message}{ANSI_RESET}");
    } else {
        let _ = writeln!(stdout, "{message}");
    }
}

pub fn build_target() -> &'static str {
    option_env!("ZENLIXEM_BUILD_TARGET").unwrap_or("unknown")
}

pub fn git_sha() -> &'static str {
    option_env!("ZENLIXEM_GIT_SHA").unwrap_or("unknown")
}

pub fn privilege_mode() -> &'static str {
    match effective_uid() {
        Some(0) => "privileged",
        _ => "unprivileged",
    }
}

pub fn privilege_mode_message() -> &'static str {
    if privilege_mode() == "privileged" {
        "Mode: privileged (full scan)"
    } else {
        "Mode: unprivileged (partial results expected)"
    }
}

pub fn short_sha(sha: &str) -> &str {
    sha.get(0..7).unwrap_or(sha)
}

pub fn print_version() {
    println!("{SUITE_NAME} v{}", env!("CARGO_PKG_VERSION"));
}

pub fn print_info() {
    println!("{SUITE_NAME} v{}", env!("CARGO_PKG_VERSION"));
    println!("Build: {} ({})", build_target(), short_sha(git_sha()));
    println!("Author: {}", env!("CARGO_PKG_AUTHORS"));
    println!("License: {}", env!("CARGO_PKG_LICENSE"));
    println!("Source: {}", env!("CARGO_PKG_REPOSITORY"));
}
