use std::io::{self, IsTerminal, Write};

const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

const SUITE_NAME: &str = "Zenlixem";

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

fn build_target() -> &'static str {
    option_env!("ZENLIXEM_BUILD_TARGET").unwrap_or("unknown")
}

fn git_sha() -> &'static str {
    option_env!("ZENLIXEM_GIT_SHA").unwrap_or("unknown")
}

fn short_sha(sha: &str) -> &str {
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
