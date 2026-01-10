use std::io::{self, Write};

const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

pub fn warn(message: &str) {
    let mut stderr = io::stderr();
    let _ = writeln!(stderr, "{ANSI_YELLOW}Warning:{ANSI_RESET} {message}");
}

pub fn error(message: &str) {
    let mut stderr = io::stderr();
    let _ = writeln!(stderr, "{ANSI_RED}Error:{ANSI_RESET} {message}");
}
