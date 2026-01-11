use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::process::Command;

use cliutil::{build_target, error, git_sha, print_header, print_info, print_version};
use procscan::{list_pids, read_proc_net_sockets, ProcAccess};

#[derive(Parser, Debug)]
#[command(name = "zenlixem", disable_version_flag = true)]
struct Args {
    #[arg(short = 'v', long = "version")]
    version: bool,

    #[arg(short = 'i', long = "info")]
    info: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Doctor(DoctorArgs),
}

#[derive(Parser, Debug)]
struct DoctorArgs {
    #[arg(long = "json")]
    json: bool,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Serialize)]
struct CheckResult {
    check: &'static str,
    status: CheckStatus,
    message: String,
}

fn main() {
    let json_requested = std::env::args().any(|a| a == "--json");

    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            if json_requested {
                print_json_error(AppError::InvalidInput(e.to_string()));
            } else {
                error(&e.to_string());
            }
            std::process::exit(1);
        }
    };

    match run(args) {
        Ok(code) => std::process::exit(code),
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

fn run(args: Args) -> Result<i32, AppError> {
    if args.version {
        print_version();
        return Ok(0);
    }

    if args.info {
        print_info();
        return Ok(0);
    }

    let Some(cmd) = args.command else {
        return Err(AppError::InvalidInput(
            "missing command (try: zenlixem doctor)".to_string(),
        ));
    };

    match cmd {
        Cmd::Doctor(d) => Ok(run_doctor(d.json)),
    }
}

fn run_doctor(json_out: bool) -> i32 {
    let checks = collect_checks();

    let mut ok = 0usize;
    let mut warn = 0usize;
    let mut fail = 0usize;

    for c in &checks {
        match c.status {
            CheckStatus::Ok => ok += 1,
            CheckStatus::Warn => warn += 1,
            CheckStatus::Fail => fail += 1,
        }
    }

    let exit_code = if fail > 0 {
        2
    } else if warn > 0 {
        1
    } else {
        0
    };

    if json_out {
        let payload = json!({
            "mode": "doctor",
            "build_target": build_target(),
            "git_sha": git_sha(),
            "summary": { "ok": ok, "warn": warn, "fail": fail },
            "results": checks,
        });
        println!(
            "{}",
            serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
        );
        return exit_code;
    }

    print_header("Doctor report:");
    print_header("STATUS  CHECK                 MESSAGE");

    for c in &checks {
        let status = match c.status {
            CheckStatus::Ok => "OK",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        };
        println!("{status:<6}  {:<20} {}", c.check, c.message);
    }

    println!();
    println!("Summary: ok={ok} warn={warn} fail={fail}");
    println!("Build: {} ({})", build_target(), short_sha(git_sha()));

    exit_code
}

fn short_sha(sha: &str) -> &str {
    sha.get(0..7).unwrap_or(sha)
}

fn collect_checks() -> Vec<CheckResult> {
    vec![
        check_os(),
        check_procfs(),
        check_list_pids(),
        check_proc_access_smoke(),
        check_proc_net(),
        check_audit_log(),
        check_journalctl(),
        check_build_metadata(),
    ]
}

fn check_os() -> CheckResult {
    if std::env::consts::OS == "linux" {
        return CheckResult {
            check: "os",
            status: CheckStatus::Ok,
            message: "linux".to_string(),
        };
    }

    CheckResult {
        check: "os",
        status: CheckStatus::Fail,
        message: format!("unsupported OS: {}", std::env::consts::OS),
    }
}

fn check_procfs() -> CheckResult {
    match fs::metadata("/proc") {
        Ok(md) => {
            if md.is_dir() {
                CheckResult {
                    check: "procfs",
                    status: CheckStatus::Ok,
                    message: "/proc present".to_string(),
                }
            } else {
                CheckResult {
                    check: "procfs",
                    status: CheckStatus::Fail,
                    message: "/proc is not a directory".to_string(),
                }
            }
        }
        Err(e) => CheckResult {
            check: "procfs",
            status: CheckStatus::Fail,
            message: format!("/proc not accessible: {e}"),
        },
    }
}

fn check_list_pids() -> CheckResult {
    match list_pids() {
        Ok(pids) => CheckResult {
            check: "pids",
            status: CheckStatus::Ok,
            message: format!("{} processes visible", pids.len()),
        },
        Err(e) => CheckResult {
            check: "pids",
            status: CheckStatus::Fail,
            message: format!("cannot list /proc: {e}"),
        },
    }
}

fn check_proc_net() -> CheckResult {
    match read_proc_net_sockets() {
        Ok(sockets) => CheckResult {
            check: "proc_net",
            status: CheckStatus::Ok,
            message: format!("{} sockets parsed", sockets.len()),
        },
        Err(e) => CheckResult {
            check: "proc_net",
            status: CheckStatus::Fail,
            message: format!("cannot read /proc/net/*: {e}"),
        },
    }
}

fn check_audit_log() -> CheckResult {
    let path = "/var/log/audit/audit.log";
    match fs::metadata(path) {
        Ok(_) => match fs::File::open(path) {
            Ok(_) => CheckResult {
                check: "audit_log",
                status: CheckStatus::Ok,
                message: "audit log readable".to_string(),
            },
            Err(e) => CheckResult {
                check: "audit_log",
                status: CheckStatus::Warn,
                message: format!("audit log not readable: {e}"),
            },
        },
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return CheckResult {
                    check: "audit_log",
                    status: CheckStatus::Warn,
                    message: "audit log not present (lasttouch will use metadata/journal)"
                        .to_string(),
                };
            }
            CheckResult {
                check: "audit_log",
                status: CheckStatus::Warn,
                message: format!("audit log metadata error: {e}"),
            }
        }
    }
}

fn check_journalctl() -> CheckResult {
    let out = Command::new("journalctl").arg("--version").output();
    match out {
        Ok(o) => {
            if o.status.success() {
                CheckResult {
                    check: "journalctl",
                    status: CheckStatus::Ok,
                    message: "available".to_string(),
                }
            } else {
                CheckResult {
                    check: "journalctl",
                    status: CheckStatus::Warn,
                    message: "present but returned non-zero".to_string(),
                }
            }
        }
        Err(e) => CheckResult {
            check: "journalctl",
            status: CheckStatus::Warn,
            message: format!("not available: {e}"),
        },
    }
}

fn check_build_metadata() -> CheckResult {
    let target = build_target();
    let sha = git_sha();

    if target == "unknown" && sha == "unknown" {
        return CheckResult {
            check: "build_meta",
            status: CheckStatus::Warn,
            message: "build target and git sha are unknown (local builds may omit env vars)"
                .to_string(),
        };
    }

    if target == "unknown" {
        return CheckResult {
            check: "build_meta",
            status: CheckStatus::Warn,
            message: "build target is unknown".to_string(),
        };
    }

    if sha == "unknown" {
        return CheckResult {
            check: "build_meta",
            status: CheckStatus::Warn,
            message: "git sha is unknown".to_string(),
        };
    }

    CheckResult {
        check: "build_meta",
        status: CheckStatus::Ok,
        message: format!("{target} ({})", short_sha(sha)),
    }
}

#[allow(dead_code)]
fn check_proc_access_smoke() -> CheckResult {
    match procscan::read_comm_access(1) {
        ProcAccess::Ok(_) => CheckResult {
            check: "proc_access",
            status: CheckStatus::Ok,
            message: "can read /proc/1/comm".to_string(),
        },
        ProcAccess::PermissionDenied => CheckResult {
            check: "proc_access",
            status: CheckStatus::Warn,
            message: "permission denied reading /proc/1/comm (hidepid?)".to_string(),
        },
        ProcAccess::Gone => CheckResult {
            check: "proc_access",
            status: CheckStatus::Warn,
            message: "/proc/1/comm not found".to_string(),
        },
        ProcAccess::Fatal(e) => CheckResult {
            check: "proc_access",
            status: CheckStatus::Warn,
            message: format!("error reading /proc/1/comm: {e}"),
        },
    }
}
