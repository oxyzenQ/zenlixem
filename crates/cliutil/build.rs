use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.join("../..");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());

    let default_label = if profile.starts_with("linux-") {
        profile
    } else {
        match target.as_str() {
            "x86_64-unknown-linux-gnu" => "linux-amd64".to_string(),
            "aarch64-unknown-linux-gnu" => "linux-aarch64".to_string(),
            _ => target.clone(),
        }
    };

    let build_target = std::env::var("ZENLIXEM_BUILD_TARGET").unwrap_or(default_label);
    println!("cargo:rustc-env=ZENLIXEM_BUILD_TARGET={build_target}");

    let git_sha = std::env::var("ZENLIXEM_GIT_SHA").ok().or_else(|| {
        let out = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&workspace_root)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    });

    if let Some(sha) = git_sha {
        println!("cargo:rustc-env=ZENLIXEM_GIT_SHA={sha}");
    }

    println!("cargo:rerun-if-env-changed=ZENLIXEM_BUILD_TARGET");
    println!("cargo:rerun-if-env-changed=ZENLIXEM_GIT_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}
