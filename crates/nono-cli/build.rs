//! Build script for nono-cli
//!
//! Embeds policy and hook scripts into the binary at compile time and
//! resolves the runtime version string (NONO_BUILD_VERSION).

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Rebuild if data files change
    println!("cargo:rerun-if-changed=data/");

    // === Resolve runtime version (NONO_BUILD_VERSION) ===
    //
    // Priority:
    //   1. NONO_VERSION env var, set by the release workflow from the git tag.
    //      This is the source of truth for tagged releases.
    //   2. The output of `git describe --tags --always`, when run from a
    //      checkout. Useful for ad-hoc local builds that happen to be at a
    //      tag.
    //   3. Literal "dev" — for everyday local builds without a tag, builds
    //      from tarballs, or builds where git is unavailable.
    //
    // The `Cargo.toml` `version` field is intentionally pinned to 0.0.0 and
    // is NOT used for the user-visible version string. This decouples the
    // crate metadata (which Cargo requires) from the release-stamped version.
    println!("cargo:rerun-if-env-changed=NONO_VERSION");
    let version = match env::var("NONO_VERSION") {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v').to_string(),
        _ => Command::new("git")
            .args(["describe", "--tags", "--always"])
            .output()
            .ok()
            .and_then(|out| {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.trim_start_matches('v').to_string())
                    }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "dev".to_string()),
    };
    println!("cargo:rustc-env=NONO_BUILD_VERSION={}", version);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // === Embed policy JSON ===
    let policy_path = Path::new("data/policy.json");
    if policy_path.exists() {
        let content = fs::read_to_string(policy_path).expect("Failed to read policy.json");

        // Write to OUT_DIR for include_str! macro
        fs::write(out_path.join("policy.json"), &content)
            .expect("Failed to write policy.json to OUT_DIR");

        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/policy.json not found");
        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=0");
    }

    // === Embed network policy JSON ===
    let net_policy_path = Path::new("data/network-policy.json");
    if net_policy_path.exists() {
        let content =
            fs::read_to_string(net_policy_path).expect("Failed to read network-policy.json");
        fs::write(out_path.join("network-policy.json"), &content)
            .expect("Failed to write network-policy.json to OUT_DIR");
        println!("cargo:rustc-env=NETWORK_POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/network-policy.json not found");
        println!("cargo:rustc-env=NETWORK_POLICY_JSON_EMBEDDED=0");
    }

    // === Embed hook script ===
    let hook_path = Path::new("data/hooks/nono-hook.sh");
    if hook_path.exists() {
        let content = fs::read_to_string(hook_path).expect("Failed to read hook script");
        fs::write(out_path.join("nono-hook.sh"), &content)
            .expect("Failed to write hook script to OUT_DIR");
    }

    // === Embed profile JSON Schema ===
    let schema_path = Path::new("data/nono-profile.schema.json");
    if schema_path.exists() {
        let content = fs::read_to_string(schema_path).expect("Failed to read profile schema");
        fs::write(out_path.join("nono-profile.schema.json"), &content)
            .expect("Failed to write profile schema to OUT_DIR");
    }

    // === Embed profile authoring guide ===
    let guide_path = Path::new("data/profile-authoring-guide.md");
    if guide_path.exists() {
        let content =
            fs::read_to_string(guide_path).expect("Failed to read profile authoring guide");
        fs::write(out_path.join("profile-authoring-guide.md"), &content)
            .expect("Failed to write profile authoring guide to OUT_DIR");
    }
}
