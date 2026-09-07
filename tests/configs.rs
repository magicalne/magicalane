//! Parse-check every shipped config: `configs/` (user-facing examples)
//! and `env/configs/*.toml` (test fixtures). This is the guard rail
//! for the AGENTS.md rule "configs must stay valid": any change to
//! src/config.rs semantics that invalidates a shipped example fails
//! here, in the same `cargo test` run as everything else.

use std::path::PathBuf;

fn toml_files(dir: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("toml") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn shipped_configs_parse() {
    let mut checked = 0;
    for dir in ["configs", "env/configs"] {
        let files = toml_files(dir);
        assert!(
            !files.is_empty(),
            "expected config files in {dir} (did the directory move?)"
        );
        for path in files {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let parsed: Result<lib::config::Config, _> = toml::from_str(&text);
            assert!(
                parsed.is_ok(),
                "{} no longer parses: {:?}",
                path.display(),
                parsed.err()
            );
            checked += 1;
        }
    }
    assert!(checked >= 6, "suspiciously few configs checked: {checked}");
}

#[test]
fn kind_must_be_inline_documented_style() {
    // Guard the documented constraint: [kind.Client] headers must fail.
    // If a dependency upgrade makes header style work, update
    // configs/README.md and relax this test.
    let bad = r#"
password = "x"
bandwidth = 1
verbose = true
[kind.Client]
socks5_port = 1080
tproxy = { mode = "off", tcp_port = 0, udp_port = 0 }
"#;
    let parsed: Result<lib::config::Config, _> = toml::from_str(bad);
    assert!(parsed.is_err(), "header style parsed: update the docs");
}
