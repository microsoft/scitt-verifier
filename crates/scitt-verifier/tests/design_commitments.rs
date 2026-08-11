//! Tests for the design commitments the README states as constraints.
//!
//! The README calls them constraints rather than aspirations, which is only
//! true if something fails when they erode. Most of the commitments are
//! *refusals* — the tool declines to do something — and those are tested per
//! invocation in `acceptance.rs`. This file covers the one commitment that is
//! a whole-program property instead, and so cannot be established by any
//! number of example runs.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/scitt-verifier.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root")
        .to_path_buf()
}

/// Crates that speak a network protocol or open a socket.
///
/// Deliberately a denylist of the plausible ways this would arrive rather than
/// an allowlist of the current tree: the failure mode worth catching is a
/// future dependency quietly pulling one in, and an allowlist would have to be
/// edited for every unrelated addition until someone stopped reading it.
const NETWORK_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "hyper-util",
    "ureq",
    "curl",
    "curl-sys",
    "isahc",
    "attohttpc",
    "surf",
    "tokio",
    "async-std",
    "mio",
    "socket2",
    "trust-dns-resolver",
    "hickory-resolver",
    "native-tls",
    "rustls",
    "tungstenite",
];

const SOCKET_APIS: &[&str] = &["std::net", "TcpStream", "TcpListener", "UdpSocket"];

fn network_crates_in(lock: &str) -> Vec<&'static str> {
    NETWORK_CRATES
        .iter()
        .copied()
        .filter(|c| lock.contains(&format!("name = \"{c}\"")))
        .collect()
}

fn socket_apis_in(body: &str) -> Vec<&'static str> {
    SOCKET_APIS
        .iter()
        .copied()
        .filter(|n| body.contains(*n))
        .collect()
}

#[test]
fn offline_by_default_is_enforced_by_the_dependency_graph() {
    let lock = std::fs::read_to_string(repo_root().join("Cargo.lock")).expect("read Cargo.lock");
    let found = network_crates_in(&lock);

    assert!(
        found.is_empty(),
        "the tool claims to be offline by default, but the dependency graph now contains {found:?}. \
         Either the claim is false or the dependency is unnecessary; the README says the former is \
         not an option."
    );
}

#[test]
fn no_source_file_reaches_for_a_socket() {
    // A dependency cannot be the only way this erodes: the standard library
    // is always available and needs no lockfile entry.
    let mut offenders = Vec::new();

    for crate_dir in ["scitt-verifier", "scitt-receipt", "scitt-policy"] {
        let src = repo_root().join("crates").join(crate_dir).join("src");
        assert!(src.is_dir(), "expected {} to exist", src.display());
        visit(&src, &mut |path, body| {
            for needle in socket_apis_in(body) {
                offenders.push(format!("{} contains {needle}", path.display()));
            }
        });
    }

    assert!(
        offenders.is_empty(),
        "verification must never open a socket: {offenders:?}"
    );
}

/// A test that cannot fail proves nothing, and cargo rewrites `Cargo.lock`
/// before tests run, so the real file cannot be used to demonstrate that the
/// detection works. These pin the detectors themselves against known-bad input.
#[test]
fn the_detectors_actually_detect() {
    let poisoned = "[[package]]\nname = \"scitt-receipt\"\n\n[[package]]\nname = \"reqwest\"\n";
    assert_eq!(network_crates_in(poisoned), vec!["reqwest"]);
    assert!(network_crates_in("[[package]]\nname = \"sha2\"\n").is_empty());

    assert_eq!(
        socket_apis_in("let s = std::net::TcpStream::connect(addr)?;"),
        vec!["std::net", "TcpStream"]
    );
    assert!(socket_apis_in("let digest = sha256_hex(&bytes);").is_empty());
}

/// The walker must actually reach files. If it silently visited nothing, the
/// socket test above would pass for the wrong reason forever.
#[test]
fn the_source_walk_reaches_every_crate() {
    for crate_dir in ["scitt-verifier", "scitt-receipt", "scitt-policy"] {
        let mut seen = 0usize;
        visit(
            &repo_root().join("crates").join(crate_dir).join("src"),
            &mut |_, _| seen += 1,
        );
        assert!(seen > 0, "walked no .rs files in {crate_dir}");
    }
}

fn visit(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            if let Ok(body) = std::fs::read_to_string(&path) {
                f(&path, &body);
            }
        }
    }
}
