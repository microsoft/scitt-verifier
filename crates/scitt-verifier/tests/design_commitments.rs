//! Tests for the design commitments the README states as constraints.
//!
//! The README calls them constraints rather than aspirations, which is only
//! true if something fails when they erode. Most of the commitments are
//! *refusals* — the tool declines to do something — and those are tested per
//! invocation in `acceptance.rs`. This file covers the one commitment that is
//! a whole-program property instead, and so cannot be established by any
//! number of example runs.

use std::collections::{BTreeSet, HashMap};
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

/// The one crate allowed to reach the network, and the only door into it.
const ACQUIRE: &str = "scitt-acquire";

/// The crates that decide whether a statement is trustworthy.
///
/// Nothing here may reach the network on any path, under any feature. A
/// verdict that depends on a socket is a verdict that can be changed by
/// whoever controls the socket.
const CORE: &[&str] = &["scitt-receipt", "scitt-policy"];

const SOCKET_APIS: &[&str] = &["std::net", "TcpStream", "TcpListener", "UdpSocket"];

/// Every package in `Cargo.lock`, mapped to the packages it depends on.
///
/// The lockfile over-approximates: it records dependencies that some feature
/// combination could enable, including ones no build of this workspace ever
/// compiles. That is the right bias here. A commitment tested against an
/// over-approximation fails early and loudly; one tested against the exact
/// current build would pass until someone flipped a feature.
fn dependency_graph(lock: &str) -> HashMap<String, Vec<String>> {
    let mut graph = HashMap::new();
    for block in lock.split("[[package]]") {
        let Some(name) = field(block, "name") else {
            continue;
        };
        let deps = match block.split_once("dependencies = [") {
            Some((_, rest)) => rest
                .split_once(']')
                .map(|(list, _)| list)
                .unwrap_or("")
                .lines()
                .filter_map(|l| {
                    let t = l.trim().trim_matches(|c| c == '"' || c == ',');
                    // Entries are `"name"` or `"name version"`; the version is
                    // a disambiguator, and the edge is to the name either way.
                    t.split_whitespace().next().map(str::to_string)
                })
                .filter(|s| !s.is_empty())
                .collect(),
            None => Vec::new(),
        };
        graph.insert(name, deps);
    }
    graph
}

fn field(block: &str, key: &str) -> Option<String> {
    block.lines().find_map(|l| {
        l.trim()
            .strip_prefix(&format!("{key} = \""))?
            .strip_suffix('"')
            .map(str::to_string)
    })
}

/// Everything reachable from `roots`, never entering any package in `stop`.
fn reachable(
    graph: &HashMap<String, Vec<String>>,
    roots: &[&str],
    stop: &[&str],
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue: Vec<String> = roots.iter().map(|r| r.to_string()).collect();
    while let Some(pkg) = queue.pop() {
        if stop.contains(&pkg.as_str()) || !seen.insert(pkg.clone()) {
            continue;
        }
        if let Some(deps) = graph.get(&pkg) {
            queue.extend(deps.iter().cloned());
        }
    }
    seen
}

fn network_crates_among(pkgs: &BTreeSet<String>) -> Vec<&'static str> {
    NETWORK_CRATES
        .iter()
        .copied()
        .filter(|c| pkgs.contains(*c))
        .collect()
}

fn socket_apis_in(body: &str) -> Vec<&'static str> {
    SOCKET_APIS
        .iter()
        .copied()
        .filter(|n| body.contains(*n))
        .collect()
}

fn graph() -> HashMap<String, Vec<String>> {
    let lock = std::fs::read_to_string(repo_root().join("Cargo.lock")).expect("read Cargo.lock");
    let g = dependency_graph(&lock);
    // A parser that silently matched nothing would make every assertion below
    // vacuously true, which is the one way this file could fail at its job
    // without anyone noticing.
    for pkg in CORE.iter().chain([ACQUIRE, "scitt-verifier"].iter()) {
        assert!(
            g.contains_key(*pkg),
            "did not find {pkg} in Cargo.lock; the parser is not reading the file it thinks it is"
        );
    }
    g
}

/// The crates that produce a verdict cannot reach the network at all.
///
/// This is narrower than the commitment this file used to test, which was that
/// no network crate appeared anywhere in the lockfile. That test could not
/// survive `--online` existing, and relaxing it was a reviewed decision rather
/// than a convenience: see docs/architecture.md.
///
/// What replaces it is more precise, not merely more permissive. Presence in a
/// lockfile was always a proxy — it flagged optional dependencies that are
/// never compiled, and it would have flagged a crate added under a dev-only
/// dependency of an unrelated package. Reachability is the property actually
/// claimed, and it is now checked directly, from named roots.
#[test]
fn the_deciding_crates_cannot_reach_the_network() {
    let found = network_crates_among(&reachable(&graph(), CORE, &[]));
    assert!(
        found.is_empty(),
        "{CORE:?} decide whether a statement is trusted, and must not depend on anything \
         that opens a socket, but they now reach {found:?}. A verdict that depends on the \
         network is a verdict someone else can change."
    );
}

/// Networking enters this tool through exactly one named door.
///
/// Without this, `--online` would be indistinguishable from the whole tool
/// having quietly become a network client: any future dependency could add a
/// socket anywhere and the tree would look the same.
#[test]
fn networking_reaches_the_cli_only_through_the_acquisition_crate() {
    let found = network_crates_among(&reachable(&graph(), &["scitt-verifier"], &[ACQUIRE]));
    assert!(
        found.is_empty(),
        "networking must reach the CLI only through {ACQUIRE}, but {found:?} is reachable \
         without going through it. Route the dependency through {ACQUIRE}, or drop it."
    );
}

/// The acquisition crate does not get to decide anything.
///
/// It fetches bytes; the core decides what they mean. If it ever depended on
/// the policy engine it would be in a position to form its own opinion, and
/// the guarantee that verdicts come from one place would stop being structural.
#[test]
fn the_acquisition_crate_cannot_form_a_verdict() {
    let reach = reachable(&graph(), &[ACQUIRE], &[]);
    assert!(
        !reach.contains("scitt-policy"),
        "{ACQUIRE} must not depend on the policy engine: fetching trust material and \
         judging it are separate jobs, and only the second may produce a verdict."
    );
}

#[test]
fn offline_remains_the_default_shape_of_a_run() {
    // The lockfile cannot show this: it is a property of the argument parser.
    // Named here so the commitment has a home next to the others it belongs
    // with, and tested where the behaviour is, in acceptance.rs.
    let usage =
        std::fs::read_to_string(repo_root().join("crates/scitt-verifier/src").join("cli.rs"))
            .expect("read cli.rs");
    assert!(
        usage.contains("Verification is offline unless --online is passed"),
        "the help text must say plainly that a run makes no network request unless asked, \
         because a user who does not know that cannot audit it."
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
    // A lockfile where the core reaches a network crate, and one where the
    // same crate is present but only behind the acquisition door. The second
    // is the case the old presence check could not tell from the first, and
    // the whole reason this detector had to change shape.
    let poisoned = "[[package]]\nname = \"scitt-receipt\"\ndependencies = [\n \"reqwest\",\n]\n\
                    \n[[package]]\nname = \"reqwest\"\n";
    let g = dependency_graph(poisoned);
    assert_eq!(
        network_crates_among(&reachable(&g, &["scitt-receipt"], &[])),
        vec!["reqwest"]
    );

    let walled =
        "[[package]]\nname = \"scitt-verifier\"\ndependencies = [\n \"scitt-acquire\",\n]\n\
                  \n[[package]]\nname = \"scitt-acquire\"\ndependencies = [\n \"ureq\",\n]\n\
                  \n[[package]]\nname = \"ureq\"\n";
    let g = dependency_graph(walled);
    assert!(
        network_crates_among(&reachable(&g, &["scitt-verifier"], &[ACQUIRE])).is_empty(),
        "a network crate reachable only through the acquisition crate must pass"
    );
    assert_eq!(
        network_crates_among(&reachable(&g, &["scitt-verifier"], &[])),
        vec!["ureq"],
        "without the stop set the same graph must still show the crate, or the \
         walled-off case above is passing because the walk found nothing at all"
    );

    // A version-qualified edge is the same edge. Missing this would let any
    // duplicated dependency slip the walk.
    let versioned = "[[package]]\nname = \"a\"\ndependencies = [\n \"ureq 3.0.0\",\n]\n\
                     \n[[package]]\nname = \"ureq\"\n";
    assert_eq!(
        network_crates_among(&reachable(&dependency_graph(versioned), &["a"], &[])),
        vec!["ureq"]
    );

    assert!(network_crates_among(&reachable(
        &dependency_graph("[[package]]\nname = \"sha2\"\n"),
        &["sha2"],
        &[]
    ))
    .is_empty());

    assert_eq!(
        socket_apis_in("let s = std::net::TcpStream::connect(addr)?;"),
        vec!["std::net", "TcpStream"]
    );
    assert!(socket_apis_in("let digest = sha256_hex(&bytes);").is_empty());

    assert_eq!(
        codes_named_in("*Reported at runtime:* code `RevocationNotChecked`."),
        vec!["RevocationNotChecked"]
    );
    // Backticked prose that is not a code must not be harvested, or the doc
    // test starts demanding that `--scitt-keys` appear as a string literal.
    assert!(codes_named_in("pass `--scitt-keys` and read `trust.limitations`").is_empty());
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

/// Stable codes that `docs/limitations.md` promises the tool reports, written
/// there as ``code `Xxx` ``.
fn codes_named_in(doc: &str) -> Vec<String> {
    const MARKER: &str = "code `";
    let mut found = Vec::new();
    let mut rest = doc;
    while let Some(start) = rest.find(MARKER) {
        rest = &rest[start + MARKER.len()..];
        match rest.find('`') {
            Some(end) => {
                found.push(rest[..end].to_string());
                rest = &rest[end + 1..];
            }
            None => break,
        }
    }
    found
}

/// `limitations.md` opens by promising that every limitation it lists is also
/// reported at runtime. That promise is only worth making if renaming or
/// deleting a code breaks something, so this pins the codes the document names
/// against the source that has to emit them.
///
/// It deliberately checks one direction. A code in the source that the document
/// does not mention is not necessarily an omission — several describe how the
/// run was invoked rather than what this build cannot do — whereas a code the
/// document promises and the source no longer emits is always a false claim.
#[test]
fn docs_report_what_they_claim() {
    let doc = std::fs::read_to_string(repo_root().join("docs").join("limitations.md"))
        .expect("read docs/limitations.md");

    let named = codes_named_in(&doc);
    assert!(
        !named.is_empty(),
        "found no codes in docs/limitations.md; either the document stopped naming them or the \
         `code `<name>`` convention changed, and this test is no longer checking anything"
    );

    let mut sources = String::new();
    for crate_dir in ["scitt-verifier", "scitt-receipt", "scitt-policy"] {
        visit(
            &repo_root().join("crates").join(crate_dir).join("src"),
            &mut |_, body| sources.push_str(body),
        );
    }

    let missing: Vec<&String> = named
        .iter()
        .filter(|code| !sources.contains(&format!("\"{code}\"")))
        .collect();

    assert!(
        missing.is_empty(),
        "docs/limitations.md promises these codes are reported at runtime, but no source file \
         emits them: {missing:?}"
    );
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
