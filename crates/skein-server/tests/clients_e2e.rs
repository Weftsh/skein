//! The real clients, against the real server.
//!
//! Every other suite sends bodies **we** built, from what we believe a
//! client sends, and reads them back with assertions written from the
//! same belief. stratum-core, which Skein was carved out of, paid for
//! that three times: a fake that was wrong in exactly the place the
//! product depended on it, with a green test named for the case. So this
//! drives the actual `npm` (and, as each door lands, `mvn`, `twine` and
//! `pip`, `cargo`, `docker`), and the assertions are on what came back
//! **through the client** — `npm view`'s output and the installed file,
//! not our own HTTP.
//!
//! A client that is not installed is a **NOTE** and claims nothing: a
//! machine with no `npm` has not proved the npm contract. CI's `clients`
//! job sets `SKEIN_REQUIRE_CLIENTS` to every client it installs, and
//! there a missing one fails instead.

mod common;

use skein_testkit::{Minio, Server};
use std::path::Path;
use std::process::Command;

/// Whether `client` can be run here. A missing one is a NOTE, or a
/// failure when `SKEIN_REQUIRE_CLIENTS` names it.
fn have(client: &str) -> bool {
    let found = Command::new(client)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    let required = std::env::var("SKEIN_REQUIRE_CLIENTS")
        .unwrap_or_default()
        .split(',')
        .any(|c| c.trim() == client);
    if !found {
        assert!(!required, "{client} is required here and is not installed");
        eprintln!("NOTE: {client} is not installed; its contract is not checked by this run");
    }
    found
}

/// Run a client, failing the test with everything it printed.
fn run(dir: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> String {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .envs(env.iter().copied())
        .output()
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "{program} {args:?} failed ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        out.status
    );
    stdout
}

/// Run a client that is expected to fail, returning what it printed.
fn run_err(dir: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> String {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .envs(env.iter().copied())
        .output()
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"));
    assert!(
        !out.status.success(),
        "{program} {args:?} succeeded and should not have"
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "skein-clients-{name}-{}-{}",
        std::process::id(),
        skein_control::ids::ulid()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An `.npmrc` pointing one scope at this registry, the way the docs
/// tell people to write it — and a home directory of its own, so the
/// developer's real `~/.npmrc` and cache cannot answer for us.
fn npm_env(server: &Server, dir: &Path, token: &str) -> Vec<(String, String)> {
    let reg = format!("{}/npm/", server.base);
    let auth_key = reg.trim_start_matches("http:");
    std::fs::write(
        dir.join(".npmrc"),
        format!("@acme:registry={reg}\n{auth_key}:_authToken={token}\n"),
    )
    .unwrap();
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    vec![
        ("HOME".into(), home.display().to_string()),
        (
            "npm_config_cache".into(),
            dir.join("cache").display().to_string(),
        ),
        (
            "npm_config_userconfig".into(),
            dir.join(".npmrc").display().to_string(),
        ),
        ("npm_config_update_notifier".into(), "false".into()),
        ("npm_config_audit".into(), "false".into()),
        ("npm_config_fund".into(), "false".into()),
    ]
}

/// `npm publish`, `npm view`, `npm install` — and the refusals a person
/// actually reads in their terminal.
#[test]
fn npm_publishes_views_and_installs_through_skein() {
    if !have("npm") {
        return;
    }
    let bucket = Minio::shared().bucket("clients-npm");
    let server = common::spawn(&bucket.base_url, "clients-npm");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);

    // A package, published by the CI service account.
    let src = scratch("npm-src");
    std::fs::write(
        src.join("package.json"),
        r#"{ "name": "@acme/widget", "version": "1.2.3", "license": "MIT",
             "main": "index.js", "description": "a widget" }"#,
    )
    .unwrap();
    std::fs::write(src.join("index.js"), "module.exports = 'widget 1.2.3';\n").unwrap();
    let env = npm_env(&server, &src, &ci);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    run(&src, "npm", &["publish"], &env);

    // Publishing the same version again is refused, and npm says why.
    let again = run_err(&src, "npm", &["publish"], &env);
    assert!(
        again.contains("409") || again.contains("already published"),
        "{again}"
    );

    // A reader sees it through npm's own eyes…
    let consumer = scratch("npm-consumer");
    std::fs::write(
        consumer.join("package.json"),
        r#"{ "name": "consumer", "version": "0.0.0", "private": true }"#,
    )
    .unwrap();
    let cenv = npm_env(&server, &consumer, &reader);
    let cenv: Vec<(&str, &str)> = cenv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let view = run(&consumer, "npm", &["view", "@acme/widget", "--json"], &cenv);
    let view: serde_json::Value =
        serde_json::from_str(&view).unwrap_or_else(|e| panic!("{e}: {view}"));
    assert_eq!(view["name"], "@acme/widget");
    assert_eq!(view["version"], "1.2.3");
    assert_eq!(view["license"], "MIT");
    assert_eq!(view["dist-tags"]["latest"], "1.2.3");
    assert!(
        view["dist"]["integrity"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha512-"),
        "{view}"
    );

    // …installs it, integrity checked by npm itself, and gets the file.
    run(&consumer, "npm", &["install", "@acme/widget@^1.2.0"], &cenv);
    let installed = std::fs::read_to_string(consumer.join("node_modules/@acme/widget/index.js"))
        .expect("the installed package");
    assert_eq!(installed, "module.exports = 'widget 1.2.3';\n");

    // …and cannot publish, with the reason in npm's own output.
    let pubdir = scratch("npm-reader-publish");
    std::fs::write(
        pubdir.join("package.json"),
        r#"{ "name": "@acme/widget", "version": "9.9.9", "license": "MIT" }"#,
    )
    .unwrap();
    let renv = npm_env(&server, &pubdir, &reader);
    let renv: Vec<(&str, &str)> = renv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let refused = run_err(&pubdir, "npm", &["publish"], &renv);
    assert!(refused.contains("403"), "{refused}");
    assert!(
        refused.contains("rita is a reader"),
        "npm did not show the reason: {refused}"
    );

    // Without a token, npm is challenged rather than told the package is
    // missing.
    let anon = scratch("npm-anon");
    std::fs::write(
        anon.join("package.json"),
        r#"{ "name": "a", "version": "0.0.0" }"#,
    )
    .unwrap();
    let aenv = npm_env(&server, &anon, "");
    std::fs::write(
        anon.join(".npmrc"),
        format!("@acme:registry={}/npm/\n", server.base),
    )
    .unwrap();
    let aenv: Vec<(&str, &str)> = aenv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let denied = run_err(&anon, "npm", &["view", "@acme/widget"], &aenv);
    assert!(
        denied.contains("401") || denied.contains("E401") || denied.contains("authentication"),
        "{denied}"
    );

    for d in [src, consumer, pubdir, anon] {
        let _ = std::fs::remove_dir_all(d);
    }
    assert!(server.healthy());
}
