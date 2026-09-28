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

/// A `CARGO_HOME` of its own, holding exactly the configuration
/// `docs/cargo.md` tells people to write — so the developer's own
/// `~/.cargo` cannot answer for us.
fn cargo_home(server: &Server, dir: &Path, token: Option<&str>) -> std::path::PathBuf {
    let home = dir.join("cargo-home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!(
            "[registries.acme]\nindex = \"sparse+{}/cargo/index/\"\n\
             credential-provider = [\"cargo:token\"]\n",
            server.base
        ),
    )
    .unwrap();
    if let Some(t) = token {
        std::fs::write(
            home.join("credentials.toml"),
            format!("[registries.acme]\ntoken = \"{t}\"\n"),
        )
        .unwrap();
    }
    home
}

/// Run the real `cargo` in `dir` against `home`, returning whether it
/// succeeded and everything it printed.
///
/// Every `CARGO_*` variable this process inherited is dropped: `cargo
/// test` sets a dozen, and a developer's `CARGO_REGISTRIES_ACME_TOKEN`
/// would answer for the `credentials.toml` under test. Colour is off so
/// an assertion on cargo's words reads the same here and in CI, where
/// the workflow sets `CARGO_TERM_COLOR=always`.
fn cargo_in(dir: &Path, home: &Path, args: &[&str]) -> (bool, String) {
    let mut cmd = Command::new("cargo");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("CARGO_") {
            cmd.env_remove(&k);
        }
    }
    let out = cmd
        .args(args)
        .current_dir(dir)
        .env("CARGO_HOME", home)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .unwrap_or_else(|e| panic!("spawn cargo: {e}"));
    (
        out.status.success(),
        format!(
            "--- stdout\n{}\n--- stderr\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn cargo_ok(dir: &Path, home: &Path, args: &[&str]) -> String {
    let (ok, out) = cargo_in(dir, home, args);
    assert!(ok, "cargo {args:?} failed:\n{out}");
    out
}

fn cargo_err(dir: &Path, home: &Path, args: &[&str]) -> String {
    let (ok, out) = cargo_in(dir, home, args);
    assert!(!ok, "cargo {args:?} succeeded and should not have:\n{out}");
    out
}

/// After uploading, `cargo publish` polls the index until the new
/// version is there, and after a minute gives up with a *warning* and
/// exits 0. So a publish whose index line Cargo cannot read looks like a
/// success — this is how a dependency the index described in the
/// publish's words instead of its own went unnoticed — and the only
/// sign at publish time is that sentence.
fn visible_at_once(publish_output: &str) {
    assert!(
        publish_output.contains("Uploaded") && !publish_output.contains("timed out waiting"),
        "the published version never became visible in the index:\n{publish_output}"
    );
}

/// A crate on disk: a manifest and one source file.
fn write_crate(dir: &Path, manifest: &str, file: &str, source: &str) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
    std::fs::write(dir.join("src").join(file), source).unwrap();
}

/// `cargo publish`, `cargo build` and `cargo yank` — and the refusals a
/// person actually reads in their terminal.
///
/// Two crates, not one, and the second depends on the first **from
/// Skein, under a rename**. That is on purpose: the publish body and the
/// index describe a dependency in two different shapes, and a crate with
/// no dependencies cannot tell whether the registry translates one into
/// the other or merely echoes it.
#[test]
fn cargo_publishes_and_builds_against_skein() {
    if !have("cargo") {
        return;
    }
    let root = scratch("cargo");
    let version = cargo_ok(&root, &root.join("version-home"), &["--version"]);
    eprintln!(
        "cargo_publishes_and_builds_against_skein: checking {}",
        version
            .lines()
            .find(|l| l.starts_with("cargo "))
            .unwrap_or("an unknown cargo")
    );
    let bucket = Minio::shared().bucket("clients-cargo");
    let server = common::spawn(&bucket.base_url, "clients-cargo");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let ci_home = cargo_home(&server, &root.join("ci"), Some(&ci));
    let index = format!("sparse+{}/cargo/index/", server.base);

    // A library with no dependencies at all, published by CI.
    let base = root.join("acme-base");
    let base_manifest = |version: &str| {
        format!(
            "[package]\nname = \"acme-base\"\nversion = \"{version}\"\nedition = \"2021\"\n\
             license = \"MIT OR Apache-2.0\"\ndescription = \"the base\"\n\
             publish = [\"acme\"]\n"
        )
    };
    write_crate(
        &base,
        &base_manifest("0.1.0"),
        "lib.rs",
        "pub fn greeting() -> &'static str {\n    \"hello from acme-base 0.1.0\"\n}\n",
    );
    let published = cargo_ok(
        &base,
        &ci_home,
        &["publish", "--registry", "acme", "--allow-dirty"],
    );
    visible_at_once(&published);

    // A library that depends on it from this registry, renamed. `cargo
    // publish` verifies by building the packaged crate, which resolves
    // `acme-base` through our index and downloads it from our `dl`.
    let widget = root.join("acme-widget");
    write_crate(
        &widget,
        "[package]\nname = \"acme-widget\"\nversion = \"1.4.0\"\nedition = \"2021\"\n\
         license = \"MIT\"\ndescription = \"a widget\"\npublish = [\"acme\"]\n\n\
         [dependencies]\nbase = { package = \"acme-base\", version = \"0.1\", registry = \"acme\" }\n",
        "lib.rs",
        "pub fn describe() -> String {\n    \
         format!(\"acme-widget 1.4.0 over [{}]\", base::greeting())\n}\n",
    );
    let published = cargo_ok(
        &widget,
        &ci_home,
        &["publish", "--registry", "acme", "--allow-dirty"],
    );
    visible_at_once(&published);

    // Publishing the same version again is refused, and cargo says so.
    let again = cargo_err(
        &base,
        &ci_home,
        &["publish", "--registry", "acme", "--allow-dirty"],
    );
    // Cargo checks our index before it uploads, so this refusal is the
    // index telling it the version is there; the server's own 409 is
    // `cargo_e2e`'s to prove.
    assert!(
        again.contains("acme-base@0.1.0 already exists on `acme` index"),
        "{again}"
    );

    // A reader builds a program against it, in a home of their own: the
    // index read, the resolution through the renamed dependency, both
    // downloads checked against the index's `cksum` by cargo itself, and
    // a binary whose output is the published code's.
    let consumer_src = |dir: &Path, dep: &str| {
        write_crate(
            dir,
            &format!(
                "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 publish = false\n\n[dependencies]\n{dep}\n"
            ),
            "main.rs",
            "fn main() {\n    println!(\"{}\", acme_widget::describe());\n}\n",
        );
    };
    // The dependency is added the way the UI's install line says to.
    let consumer = root.join("consumer");
    consumer_src(&consumer, "");
    let reader_home = cargo_home(&server, &root.join("rita"), Some(&reader));
    cargo_ok(
        &consumer,
        &reader_home,
        &["add", "acme-widget@1.4.0", "--registry", "acme"],
    );
    let ran = cargo_ok(&consumer, &reader_home, &["run", "--quiet"]);
    assert!(
        ran.contains("acme-widget 1.4.0 over [hello from acme-base 0.1.0]"),
        "{ran}"
    );
    let lock = std::fs::read_to_string(consumer.join("Cargo.lock")).expect("a lockfile");
    for name in ["acme-base", "acme-widget"] {
        assert!(lock.contains(&format!("name = \"{name}\"")), "{lock}");
    }
    assert!(
        lock.contains(&format!("source = \"{index}\"")),
        "not resolved from Skein: {lock}"
    );

    // A yank through the client. A fresh resolution now refuses the
    // version, and cargo says why…
    cargo_ok(
        &base,
        &ci_home,
        &[
            "yank",
            "acme-base",
            "--version",
            "0.1.0",
            "--registry",
            "acme",
        ],
    );
    let fresh = root.join("fresh");
    consumer_src(
        &fresh,
        "acme-widget = { version = \"1.4\", registry = \"acme\" }",
    );
    let yanked = cargo_err(
        &fresh,
        &cargo_home(&server, &root.join("fresh-a"), Some(&reader)),
        &["generate-lockfile"],
    );
    assert!(yanked.contains("version 0.1.0 is yanked"), "{yanked}");

    // …while a lockfile that already names it still builds, downloading
    // the yanked crate into a home that has never seen it.
    let locked = root.join("locked");
    consumer_src(&locked, "");
    for file in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(consumer.join(file), locked.join(file)).unwrap();
    }
    let ran = cargo_ok(
        &locked,
        &cargo_home(&server, &root.join("locked"), Some(&reader)),
        &["run", "--quiet", "--locked"],
    );
    assert!(
        ran.contains("acme-widget 1.4.0 over [hello from acme-base 0.1.0]"),
        "a yank broke a build that had pinned the version:\n{ran}"
    );

    // `--undo` puts it back, and the fresh resolution succeeds.
    cargo_ok(
        &base,
        &ci_home,
        &[
            "yank",
            "--undo",
            "acme-base",
            "--version",
            "0.1.0",
            "--registry",
            "acme",
        ],
    );
    cargo_ok(
        &fresh,
        &cargo_home(&server, &root.join("fresh-b"), Some(&reader)),
        &["generate-lockfile"],
    );

    // The reader cannot publish, and the reason is in cargo's output.
    let rpub = root.join("rita-publish");
    write_crate(
        &rpub,
        &base_manifest("0.2.0"),
        "lib.rs",
        "pub fn greeting() -> &'static str {\n    \"not published\"\n}\n",
    );
    let refused = cargo_err(
        &rpub,
        &reader_home,
        &["publish", "--registry", "acme", "--allow-dirty"],
    );
    // Cargo's own words around our sentence — matched whole, because a
    // bare "403" also turns up in a port number or a scratch path.
    assert!(
        refused.contains(
            "(status 403 Forbidden): rita is a reader here, and a reader may not \
             publish to this registry"
        ),
        "cargo did not show the reason: {refused}"
    );

    // A token that is not one of ours is told so, rather than being
    // shown an empty registry.
    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    let denied = cargo_err(
        &fresh,
        &cargo_home(&server, &root.join("forged"), Some(forged)),
        &["generate-lockfile"],
    );
    assert!(denied.contains("token rejected for `acme`"), "{denied}");

    // No token at all: our 401 on `config.json` is what tells cargo this
    // registry needs one, and it asks for it rather than reporting an
    // empty registry.
    let anonymous = cargo_err(
        &fresh,
        &cargo_home(&server, &root.join("anonymous"), None),
        &["generate-lockfile"],
    );
    assert!(
        anonymous.contains("no token found for `acme`, please run `cargo login --registry acme`"),
        "{anonymous}"
    );

    // `docs/cargo.md` says `credential-provider` is required, not a
    // nicety. Without it, a perfectly good `credentials.toml` is never
    // read for a registry that says `auth-required` — which is what
    // this one says — and cargo says so in these words.
    let no_provider = cargo_home(&server, &root.join("no-provider"), Some(&reader));
    std::fs::write(
        no_provider.join("config.toml"),
        format!("[registries.acme]\nindex = \"{index}\"\n"),
    )
    .unwrap();
    let unread = cargo_err(&fresh, &no_provider, &["generate-lockfile"]);
    assert!(
        unread.contains("authenticated registries require a credential-provider to be configured"),
        "{unread}"
    );

    // A crate nobody published, and Cargo switched off, read the same
    // through the client: an absence, not an error about the registry.
    let ghost = root.join("ghost");
    consumer_src(
        &ghost,
        "acme-ghost = { version = \"1\", registry = \"acme\" }",
    );
    let absent = cargo_err(
        &ghost,
        &cargo_home(&server, &root.join("ghost"), Some(&reader)),
        &["generate-lockfile"],
    );
    assert!(
        absent.contains("no matching package named `acme-ghost` found"),
        "{absent}"
    );
    let switch = |mode: &str| {
        let (status, body) = server.req(
            "PUT",
            "/api/v1/ecosystems",
            &admin,
            Some(serde_json::json!({ "ecosystem": "cargo", "mode": mode })),
        );
        assert_eq!(status, 200, "{body}");
    };
    switch("off");
    let off = cargo_err(
        &fresh,
        &cargo_home(&server, &root.join("off"), Some(&reader)),
        &["generate-lockfile"],
    );
    assert!(
        off.contains("no matching package named `acme-widget` found"),
        "{off}"
    );
    switch("private");

    // Nothing the reader or the forger tried was published.
    let (_, listed) = server.get("/api/v1/packages?ecosystem=cargo", &admin);
    let mut names: Vec<&str> = listed["packages"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|p| p["name"].as_str().unwrap_or_default())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["acme-base", "acme-widget"], "{listed}");

    let _ = std::fs::remove_dir_all(root);
    assert!(server.healthy());
}
