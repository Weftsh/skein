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

/// Whether the docker **daemon** answers. `docker --version` is the
/// client alone, and a client with no daemon behind it can prove
/// nothing — so that is a NOTE too, or a failure where docker is
/// required.
fn docker_daemon_answers() -> bool {
    let up = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !up {
        let required = std::env::var("SKEIN_REQUIRE_CLIENTS")
            .unwrap_or_default()
            .split(',')
            .any(|c| c.trim() == "docker");
        assert!(
            !required,
            "docker is required here and its daemon does not answer"
        );
        eprintln!(
            "NOTE: the docker daemon does not answer; its contract is not checked by this run"
        );
    }
    up
}

/// `docker <args>` under one person's own `DOCKER_CONFIG`, so the
/// developer's real `~/.docker/config.json` cannot answer for us.
/// `(succeeded, everything it printed)`.
fn docker(config: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String) {
    use std::io::Write;
    let mut child = Command::new("docker")
        .args(args)
        .env("DOCKER_CONFIG", config)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn docker: {e}"));
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("docker");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// `docker` that must succeed.
fn docker_ok(config: &Path, args: &[&str]) -> String {
    let (ok, out) = docker(config, args, None);
    assert!(ok, "docker {args:?} failed:\n{out}");
    out
}

/// What this test put in the shared daemon, taken out again however it
/// ends: the daemon's storage is the machine's disk, and a test that
/// panicked half-way must not leave fifty megabytes of layers behind.
struct DockerLeftovers {
    config: std::path::PathBuf,
    images: Vec<String>,
    containers: Vec<String>,
}

impl Drop for DockerLeftovers {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = docker(&self.config, &["rm", "-f", c], None);
        }
        for i in &self.images {
            let _ = docker(&self.config, &["image", "rm", "-f", i], None);
        }
        let _ = docker(&self.config, &["builder", "prune", "-f"], None);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A pull that took every layer from the registry. One that found a
/// layer on the machine already says so, and has proved nothing about
/// that layer's trip through Skein.
fn fetched_every_layer(pull: &str) {
    assert!(
        !pull.contains("Already exists"),
        "the pull found layers on the machine rather than in the registry:\n{pull}"
    );
    assert!(pull.contains("Pull complete"), "{pull}");
}

/// The `sha256:…` that `docker push` printed for the tag it pushed.
fn pushed_digest(out: &str) -> String {
    let at = out
        .find("digest: sha256:")
        .unwrap_or_else(|| panic!("docker push printed no digest:\n{out}"));
    out[at + "digest: ".len()..at + "digest: ".len() + 71].to_string()
}

/// `docker login`, `build`, `push`, `pull` — by tag and by digest — and
/// the refusals a person actually reads in their terminal.
///
/// The image carries a layer larger than one block, of bytes that do not
/// compress, so the push really does go through the block path — and
/// that is checked, not assumed. What is asserted about the image is
/// what came back **through the client**: the digest `docker image
/// inspect` reports and the bytes `docker cp` takes out of a container.
#[test]
fn docker_pushes_and_pulls_through_skein() {
    if !have("docker") || !docker_daemon_answers() {
        return;
    }
    let bucket = Minio::shared().bucket("clients-docker");
    let server = common::spawn(&bucket.base_url, "clients-docker");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let host = server.host().to_string();

    let root = scratch("docker");
    let cfg = |who: &str| {
        let d = root.join(format!("docker-{who}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    };
    let (ci_cfg, reader_cfg, anon_cfg) = (cfg("ci"), cfg("reader"), cfg("anon"));
    let app = format!("{host}/team/app");
    let single = format!("{host}/app");
    let multi = format!("{host}/team/multi");
    let mut leftovers = DockerLeftovers {
        config: anon_cfg.clone(),
        images: vec![
            format!("{app}:1.0"),
            format!("{single}:1"),
            format!("{app}:reader"),
            format!("{multi}:1"),
        ],
        containers: Vec::new(),
    };

    // A layer bigger than one block, of bytes gzip cannot shrink below
    // it, and a small one beside it.
    let mut big = Vec::with_capacity(24 * 1024 * 1024 + 12_345);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ u64::from(std::process::id());
    while big.len() < 24 * 1024 * 1024 + 12_345 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        big.extend_from_slice(&x.to_le_bytes());
    }
    let ctx = root.join("context");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(ctx.join("big.bin"), &big).unwrap();
    std::fs::write(ctx.join("hello.txt"), "hello from skein\n").unwrap();
    std::fs::write(
        ctx.join("Dockerfile"),
        "FROM scratch\nCOPY big.bin /big.bin\nCOPY hello.txt /hello.txt\nCMD [\"/nothing\"]\n",
    )
    .unwrap();

    // Logged in exactly the way the UI's Connect page says to.
    let (ok, out) = docker(
        &ci_cfg,
        &["login", &host, "--username", "skein", "--password-stdin"],
        Some(&format!("{ci}\n")),
    );
    assert!(ok, "docker login failed:\n{out}");
    assert!(out.contains("Login Succeeded"), "{out}");
    // A token that is not one is refused at login, not at first push.
    let (ok, out) = docker(
        &anon_cfg,
        &["login", &host, "--username", "skein", "--password-stdin"],
        Some("skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret\n"),
    );
    assert!(!ok, "docker login accepted a forged token:\n{out}");
    assert!(
        out.contains("401") || out.to_lowercase().contains("unauthorized"),
        "{out}"
    );

    docker_ok(
        &ci_cfg,
        &[
            "build",
            // One platform manifest, and no attestation manifests beside
            // it: whichever image store the daemon uses, what is pushed
            // is an image `docker manifest create` can name.
            "--provenance=false",
            "-t",
            &format!("{app}:1.0"),
            "-t",
            &format!("{single}:1"),
            ctx.to_str().unwrap(),
        ],
    );
    let out = docker_ok(&ci_cfg, &["push", &format!("{app}:1.0")]);
    let digest = pushed_digest(&out);

    // The block path really ran: a layer of the pushed image is more
    // than one block in the database.
    let mut pg = postgres::Client::connect(&server.db_url, postgres::NoTls).expect("connect");
    let most: i64 = pg
        .query_one(
            "SELECT COALESCE(MAX(n), 0) FROM \
             (SELECT COUNT(*) AS n FROM package_blocks GROUP BY digest) AS per_blob",
            &[],
        )
        .expect("count blocks")
        .get(0);
    assert!(
        most >= 2,
        "no layer went through the block path, so this run proved nothing about it"
    );

    // The same image under a one-component name. Its layers are already
    // here, and docker is told so rather than sending them again.
    let out = docker_ok(&ci_cfg, &["push", &format!("{single}:1")]);
    assert!(
        out.contains("already exists") || out.contains("Mounted from"),
        "docker sent layers the registry already holds:\n{out}"
    );
    assert_eq!(pushed_digest(&out), digest);

    // Gone from the machine, then back through the registry — as the
    // reader, who may pull. The build cache goes too: it holds the
    // layers, and a pull that finds them there says "Already exists"
    // and takes nothing from the registry but the manifest and config.
    for i in [format!("{app}:1.0"), format!("{single}:1")] {
        docker_ok(&ci_cfg, &["image", "rm", &i]);
    }
    docker_ok(&ci_cfg, &["builder", "prune", "-f"]);
    let (ok, out) = docker(
        &reader_cfg,
        &["login", &host, "--username", "skein", "--password-stdin"],
        Some(&format!("{reader}\n")),
    );
    assert!(ok, "the reader's docker login failed:\n{out}");
    let pulled = docker_ok(&reader_cfg, &["pull", &format!("{app}:1.0")]);
    fetched_every_layer(&pulled);
    let repo_digests = docker_ok(
        &reader_cfg,
        &[
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            &format!("{app}:1.0"),
        ],
    );
    assert!(
        repo_digests.contains(&format!("{app}@{digest}")),
        "what came back is not what was pushed: {repo_digests} (pushed {digest})"
    );

    // The bytes, out of a container made from what was pulled.
    let check_files = |image: &str, leftovers: &mut DockerLeftovers| {
        let id = docker_ok(&reader_cfg, &["create", image])
            .trim()
            .to_string();
        leftovers.containers.push(id.clone());
        let out_dir = root.join(format!("out-{}", leftovers.containers.len()));
        std::fs::create_dir_all(&out_dir).unwrap();
        for f in ["big.bin", "hello.txt"] {
            docker_ok(
                &reader_cfg,
                &[
                    "cp",
                    &format!("{id}:/{f}"),
                    out_dir.join(f).to_str().unwrap(),
                ],
            );
        }
        let got = std::fs::read(out_dir.join("big.bin")).unwrap();
        assert_eq!(
            got.len(),
            big.len(),
            "{image}: big.bin came back a different length"
        );
        assert_eq!(
            sha256_hex(&got),
            sha256_hex(&big),
            "{image}: big.bin came back different"
        );
        assert_eq!(
            std::fs::read_to_string(out_dir.join("hello.txt")).unwrap(),
            "hello from skein\n"
        );
        docker_ok(&reader_cfg, &["rm", &id]);
    };
    check_files(&format!("{app}:1.0"), &mut leftovers);

    // By digest, which is what a deployment should pin.
    docker_ok(&reader_cfg, &["image", "rm", &format!("{app}:1.0")]);
    let by_digest = format!("{app}@{digest}");
    leftovers.images.push(by_digest.clone());
    fetched_every_layer(&docker_ok(&reader_cfg, &["pull", &by_digest]));
    check_files(&by_digest, &mut leftovers);

    // A reader's push is refused, and docker shows the reason.
    docker_ok(&reader_cfg, &["tag", &by_digest, &format!("{app}:reader")]);
    let (ok, out) = docker(&reader_cfg, &["push", &format!("{app}:reader")], None);
    assert!(!ok, "a reader pushed:\n{out}");
    assert!(out.contains("denied"), "{out}");
    assert!(
        out.contains("rita is a reader"),
        "docker did not show the reason:\n{out}"
    );

    // Nobody at all is challenged, and told so.
    // Off the machine, so the pull below has to ask the registry.
    // Untagging the last tag took the digest reference with it.
    docker_ok(&reader_cfg, &["image", "rm", &format!("{app}:reader")]);
    if docker(&reader_cfg, &["image", "inspect", &by_digest], None).0 {
        docker_ok(&reader_cfg, &["image", "rm", &by_digest]);
    }
    let (ok, out) = docker(&anon_cfg, &["pull", &format!("{app}:1.0")], None);
    assert!(!ok, "an anonymous pull succeeded:\n{out}");
    assert!(
        out.contains("no basic auth credentials")
            || out.to_lowercase().contains("unauthorized")
            || out.contains("401"),
        "{out}"
    );

    // A multi-platform index assembled in another repository, the way
    // `docker manifest` does it: every blob mounted across, the platform
    // manifest pushed by digest with no tag of its own, the index by
    // tag.
    let (ok, out) = docker(
        &ci_cfg,
        &[
            "manifest",
            "create",
            "--insecure",
            &format!("{multi}:1"),
            &format!("{app}:1.0"),
        ],
        None,
    );
    assert!(ok, "docker manifest create failed:\n{out}");
    let (ok, out) = docker(
        &ci_cfg,
        &["manifest", "push", "--insecure", &format!("{multi}:1")],
        None,
    );
    assert!(ok, "docker manifest push failed:\n{out}");

    // Then the repository the index was built from goes, so the index
    // is the only thing left that needs those layers — and the collector
    // runs with no grace at all.
    let (_, listed) = server.get("/api/v1/packages?ecosystem=oci", &admin);
    for gone in ["team/app", "app"] {
        let id = listed["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == gone)
            .and_then(|p| p["id"].as_str())
            .unwrap_or_else(|| panic!("no repository {gone}: {listed}"))
            .to_string();
        let (status, body) = server.req("DELETE", &format!("/api/v1/packages/{id}"), &admin, None);
        assert_eq!(status, 204, "{body}");
    }
    let swept = server
        .admin(&["admin", "gc", "--grace-secs", "0"])
        .expect("admin gc");
    let swept: serde_json::Value = serde_json::from_str(swept.trim()).expect("json");
    assert!(swept["blobs"].is_u64(), "{swept}");
    fetched_every_layer(&docker_ok(&reader_cfg, &["pull", &format!("{multi}:1")]));
    check_files(&format!("{multi}:1"), &mut leftovers);

    drop(leftovers);
    let _ = std::fs::remove_dir_all(&root);
    assert!(server.healthy());
}
