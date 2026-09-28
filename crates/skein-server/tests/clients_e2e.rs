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

    // `npm whoami` and `npm ping`, which is what somebody runs first to
    // check a new `.npmrc`.
    let who = run(
        &consumer,
        "npm",
        &["whoami", "--registry", &format!("{}/npm/", server.base)],
        &cenv,
    );
    assert_eq!(who.trim(), "rita");
    run(
        &consumer,
        "npm",
        &["ping", "--registry", &format!("{}/npm/", server.base)],
        &cenv,
    );

    // `npm login` with a username and password, through a terminal —
    // npm will not read a password from anything else.
    npm_login_through_a_terminal(&server, &admin);

    for d in [src, consumer, pubdir, anon] {
        let _ = std::fs::remove_dir_all(d);
    }
    assert!(server.healthy());
}

/// Drive `npm login`, `npm whoami` and `npm logout` through a
/// pseudo-terminal, because npm's password prompt refuses a pipe. The
/// terminal is python's `pty`; without python3 this part is a NOTE.
fn npm_login_through_a_terminal(server: &Server, admin: &str) {
    if !have("python3") {
        return;
    }
    let (status, _) = server.req(
        "POST",
        "/api/v1/users",
        admin,
        Some(serde_json::json!({ "username": "lena", "role": "publisher", "password": "lena's long password" })),
    );
    assert_eq!(status, 201);
    let home = scratch("npm-login");
    let registry = format!("{}/npm/", server.base);
    std::fs::write(home.join(".npmrc"), format!("registry={registry}\n")).unwrap();
    const DRIVER: &str = r#"
import os, pty, re, select, sys
home, registry, user, password = sys.argv[1:5]
env = dict(os.environ, HOME=home, npm_config_userconfig=home + "/.npmrc",
           npm_config_update_notifier="false")
def npm(*args, answers=()):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("npm", ["npm", *args, "--registry", registry], env)
    out, answers = b"", list(answers)
    while True:
        r, _, _ = select.select([fd], [], [], 60)
        if not r:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        tail = out[-40:]
        if answers and ((len(answers) == 2 and b"Username:" in tail) or (len(answers) == 1 and b"Password:" in tail)):
            os.write(fd, (answers.pop(0) + "\n").encode())
    _, code = os.waitpid(pid, 0)
    return code, out.decode(errors="replace")
code, out = npm("login", answers=(user, password))
print("LOGIN", code, "Logged in" in out)
print("TOKEN", "_authToken" in open(home + "/.npmrc").read())
code, out = npm("whoami")
lines = [re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", l).strip() for l in out.splitlines()]
print("WHOAMI", code, user if user in lines else repr(lines))
code, out = npm("logout")
print("LOGOUT", code, "_authToken" in open(home + "/.npmrc").read())
"#;
    let out = run(
        &home,
        "python3",
        &[
            "-c",
            DRIVER,
            &home.display().to_string(),
            &registry,
            "lena",
            "lena's long password",
        ],
        &[],
    );
    assert!(out.contains("LOGIN 0 True"), "npm login failed:\n{out}");
    assert!(
        out.contains("TOKEN True"),
        "npm did not save the token:\n{out}"
    );
    assert!(
        out.contains("WHOAMI 0 lena"),
        "npm whoami did not say lena:\n{out}"
    );
    assert!(
        out.contains("LOGOUT 0 False"),
        "npm logout left the token behind:\n{out}"
    );
    // …and the token it removed is revoked here, not just forgotten there.
    let (_, tokens) = server.get("/api/v1/tokens", admin);
    assert!(
        !tokens["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["username"] == "lena"),
        "npm logout left a live token: {tokens}"
    );
    let _ = std::fs::remove_dir_all(home);
}

/// A `settings.xml` in the shape the Connect page hands out — a
/// `<server>` carrying the token and a `<repository>` in an always-active
/// profile, beside Maven Central rather than a mirror of it — so what
/// passes here is the configuration people are told to write.
///
/// One addition to what the page gives, and it only makes this stricter:
/// `<checksumPolicy>fail</checksumPolicy>`. Maven's default is `warn`,
/// under which a checksum that disagrees with its file is a line in the
/// log and the build goes on — and this test would pass against a
/// registry serving the wrong digest. `token: None` leaves the `<server>`
/// out, which is a person who never configured one.
fn maven_settings(dir: &Path, repo: &str, token: Option<&str>) -> std::path::PathBuf {
    let server = token
        .map(|t| {
            format!(
                "<servers><server><id>skein</id><username>skein</username>\
                 <password>{t}</password></server></servers>"
            )
        })
        .unwrap_or_default();
    let path = dir.join("settings.xml");
    std::fs::write(
        &path,
        format!(
            r#"<settings>
  {server}
  <profiles>
    <profile>
      <id>skein</id>
      <repositories>
        <repository>
          <id>skein</id>
          <url>{repo}</url>
          <releases><enabled>true</enabled><checksumPolicy>fail</checksumPolicy></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles><activeProfile>skein</activeProfile></activeProfiles>
</settings>
"#
        ),
    )
    .unwrap();
    path
}

/// A one-class jar project at `version`. `deploy_to` writes a
/// `distributionManagement` naming the registry — the other way the docs
/// give of pointing `mvn deploy` at it.
fn maven_widget(dir: &Path, version: &str, deploy_to: Option<&str>) {
    let dist = deploy_to
        .map(|url| {
            format!(
                "<distributionManagement><repository><id>skein</id><url>{url}</url>\
                 </repository></distributionManagement>"
            )
        })
        .unwrap_or_default();
    std::fs::write(
        dir.join("pom.xml"),
        format!(
            r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>sh.skein.clients</groupId>
  <artifactId>widget</artifactId>
  <version>{version}</version>
  <packaging>jar</packaging>
  <licenses>
    <license><name>Apache License, Version 2.0</name></license>
  </licenses>
  <properties>
    <maven.compiler.release>11</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  {dist}
</project>
"#
        ),
    )
    .unwrap();
    let src = dir.join("src/main/java/sh/skein/clients");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("Widget.java"),
        format!(
            "package sh.skein.clients;\n\
             public class Widget {{ public static String version() {{ return \"widget {version}\"; }} }}\n"
        ),
    )
    .unwrap();
}

/// A project that depends on the widget at `spec` and calls into it, so
/// resolving is not enough: the jar that came back has to compile
/// against and run.
fn maven_consumer(dir: &Path, spec: &str) {
    std::fs::write(
        dir.join("pom.xml"),
        format!(
            r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>sh.skein.clients</groupId>
  <artifactId>consumer</artifactId>
  <version>0.0.0</version>
  <properties>
    <maven.compiler.release>11</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>sh.skein.clients</groupId>
      <artifactId>widget</artifactId>
      <version>{spec}</version>
    </dependency>
  </dependencies>
</project>
"#
        ),
    )
    .unwrap();
    let src = dir.join("src/main/java");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("Consumer.java"),
        "public class Consumer { public static void main(String[] a) { \
         System.out.println(sh.skein.clients.Widget.version()); } }\n",
    )
    .unwrap();
}

/// Removes a scratch tree however the test ends. A Maven run leaves a
/// local repository of plugins behind — tens of megabytes a run — and a
/// red run is exactly the one that would otherwise leak it.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The line of Maven's output that carries a refusal, printed so a CI
/// log shows exactly what a person would have read.
fn maven_says(what: &str, out: &str) {
    let line = out
        .lines()
        .find(|l| l.contains("status code:"))
        .unwrap_or("(no status line in the output)");
    eprintln!("mvn, {what}: {line}");
}

/// `mvn deploy` of a real jar project, twice over, and a build that
/// resolves it from an empty local repository through a version range —
/// which makes Maven read the `maven-metadata.xml` this registry
/// generates, and its checksum, with its own parser.
///
/// And the refusals, as Maven prints them. Maven never shows a response
/// body — only `status code: N, reason phrase: …` — so each of these
/// asserts on the *sentence*, which is the proof that it travels in the
/// status line. The first run of this test found every one of them
/// reduced to a bare `Forbidden (403)`.
#[test]
fn mvn_deploys_and_resolves_through_skein() {
    if !have("mvn") {
        return;
    }
    let bucket = Minio::shared().bucket("clients-maven");
    let server = common::spawn(&bucket.base_url, "clients-maven");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let repo = format!("{}/maven/", server.base);

    // Every run gets a home of its own, so the developer's real
    // `~/.m2/settings.xml` cannot answer for us, and every `mvn` names
    // its local repository on the command line.
    let root = Scratch(scratch("maven"));
    let root = root.0.as_path();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home_s = home.display().to_string();
    let env = [("HOME", home_s.as_str())];
    let mvn = |dir: &Path, settings: &Path, local: &Path, args: &[&str], ok: bool| {
        let s = settings.display().to_string();
        let l = format!("-Dmaven.repo.local={}", local.display());
        let mut all = vec!["-B", "-ntp", "-s", s.as_str(), l.as_str()];
        all.extend_from_slice(args);
        if ok {
            run(dir, "mvn", &all, &env)
        } else {
            run_err(dir, "mvn", &all, &env)
        }
    };
    let dir = |name: &str| {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    };

    // The publisher: the CI service account, deploying 1.0.0 the way the
    // Connect page says, with nothing about the registry in the POM.
    let publisher = dir("publisher");
    let ci_settings = maven_settings(&dir("ci"), &repo, Some(&ci));
    let deploy_repo = root.join("deploy-repo");
    let alt = format!("-DaltDeploymentRepository=skein::{repo}");
    maven_widget(&publisher, "1.0.0", None);
    mvn(
        &publisher,
        &ci_settings,
        &deploy_repo,
        &["deploy", &alt],
        true,
    );

    // Deploying the same version again is refused, and Maven prints why.
    let again = mvn(
        &publisher,
        &ci_settings,
        &deploy_repo,
        &["deploy", &alt],
        false,
    );
    maven_says("a redeploy", &again);
    assert!(again.contains("status code: 409"), "{again}");
    assert!(
        again.contains("is already deployed at sh.skein.clients:widget 1.0.0")
            && again.contains("a published file never changes here"),
        "Maven did not show why the redeploy was refused:\n{again}"
    );

    // 1.1.0, deployed through the POM's own `distributionManagement`.
    // The second version of an artifact is where Maven first reads our
    // `maven-metadata.xml`, merges its own version into it, and uploads
    // the result.
    maven_widget(&publisher, "1.1.0", Some(&repo));
    mvn(&publisher, &ci_settings, &deploy_repo, &["deploy"], true);
    let built = std::fs::read(publisher.join("target/widget-1.1.0.jar")).expect("the built jar");

    // A reader resolves `[1.0,2.0)` into an EMPTY local repository — so
    // nothing is answered from the cache the deploys filled — compiles
    // against it, and runs it.
    let consumer = dir("consumer");
    maven_consumer(&consumer, "[1.0,2.0)");
    let reader_settings = maven_settings(&dir("reader"), &repo, Some(&reader));
    let fresh = root.join("fresh-repo");
    assert!(!fresh.exists());
    mvn(&consumer, &reader_settings, &fresh, &["compile"], true);
    let widget = fresh.join("sh/skein/clients/widget");
    let got = std::fs::read(widget.join("1.1.0/widget-1.1.0.jar"))
        .unwrap_or_else(|e| panic!("Maven did not resolve 1.1.0 through the range: {e}"));
    assert_eq!(got, built, "the jar Maven resolved is not the one deployed");
    let remote = std::fs::read_to_string(widget.join("1.1.0/_remote.repositories")).unwrap();
    assert!(
        remote.contains("widget-1.1.0.jar>skein="),
        "the jar did not come from the skein repository: {remote}"
    );
    // The range was decided by our metadata, and its checksum passed
    // under `checksumPolicy=fail`: Maven keeps both, named for the
    // repository they came from.
    let metadata = std::fs::read_to_string(widget.join("maven-metadata-skein.xml"))
        .expect("Maven never read the generated maven-metadata.xml");
    assert!(metadata.contains("<version>1.0.0</version>"), "{metadata}");
    assert!(metadata.contains("<release>1.1.0</release>"), "{metadata}");
    assert!(widget.join("maven-metadata-skein.xml.sha1").exists());
    // Maven reads every POM in a range to build the graph, and fetches
    // the jar only of the version it picked.
    assert!(
        !widget.join("1.0.0/widget-1.0.0.jar").exists(),
        "the range resolved to something other than the newest release"
    );
    let cp = format!(
        "{}:{}",
        consumer.join("target/classes").display(),
        widget.join("1.1.0/widget-1.1.0.jar").display()
    );
    let out = run(&consumer, "java", &["-cp", &cp, "Consumer"], &env);
    assert_eq!(out.trim(), "widget 1.1.0");

    // The reader cannot deploy, and Maven prints the reason.
    let rpub = dir("reader-publisher");
    maven_widget(&rpub, "9.9.9", Some(&repo));
    let refused = mvn(&rpub, &reader_settings, &deploy_repo, &["deploy"], false);
    maven_says("a reader deploying", &refused);
    assert!(refused.contains("status code: 403"), "{refused}");
    assert!(
        refused.contains("rita is a reader here, and a reader may not publish"),
        "Maven did not show why the reader was refused:\n{refused}"
    );

    // A SNAPSHOT is refused, and the reason is the sentence rather than
    // the status: the output names `2.0.0-SNAPSHOT` either way, so
    // "snapshot" alone would be found in any failure at all.
    let snap = dir("snapshot");
    maven_widget(&snap, "2.0.0-SNAPSHOT", None);
    let refused = mvn(&snap, &ci_settings, &deploy_repo, &["deploy", &alt], false);
    maven_says("a SNAPSHOT", &refused);
    assert!(refused.contains("status code: 400"), "{refused}");
    assert!(
        refused.contains("this registry does not hold snapshots"),
        "Maven did not show why the SNAPSHOT was refused:\n{refused}"
    );

    // Without a credential Maven is challenged, and fails on it rather
    // than reporting the artifact absent.
    let anon_settings = maven_settings(&dir("anon"), &repo, None);
    let anon_consumer = dir("anon-consumer");
    maven_consumer(&anon_consumer, "1.1.0");
    std::fs::remove_dir_all(fresh.join("sh/skein")).unwrap();
    let denied = mvn(&anon_consumer, &anon_settings, &fresh, &["compile"], false);
    maven_says("no credential", &denied);
    assert!(denied.contains("status code: 401"), "{denied}");

    assert!(server.healthy());
}

// ---------------------------------------------------------------- PyPI

/// The Python whose environment holds twine, `build` and setuptools:
/// `SKEIN_PYTHON`, or `python3` on the PATH. twine runs as
/// `<python> -m twine`, which is the same entry point as the `twine`
/// script, so a twine installed in a virtualenv is found by pointing
/// `SKEIN_PYTHON` at that virtualenv's `python`.
fn python() -> String {
    std::env::var("SKEIN_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// Whether a Python client can run here — `<python> <check…>` succeeds.
/// Missing is a NOTE, or a failure when `SKEIN_REQUIRE_CLIENTS` names
/// it, exactly as [`have`] does for a client on the PATH.
fn have_python(client: &str, check: &[&str], what: &str) -> bool {
    let py = python();
    let found = Command::new(&py)
        .args(check)
        .output()
        .is_ok_and(|o| o.status.success());
    let required = std::env::var("SKEIN_REQUIRE_CLIENTS")
        .unwrap_or_default()
        .split(',')
        .any(|c| c.trim() == client);
    if !found {
        assert!(
            !required,
            "{client} is required here and {what} is not installed for {py} \
             (set SKEIN_PYTHON to a Python that has it)"
        );
        eprintln!(
            "NOTE: {what} is not installed for {py}; the {client} contract is not checked \
             by this run (set SKEIN_PYTHON to a Python that has it)"
        );
    }
    found
}

/// Whitespace collapsed, so an assertion on a sentence does not depend
/// on where a terminal renderer chose to wrap it.
fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A tiny project, `acme-widget` at `version`, built into `dist/` by
/// PyPA's own `build` — an sdist and a wheel, exactly what a person
/// uploads. No build isolation: an isolated build would fetch
/// setuptools from pypi.org, and nothing here leaves the machine except
/// through the client under test.
fn python_project(name: &str, version: &str, dists: &[&str]) -> std::path::PathBuf {
    let src = scratch(name);
    std::fs::write(
        src.join("pyproject.toml"),
        format!(
            "[build-system]\nrequires = [\"setuptools>=77\"]\n\
             build-backend = \"setuptools.build_meta\"\n\n\
             [project]\nname = \"acme-widget\"\nversion = \"{version}\"\n\
             description = \"a widget\"\nlicense = \"MIT\"\n\
             requires-python = \">=3.8\"\n\n\
             [tool.setuptools]\npackages = [\"acme_widget\"]\n"
        ),
    )
    .unwrap();
    std::fs::create_dir_all(src.join("acme_widget")).unwrap();
    std::fs::write(
        src.join("acme_widget/__init__.py"),
        format!("def hello():\n    return \"widget {version}\"\n"),
    )
    .unwrap();
    let mut args = vec!["-m", "build", "--no-isolation", "--outdir", "dist"];
    args.extend_from_slice(dists);
    args.push(".");
    run(&src, &python(), &args, &[]);
    src
}

/// The files `build` wrote, sorted.
fn dists(src: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(src.join("dist"))
        .unwrap()
        .map(|e| e.unwrap().path().display().to_string())
        .collect();
    out.sort();
    out
}

/// A `.pypirc` that is, byte for byte, the one **Connect a client**
/// shows for twine — so the configuration a person copies out of the UI
/// is the configuration proved here — and the environment twine runs
/// in: its own home, no keyring, no colour, no progress bar.
fn twine_env(server: &Server, dir: &Path, token: &str) -> (String, Vec<(String, String)>) {
    let rc = dir.join(".pypirc");
    std::fs::write(
        &rc,
        format!(
            "[distutils]\nindex-servers = skein\n\n[skein]\nrepository = {}/pypi/\n\
             username = __token__\npassword = {token}",
            server.base
        ),
    )
    .unwrap();
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    (
        rc.display().to_string(),
        vec![
            ("HOME".into(), home.display().to_string()),
            (
                "PYTHON_KEYRING_BACKEND".into(),
                "keyring.backends.null.Keyring".into(),
            ),
            ("NO_COLOR".into(), "1".into()),
            ("TERM".into(), "dumb".into()),
            ("COLUMNS".into(), "400".into()),
        ],
    )
}

fn twine_upload(rc: &str, files: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "-m",
        "twine",
        "upload",
        "--repository",
        "skein",
        "--config-file",
        rc,
        "--non-interactive",
        "--disable-progress-bar",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(files.iter().cloned());
    args
}

/// A `pip.conf` that is, byte for byte, the one **Connect a client**
/// shows — `index-url`, the token in the URL — and an environment in
/// which nothing of the developer's own pip configuration, cache or
/// keyring can answer for us.
fn pip_env(dir: &Path, index_url: &str) -> Vec<(String, String)> {
    let conf = dir.join("pip.conf");
    std::fs::write(&conf, format!("[global]\nindex-url = {index_url}")).unwrap();
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    vec![
        ("HOME".into(), home.display().to_string()),
        ("PIP_CONFIG_FILE".into(), conf.display().to_string()),
        ("PIP_NO_CACHE_DIR".into(), "1".into()),
        ("PIP_DISABLE_PIP_VERSION_CHECK".into(), "1".into()),
        ("PIP_NO_INPUT".into(), "1".into()),
        ("PIP_KEYRING_PROVIDER".into(), "disabled".into()),
        // Whatever the calling shell points pip at is not ours.
        ("PIP_INDEX_URL".into(), index_url.into()),
        ("PIP_EXTRA_INDEX_URL".into(), String::new()),
        ("PIP_FIND_LINKS".into(), String::new()),
        ("NO_COLOR".into(), "1".into()),
    ]
}

fn borrow(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// `twine upload` an sdist and a wheel, `pip install` from the simple
/// index into a fresh virtualenv, and the refusals a person actually
/// reads in their terminal — through the real clients, configured the
/// way **Connect a client** tells people to configure them.
#[test]
fn twine_uploads_and_pip_installs_through_skein() {
    // Both, or neither: an upload nobody installs proves a row was
    // written, and an install needs something uploaded.
    let twine = have_python(
        "twine",
        &["-c", "import twine, build, setuptools"],
        "twine (with build and setuptools)",
    ) && have_python("twine", &["-m", "twine", "--version"], "twine");
    let pip = have_python(
        "pip",
        &["-c", "import venv, ensurepip, pip"],
        "pip (with venv)",
    );
    if !(twine && pip) {
        // A required client whose partner is missing has not been
        // checked either, and a requirement is not met by a NOTE.
        let required = std::env::var("SKEIN_REQUIRE_CLIENTS").unwrap_or_default();
        for client in ["twine", "pip"] {
            assert!(
                !required.split(',').any(|c| c.trim() == client),
                "{client} is required here, and twine and pip are checked together"
            );
        }
        if twine != pip {
            eprintln!("NOTE: twine and pip are checked together; neither is checked by this run");
        }
        return;
    }
    let py = python();
    let bucket = Minio::shared().bucket("clients-pypi");
    let server = common::spawn(&bucket.base_url, "clients-pypi");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);

    // 1.2.3, an sdist and a wheel, uploaded by the CI service account.
    let v123 = python_project("pypi-src-123", "1.2.3", &["--sdist", "--wheel"]);
    let files = dists(&v123);
    assert_eq!(
        files.len(),
        2,
        "build did not write an sdist and a wheel: {files:?}"
    );
    let (rc, env) = twine_env(&server, &v123, &ci);
    let env = borrow(&env);
    let out = run(&v123, &py, &borrow_args(&twine_upload(&rc, &files)), &env);
    for f in &files {
        let base = Path::new(f).file_name().unwrap().to_string_lossy();
        assert!(out.contains(&*base), "twine did not upload {base}: {out}");
    }

    // Uploading the same files again is refused, and twine says why.
    let again = flat(&run_err(
        &v123,
        &py,
        &borrow_args(&twine_upload(&rc, &files)),
        &env,
    ));
    assert!(again.contains("409"), "{again}");
    assert!(
        again.contains("is already uploaded for acme-widget"),
        "twine did not show the reason: {again}"
    );

    // A reader cannot publish, and twine's own output says why — not
    // just "403 Forbidden".
    let v130 = python_project("pypi-src-130", "1.3.0", &["--wheel"]);
    let wheel130 = dists(&v130);
    let (rrc, renv) = twine_env(&server, &v130, &reader);
    let refused = flat(&run_err(
        &v130,
        &py,
        &borrow_args(&twine_upload(&rrc, &wheel130)),
        &borrow(&renv),
    ));
    assert!(refused.contains("403"), "{refused}");
    assert!(
        refused.contains("rita is a reader here, and a reader may not publish to this registry"),
        "twine did not show the reason: {refused}"
    );

    // The publisher uploads 1.3.0, and an admin yanks it.
    let (crc, cenv) = twine_env(&server, &v130, &ci);
    run(
        &v130,
        &py,
        &borrow_args(&twine_upload(&crc, &wheel130)),
        &borrow(&cenv),
    );
    let (_, listed) = server.get("/api/v1/packages?ecosystem=pypi", &admin);
    let id = listed["packages"][0]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let (status, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(status, 200, "{shown}");
    // The licence twine sent is PEP 639's `license_expression`, read as
    // the real client sends it rather than as we believe it does.
    for v in shown["versions"].as_array().unwrap() {
        assert_eq!(v["license"], "MIT", "{v}");
        assert_eq!(v["license_source"], "declared", "{v}");
        assert_eq!(v["published_by_username"], "ci", "{v}");
    }
    let (status, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/1.3.0/yank"),
        &admin,
        Some(serde_json::json!({ "yanked": true, "reason": "yanked on purpose" })),
    );
    assert_eq!(status, 200, "{body}");

    // A reader installs into a fresh virtualenv with the UI's pip.conf.
    let consumer = scratch("pypi-consumer");
    let venv = consumer.join("venv");
    run(
        &consumer,
        &py,
        &["-m", "venv", &venv.display().to_string()],
        &[],
    );
    let vpip = venv.join("bin/pip").display().to_string();
    let vpy = venv.join("bin/python").display().to_string();
    let index = format!(
        "{}/pypi/simple/",
        server.base.replace("://", &format!("://skein:{reader}@"))
    );
    let penv = pip_env(&consumer, &index);
    let penv = borrow(&penv);

    // Unpinned, pip passes over the yanked 1.3.0 for 1.2.3, and takes
    // the wheel — its digest checked against the index's fragment by
    // pip itself.
    run(&consumer, &vpip, &["install", "acme-widget"], &penv);
    let hello = run(
        &consumer,
        &vpy,
        &["-c", "import acme_widget; print(acme_widget.hello())"],
        &penv,
    );
    assert_eq!(hello, "widget 1.2.3\n", "pip installed the yanked release");
    let show = run(&consumer, &vpip, &["show", "acme-widget"], &penv);
    for want in ["Name: acme-widget", "Version: 1.2.3", "Summary: a widget"] {
        assert!(show.contains(want), "{want:?} not in {show}");
    }

    // Pinned, the yanked release still installs — with pip's warning
    // carrying the reason the admin gave.
    let pinned = Command::new(&vpip)
        .args(["install", "acme-widget==1.3.0"])
        .current_dir(&consumer)
        .envs(penv.iter().copied())
        .output()
        .unwrap();
    let said = flat(&format!(
        "{}{}",
        String::from_utf8_lossy(&pinned.stdout),
        String::from_utf8_lossy(&pinned.stderr)
    ));
    assert!(pinned.status.success(), "{said}");
    assert!(
        said.contains("yanked"),
        "pip did not say 1.3.0 is yanked: {said}"
    );
    assert!(said.contains("yanked on purpose"), "{said}");
    let hello = run(
        &consumer,
        &vpy,
        &["-c", "import acme_widget; print(acme_widget.hello())"],
        &penv,
    );
    assert_eq!(hello, "widget 1.3.0\n");

    // The sdist, fetched by pip from the link the index gives it, is
    // byte for byte what twine uploaded. `pip download` prepares the
    // sdist's metadata, which needs setuptools; the builder's Python has
    // it, so this is that Python's pip, with the same configuration.
    let dl = consumer.join("dl");
    run(
        &consumer,
        &py,
        &[
            "-m",
            "pip",
            "download",
            "--no-deps",
            "--no-binary",
            ":all:",
            "--no-build-isolation",
            "--dest",
            &dl.display().to_string(),
            "acme-widget==1.2.3",
        ],
        &penv,
    );
    let sdist = files
        .iter()
        .find(|f| f.ends_with(".tar.gz"))
        .expect("an sdist");
    let name = Path::new(sdist).file_name().unwrap();
    assert_eq!(
        std::fs::read(dl.join(name)).expect("pip downloaded the sdist"),
        std::fs::read(sdist).unwrap(),
        "the sdist pip fetched is not the one twine uploaded"
    );

    // Without credentials pip is challenged rather than handed an empty
    // page. What pip makes of the challenge is its own business, and
    // the real client differs from the obvious belief: interactively it
    // prompts for a username, and with `--no-input` it logs an index it
    // could not read only at debug level, so the person sees "No
    // matching distribution found" and the 401 — with its reason
    // phrase, as ever — appears only under `-vv`.
    let anon = scratch("pypi-anon");
    let aenv = pip_env(&anon, &format!("{}/pypi/simple/", server.base));
    let denied = flat(&run_err(
        &anon,
        &vpip,
        &[
            "download",
            "-vv",
            "--no-deps",
            "--dest",
            "dl",
            "acme-widget",
        ],
        &borrow(&aenv),
    ));
    assert!(denied.contains("401 Client Error"), "{denied}");
    // pip makes `--dest` before it asks anybody anything; empty is the
    // claim.
    let fetched = std::fs::read_dir(anon.join("dl"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(fetched, 0, "pip fetched something: {denied}");

    for d in [v123, v130, consumer, anon] {
        let _ = std::fs::remove_dir_all(d);
    }
    assert!(server.healthy());
}

fn borrow_args(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
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
    // How docker words a registry's DENIED depends on its image store:
    // the classic one prints `denied: <message>`, the containerd store —
    // the default for a fresh Docker 29 install — `error from registry:
    // <message>`. Either way the sentence is what reaches the person.
    assert!(
        out.contains("denied") || out.contains("error from registry"),
        "{out}"
    );
    assert!(
        out.contains("rita is a reader here, and a reader may not push"),
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
