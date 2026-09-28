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
