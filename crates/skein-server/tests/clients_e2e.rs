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
