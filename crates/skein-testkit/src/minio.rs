//! Shared MinIO instance for tests: one server per test process, one
//! uniquely-named bucket per test.
//!
//! Resolution order, and the first entry is the one that matters on a
//! machine that is not Linux:
//!
//!   1. `$SKEIN_MINIO_URL` — an S3 endpoint that is **already running**,
//!      which the harness uses as-is and never spawns or kills. This is
//!      how a developer runs the Rust suites from a MinIO in Docker.
//!   2. `$MINIO_BIN` → `minio` on PATH → `.testkit/bin/minio` at the
//!      workspace root, spawned per test process. CI pre-populates that
//!      path so test runs stay network-free.
//!
//! **MinIO no longer publishes prebuilt binaries.** `dl.min.io`, which
//! this used to download from, answers `410 Gone` for every platform of
//! the pinned release, and the GitHub release carries no assets — the
//! same withdrawal that took `minio/minio` and `minio/mc` off Docker Hub
//! and moved `deploy/compose.yml` to quay.io. The container image is the
//! only artifact still published, so that is where the binary comes from
//! now: extracted from `quay.io/minio/minio:<pin>`, the same registry and
//! the same pin.
//!
//! That works where the test host matches the image — Linux, which is
//! CI. It cannot work on macOS, where the image's binary is an ELF that
//! will not execute. There is no darwin binary left to fetch anywhere, so
//! on a Mac the answer is (1): run the image and point the harness at it.
//! `minio_bin` says so in its error rather than leaving somebody to
//! rediscover it.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const ROOT_USER: &str = "skein-test";
pub const ROOT_PASSWORD: &str = "skein-test-only";

pub struct Minio {
    /// Where the S3 API is, without a trailing slash — `http://127.0.0.1:9000`.
    ///
    /// A field rather than a port so that an endpoint somebody else is
    /// running can be used verbatim: the host may not be `127.0.0.1` and
    /// the scheme may not be `http`.
    pub endpoint: String,
    /// `None` when the endpoint was handed to us: a MinIO this process did
    /// not start is a MinIO it must not kill, and its data directory is
    /// not ours to delete.
    _owned: Option<Owned>,
}

struct Owned {
    _child: KillOnDrop,
    _data_dir: crate::tempdir::TempDir,
}

static SHARED: OnceLock<Minio> = OnceLock::new();
static BUCKET_SEQ: AtomicU64 = AtomicU64::new(0);

impl Minio {
    /// The process-wide shared MinIO instance, started on first use.
    /// Also sets the `AWS_*` env vars the store's SigV4 signer reads —
    /// every request in tests is signed, same as production against S3.
    pub fn shared() -> &'static Minio {
        SHARED.get_or_init(|| {
            std::env::set_var("AWS_ACCESS_KEY_ID", ROOT_USER);
            std::env::set_var("AWS_SECRET_ACCESS_KEY", ROOT_PASSWORD);
            std::env::set_var("AWS_REGION", "us-east-1");
            // `panic!("{e}")` and not `.expect(...)`, which formats the
            // error with `Debug` — so a message written over several
            // lines, naming the command that fixes it, arrives as one
            // run-on line of `\n` escapes. This is the error somebody
            // meets before they have ever run the suite; it is the one
            // place legibility is worth a line of code.
            let started = match std::env::var("SKEIN_MINIO_URL") {
                Ok(url) if !url.trim().is_empty() => Minio::attach(url.trim()),
                _ => Minio::start(),
            };
            match started {
                Ok(m) => m,
                Err(e) => panic!("{e}"),
            }
        })
    }

    /// Use a MinIO somebody else is running, without spawning or owning
    /// anything.
    ///
    /// Its credentials must be `ROOT_USER`/`ROOT_PASSWORD`, because that
    /// is what `shared` puts in the `AWS_*` env vars the store's SigV4
    /// signer reads. Readiness is still waited for: the endpoint may have
    /// been started a second ago by the same script that set the variable.
    fn attach(url: &str) -> Result<Minio, String> {
        let endpoint = url.trim_end_matches('/').to_string();
        wait_ready(&endpoint)?;
        Ok(Minio {
            endpoint,
            _owned: None,
        })
    }

    fn start() -> Result<Minio, String> {
        let bin = minio_bin()?;
        let data_dir = crate::tempdir::TempDir::new("skein-minio")?;
        let port = free_port()?;
        let mut minio = Command::new(&bin);
        minio
            .args([
                "server",
                "--address",
                &format!("127.0.0.1:{port}"),
                data_dir.path().to_str().unwrap(),
            ])
            .env("MINIO_ROOT_USER", ROOT_USER)
            .env("MINIO_ROOT_PASSWORD", ROOT_PASSWORD)
            // No console, quieter logs.
            .env("MINIO_BROWSER", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = crate::detach::detached(&mut minio)
            .spawn()
            .map_err(|e| format!("spawn {bin:?}: {e}"))?;
        reap_on_process_exit(child.id(), data_dir.path());
        let m = Minio {
            endpoint: format!("http://127.0.0.1:{port}"),
            _owned: Some(Owned {
                _child: KillOnDrop(child),
                _data_dir: data_dir,
            }),
        };
        wait_ready(&m.endpoint)?;
        Ok(m)
    }

    /// The endpoint's `host:port`, which is what a signature covers and
    /// what a proxy in front of the store has to be pointed at.
    ///
    /// Derived rather than stored as a port, because an endpoint handed
    /// in through `SKEIN_MINIO_URL` need not be on `127.0.0.1` — the
    /// two call sites that used to build `127.0.0.1:{port}` themselves
    /// would both have been silently wrong against one.
    pub fn authority(&self) -> &str {
        self.endpoint
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&self.endpoint)
    }

    /// Create a fresh, uniquely-named bucket and return a handle whose
    /// `base_url` is what `ObjectStore::new` expects.
    pub fn bucket(&self, hint: &str) -> Bucket {
        let seq = BUCKET_SEQ.fetch_add(1, Ordering::Relaxed);
        // Bucket names: lowercase alnum + hyphen, 3-63 chars.
        let clean: String = hint
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .take(40)
            .collect();
        let name = format!("t-{clean}-{}-{seq}", std::process::id());
        self.create_bucket(&name).expect("create bucket");
        Bucket {
            name: name.clone(),
            base_url: format!("{}/{}", self.endpoint, name),
        }
    }

    fn create_bucket(&self, name: &str) -> Result<(), String> {
        let signer = skein_store::sig::SigV4::from_env().ok_or("AWS env creds not set")?;
        // The signature covers the Host header, so it has to be the
        // endpoint's own authority rather than an assumed `127.0.0.1:port`.
        let authority = self.authority().to_string();
        let path = format!("/{name}");
        let hdrs = signer.sign("PUT", &authority, &path, skein_store::sig::EMPTY_SHA256)?;
        let mut req = ureq::put(&format!("{}{path}", self.endpoint));
        for (n, v) in hdrs.headers {
            req = req.set(n, &v);
        }
        // A retry loop: right after readiness the API can still briefly
        // refuse (also learned in the research harness).
        let mut last = String::new();
        for _ in 0..20 {
            match req.clone().send_bytes(&[]) {
                Ok(_) => return Ok(()),
                Err(ureq::Error::Status(409, _)) => return Ok(()), // already exists
                Err(e) => {
                    last = e.to_string();
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
        Err(format!("create bucket {name}: {last}"))
    }
}

pub struct Bucket {
    pub name: String,
    /// e.g. `http://127.0.0.1:9000/t-mytest-1234-0` — pass to ObjectStore.
    pub base_url: String,
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Shared harness daemons live in `OnceLock` statics, whose Drop never
/// runs — when the test process exits, the daemon would be orphaned and
/// live forever (hundreds of leaked minio/postgres processes after a day
/// of local runs; CI's runner cleans them up, a workstation doesn't).
/// This detached watchdog polls the current process and, once it is
/// gone, kills the daemon and removes its scratch directory. `sh` +
/// 1s-sleep loop: negligible, self-terminating.
pub(crate) fn reap_on_process_exit(daemon_pid: u32, scratch_dir: &Path) {
    let me = std::process::id();
    let dir = scratch_dir.display();
    let mut sh = Command::new("sh");
    sh.arg("-c")
        .arg(format!(
            "while kill -0 {me} 2>/dev/null; do sleep 1; done; \
             kill -9 {daemon_pid} 2>/dev/null; sleep 1; rm -rf '{dir}'"
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = crate::detach::detached(&mut sh).spawn();
}

/// `/health/ready`, not `/live`: liveness turns 200 before the S3 API
/// accepts requests on a cold boot (learned in the research harness).
fn wait_ready(endpoint: &str) -> Result<(), String> {
    let url = format!("{endpoint}/minio/health/ready");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match ureq::get(&url).timeout(Duration::from_millis(500)).call() {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("minio never became ready at {endpoint}: {e}")),
        }
    }
}

fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

fn minio_bin() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("MINIO_BIN") {
        return Ok(PathBuf::from(p));
    }
    if let Ok(out) = Command::new("which").arg("minio").output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Ok(PathBuf::from(p));
            }
        }
    }
    // Download into <workspace>/.testkit/bin/minio (CI pre-populates this).
    let root = workspace_root()?;
    let dir = root.join(".testkit/bin");
    let bin = dir.join("minio");
    if bin.exists() {
        return Ok(bin);
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // The pin, read from the same file CI reads so the two cannot drift:
    // a harness that runs a different MinIO from the one the gate ran
    // against is a harness testing a different product.
    let release = include_str!("../../../.minio-version").trim();
    // No per-platform slug any more, and its absence is the fix rather
    // than an omission. The old code picked one — and had already been
    // caught hardcoding `linux-amd64`, so a darwin machine downloaded a
    // Linux ELF and every suite failed with "minio never became ready"
    // rather than "wrong architecture". Which platforms are possible at
    // all is now the script's question, asked in one place, and its
    // answer is passed through verbatim below.
    // One implementation, in `scripts/fetch-minio.sh`, which CI's three
    // MinIO jobs run as their own step. Shelling out rather than
    // reimplementing the registry walk here is the point: a harness that
    // fetched MinIO differently from the gate would be a harness testing
    // against a different store, and this file and that script would
    // drift the first time either was touched.
    let script = root.join("scripts/fetch-minio.sh");
    eprintln!(
        "skein-testkit: fetching minio {release} via {} ...",
        script.display()
    );
    let out = Command::new("bash")
        .arg(&script)
        .arg(&bin)
        .output()
        .map_err(|e| format!("spawn {}: {e}", script.display()))?;
    if !out.status.success() {
        // The script's own words, which name the platform problem and
        // the command that works, rather than a paraphrase of them.
        return Err(format!(
            "{}\n(from {})",
            String::from_utf8_lossy(&out.stderr).trim(),
            script.display()
        ));
    }
    Ok(bin)
}

fn workspace_root() -> Result<PathBuf, String> {
    // CARGO_MANIFEST_DIR of this crate is <root>/crates/skein-testkit.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot locate workspace root".into())
}
