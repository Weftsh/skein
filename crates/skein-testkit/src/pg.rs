//! Shared PostgreSQL instance for tests: one server per test process, one
//! uniquely-named database per test — the same discipline as the MinIO
//! harness, so control-plane tests are hermetic and parallel-safe.
//!
//! Binary resolution order: `$SKEIN_PG_BIN_DIR` → `initdb` on PATH →
//! newest `/usr/lib/postgresql/<v>/bin` (the layout Debian/Ubuntu — and
//! the GitHub Actions runner image — installs).
//!
//! PostgreSQL refuses to run as root, so when the test process is root
//! (dev containers) the harness chowns the data directory to the
//! `postgres` system user and spawns `initdb`/`postgres` under that uid.

use std::path::{Path, PathBuf};

use crate::tempdir::TempDir;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Superuser name inside the test cluster; trust auth, loopback only.
pub const PG_USER: &str = "skein";

pub struct Pg {
    pub port: u16,
    _child: KillOnDrop,
    _data_dir: TempDir,
}

static SHARED: OnceLock<Pg> = OnceLock::new();
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

/// The shared cluster's postmaster, for the exit hook below.
static SHARED_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Shut the shared cluster down on the way out of the process.
///
/// `SHARED` is a `OnceLock`, and Rust never drops a `static` — so
/// `KillOnDrop` runs for the private clusters the unit tests build and
/// *never* for the shared one that every e2e suite uses. Each test binary
/// therefore left a postmaster to be orphaned rather than stopped, and an
/// unstopped postmaster keeps its System V shared-memory segment forever.
///
/// macOS allows 32 of those for the entire machine (`kern.sysv.shmmni`;
/// Linux allows thousands), and `cargo test --workspace` runs a couple of
/// dozen test binaries. So a full local run exhausted the machine partway
/// through and every later suite died on `initdb` with "could not create
/// shared memory segment: No space left on device" — a message that is
/// not about disk, that names no cause a reader would connect to
/// postgres, and that lands on whichever suite happened to run next.
///
/// `atexit` runs on normal exit, which is how a test binary finishes even
/// when tests failed. A hard kill still leaks; `scripts/clean-build-
/// artifacts.sh` reclaims those.
extern "C" fn stop_shared_cluster() {
    let pid = SHARED_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid <= 0 {
        return;
    }
    stop_and_reap(pid, Duration::from_secs(5));
}

/// How a cluster ended: on its own, or at the end of the deadline.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Shutdown {
    /// The postmaster took the signal and left. The overwhelming majority.
    Exited,
    /// It did not, so it was killed. A wedged postmaster leaks its
    /// segment, but a test harness must always terminate.
    Killed,
}

/// Ask the postmaster to stop, and **reap it**, within `within`.
///
/// The reaping is the whole point, and it was the bug. This used to send
/// `SIGINT` and then poll `libc::kill(pid, 0)` until the deadline — but
/// the postmaster is a *direct child* of the test process and nothing
/// ever waits on it: `SHARED` is a `OnceLock`, and Rust never drops a
/// `static`, so the `KillOnDrop` below (which polls `Child::try_wait`,
/// and therefore reaps, and was always correct) never runs for the shared
/// cluster. That is why this function exists in raw `libc` at all — a
/// `static` has no `Child` to call a method on.
///
/// A signalled child that nobody waits on becomes a **zombie**, and
/// signal 0 succeeds against a zombie for as long as it goes unreaped. So
/// the liveness poll could never see the postmaster go: every test binary
/// that had touched a database sat out the full five seconds and then
/// `SIGKILL`ed a corpse.
///
/// `cargo test` runs test binaries one at a time. On the CI run this was
/// found in, the gap between one binary's last result and the next
/// binary's first line had a median of **5.01s** across 67 transitions —
/// 4.5 minutes of dead time in the correctness gate and another 4.5 in
/// the coverage job, which is a fifth of each. Nothing was wrong with any
/// test; the harness was waiting out its own deadline, every time.
///
/// `waitpid` is the answer to "is it actually gone", because it is the
/// call that makes it gone. `crates/skein-testkit/tests/pg_exit.rs`
/// measures the property that costs — how long a test binary takes to
/// exit once its last test has finished.
pub(crate) fn stop_and_reap(pid: i32, within: Duration) -> Shutdown {
    unsafe {
        // Fast shutdown: the postmaster detaches its segment.
        libc::kill(pid, libc::SIGINT);
    }
    // Bounded: the exit path must never hang.
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if gone(pid) {
            return Shutdown::Exited;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    // Clear the corpse too. A `SIGKILL`ed child is still a zombie until
    // somebody waits on it, and leaving one behind is how this started.
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && !gone(pid) {
        std::thread::sleep(Duration::from_millis(20));
    }
    Shutdown::Killed
}

/// Has `pid` actually finished — and if it was ours, is it reaped?
///
/// `waitpid` is authoritative for a child of this process: `> 0` means it
/// exited and this call has just collected it. `ECHILD` means it is not
/// ours to wait on (already reaped, or never a child), and only then is
/// signal 0 the best available answer.
fn gone(pid: i32) -> bool {
    let mut status: libc::c_int = 0;
    match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
        0 => false,
        r if r == pid => true,
        _ => (unsafe { libc::kill(pid, 0) }) != 0,
    }
}

impl Pg {
    /// The process-wide shared PostgreSQL instance, started on first use.
    pub fn shared() -> &'static Pg {
        SHARED.get_or_init(|| {
            let pg = Pg::start().expect("start postgres");
            SHARED_PID.store(pg._child.0.id() as i32, std::sync::atomic::Ordering::SeqCst);
            unsafe {
                libc::atexit(stop_shared_cluster);
            }
            pg
        })
    }

    /// A private cluster, owned by the caller and stopped on drop.
    ///
    /// Almost every test wants [`Pg::shared`] and a fresh database on it.
    /// This is for the handful that need to take the server *away* from a
    /// connection — a worker lock released after its database died — and
    /// so cannot share a cluster with anyone.
    pub fn start() -> Result<Pg, String> {
        let bin_dir = pg_bin_dir()?;
        let data_dir = TempDir::new("skein-testkit-pg")?;
        let datadir = data_dir.path().join("data");
        std::fs::create_dir_all(&datadir).map_err(|e| e.to_string())?;
        let run_as = run_as_uid_gid(data_dir.path())?;

        let mut initdb = Command::new(bin_dir.join("initdb"));
        initdb
            .arg("-D")
            .arg(&datadir)
            .args(["-U", PG_USER, "-A", "trust", "--no-sync"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        apply_uid(&mut initdb, run_as);
        let out = initdb.output().map_err(|e| format!("spawn initdb: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "initdb failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }

        // Choosing a port by binding it and letting go is racy, and the
        // whole workspace's test binaries do it at once — each of them
        // here, and again for every server they spawn. Two harnesses can
        // be handed the same number.
        //
        // That does not merely fail: `connect` may *succeed* against
        // whoever won the race, and this harness would then create its
        // databases inside somebody else's cluster and watch them vanish
        // when that cluster dies. `spawn_on_free_port` in this crate
        // documents the same hazard for the server; the fix here is the
        // same shape — retry on a fresh port, and prove the cluster on
        // the other end is ours before trusting it.
        for attempt in 0..8 {
            let port = free_port()?;
            let mut pg = Command::new(bin_dir.join("postgres"));
            pg.arg("-D")
                .arg(&datadir)
                .args(["-p", &port.to_string()])
                .args(["-c", "listen_addresses=127.0.0.1"])
                .args(["-c", "fsync=off"])
                .args(["-c", "synchronous_commit=off"])
                .args(["-c", "full_page_writes=off"])
                .args(["-c", "max_connections=200"])
                .arg("-c")
                .arg(format!(
                    "unix_socket_directories={}",
                    datadir.to_str().unwrap()
                ))
                .stdout(Stdio::null());
            // Postgres' own complaint is the only thing that can say why
            // it would not start, and this used to go to /dev/null — so
            // the one time it failed under a full `--release` workspace
            // run, the panic named `Pg::shared` and nothing else. A file
            // rather than a pipe: a pipe nobody drains fills and blocks
            // the child, and this child has to stay killable.
            let log = datadir.join(format!("startup-{attempt}.log"));
            match std::fs::File::create(&log) {
                Ok(f) => {
                    pg.stderr(Stdio::from(f));
                }
                // Losing the log must not lose the attempt.
                Err(_) => {
                    pg.stderr(Stdio::null());
                }
            }
            apply_uid(&mut pg, run_as);
            let mut child = crate::detach::detached(&mut pg)
                .spawn()
                .map_err(|e| format!("spawn postgres: {e}"))?;
            crate::minio::reap_on_process_exit(child.id(), data_dir.path());

            let url = format!("postgres://{PG_USER}@127.0.0.1:{port}/postgres");
            // Ten seconds, not thirty: a lost race has to be cheap to
            // discover, because the answer to it is another attempt.
            let deadline = Instant::now() + Duration::from_secs(10);
            let outcome = loop {
                // A postgres that could not bind the port is gone within
                // milliseconds. Noticing that beats waiting out the
                // deadline for a process that will never answer.
                if let Ok(Some(_)) = child.try_wait() {
                    break Err("postgres exited during startup".to_string());
                }
                match postgres::Client::connect(&url, postgres::NoTls) {
                    Ok(mut c) => break identify(&mut c, &datadir),
                    Err(e) if Instant::now() >= deadline => {
                        break Err(format!("postgres never became ready: {e}"))
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            };
            match outcome {
                Ok(()) => {
                    return Ok(Pg {
                        port,
                        _child: KillOnDrop(child),
                        _data_dir: data_dir,
                    })
                }
                Err(why) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    if attempt == 7 {
                        return Err(format!(
                            "postgres never started: {why}\n--- its own last words ---\n{}",
                            last_words(&log)
                        ));
                    }
                }
            }
        }
        unreachable!("the last attempt either returns or errors")
    }

    fn url(&self, db: &str) -> String {
        format!("postgres://{PG_USER}@127.0.0.1:{}/{db}", self.port)
    }

    /// Create a fresh, uniquely-named database and return its URL — what
    /// `ControlDb::open` / `SKEIN_DB_URL` expect.
    pub fn database(&self, hint: &str) -> String {
        let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let clean: String = hint
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(30)
            .collect();
        let name = format!("t_{clean}_{}_{seq}", std::process::id());
        let mut admin = postgres::Client::connect(&self.url("postgres"), postgres::NoTls)
            .expect("connect postgres");
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .expect("create database");
        self.url(&name)
    }
}

/// One fresh database on the shared instance; the usual entry point.
pub fn test_db_url(hint: &str) -> String {
    Pg::shared().database(hint)
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    /// Ask postgres to shut down before killing it.
    ///
    /// This used to be a bare `kill()`. A postmaster that dies on SIGKILL
    /// never detaches the small System V shared-memory segment it holds
    /// as its startup interlock, so every test cluster leaked one. On
    /// Linux that is invisible — `kern.sysv.shmmni` is in the thousands —
    /// but macOS ships a limit of **32** segments for the whole machine,
    /// so after a few dozen cluster starts every further `initdb` fails
    /// with:
    ///
    /// ```text
    /// FATAL: could not create shared memory segment: No space left on device
    /// ```
    ///
    /// which is not a disk problem at all, says so in its own HINT, and
    /// arrives long after the run that caused it — a leak that presents
    /// as an unrelated failure in somebody else's test, on one platform
    /// only. `ipcs -m` shows the orphans with NATTCH 0.
    ///
    /// SIGINT is postgres's *fast* shutdown: it releases the segment.
    /// SIGKILL stays as the backstop for a postmaster that is already
    /// wedged, because a test harness must always terminate.
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let pid = self.0.id() as i32;
            unsafe {
                libc::kill(pid, libc::SIGINT);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match self.0.try_wait() {
                    Ok(Some(_)) => return,
                    _ => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Confirm the cluster on the other end is the one we just started.
///
/// `SHOW data_directory` is the cluster's own answer about where it
/// lives, so it cannot be spoofed by a coincidence of port numbers. If it
/// does not name our scratch directory, we reached somebody else's
/// postgres and must not use it.
/// The tail of what a failed postgres wrote before giving up.
///
/// Bounded, because a cluster that failed on every connection can have
/// written a great deal, and the useful part is always at the end.
fn last_words(log: &Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(12).collect();
    if lines.is_empty() {
        return "(it wrote nothing)".into();
    }
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

fn identify(client: &mut postgres::Client, datadir: &Path) -> Result<(), String> {
    let row = client
        .query_one("SHOW data_directory", &[])
        .map_err(|e| format!("ask which cluster this is: {e}"))?;
    let theirs: String = row.get(0);
    // Compare canonically: postgres reports the path it resolved, which
    // can differ from ours by a symlink (/tmp on macOS, for one).
    let same = std::fs::canonicalize(&theirs)
        .ok()
        .zip(std::fs::canonicalize(datadir).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(theirs == datadir.to_string_lossy());
    if same {
        Ok(())
    } else {
        Err(format!(
            "that port belongs to another cluster at {theirs}, not ours at {}",
            datadir.display()
        ))
    }
}

fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

/// Root can't run postgres: resolve the `postgres` system user and chown
/// the scratch dir to it. Non-root processes run the binaries directly.
fn run_as_uid_gid(dir: &Path) -> Result<Option<(u32, u32)>, String> {
    // SAFETY: geteuid has no failure modes.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(None);
    }
    let uid = id_of(["-u", "postgres"])?;
    let gid = id_of(["-g", "postgres"])?;
    let st = Command::new("chown")
        .arg("-R")
        .arg(format!("{uid}:{gid}"))
        .arg(dir)
        .status()
        .map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("chown pg scratch dir failed".into());
    }
    Ok(Some((uid, gid)))
}

fn id_of(args: [&str; 2]) -> Result<u32, String> {
    let out = Command::new("id")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("running as root but no `postgres` system user exists".into());
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|e| format!("parse id: {e}"))
}

fn apply_uid(cmd: &mut Command, run_as: Option<(u32, u32)>) {
    if let Some((uid, gid)) = run_as {
        use std::os::unix::process::CommandExt;
        cmd.uid(uid).gid(gid);
    }
}

fn pg_bin_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("SKEIN_PG_BIN_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Ok(out) = Command::new("which").arg("initdb").output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Some(parent) = Path::new(&p).parent() {
                return Ok(parent.to_path_buf());
            }
        }
    }
    // Debian/Ubuntu (and the GitHub runner image): versioned bin dirs.
    let mut versions: Vec<(u32, PathBuf)> = std::fs::read_dir("/usr/lib/postgresql")
        .map_err(|_| {
            "no PostgreSQL binaries found: set SKEIN_PG_BIN_DIR, put initdb on PATH, \
             or install postgresql (apt install postgresql)"
                .to_string()
        })?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let v: u32 = e.file_name().to_str()?.parse().ok()?;
            Some((v, e.path().join("bin")))
        })
        .filter(|(_, p)| p.join("initdb").exists())
        .collect();
    versions.sort();
    versions
        .pop()
        .map(|(_, p)| p)
        .ok_or_else(|| "no usable /usr/lib/postgresql/<v>/bin found".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this guards: `free_port` binds a port and lets it go, and
    /// every test binary in the workspace does that at once — for its own
    /// cluster and again for every server it spawns. Two harnesses can be
    /// handed the same number, and then `connect` **succeeds** against
    /// whoever won. Without an identity check this harness would create
    /// its databases inside a stranger's cluster and watch them vanish
    /// when that cluster died, which is how a coverage run failed with
    /// "postgres never became ready" while the same suite passed alone.
    ///
    /// Two real clusters, so the wrong-cluster case is the real thing
    /// rather than a fabricated path.
    #[test]
    fn a_cluster_reached_on_a_borrowed_port_is_not_mistaken_for_ours() {
        let ours = Pg::start().expect("start our cluster");
        let theirs = Pg::start().expect("start another cluster");
        assert_ne!(ours.port, theirs.port, "two harnesses shared a port");

        let mut client = postgres::Client::connect(&ours.url("postgres"), postgres::NoTls).unwrap();

        // Connected to our own: accepted.
        identify(&mut client, &ours._data_dir.path().join("data"))
            .expect("our own cluster was rejected");

        // The same live connection, checked against somebody else's data
        // directory: refused, and the message names both so a failure is
        // diagnosable rather than mysterious.
        let e = identify(&mut client, &theirs._data_dir.path().join("data"))
            .expect_err("a foreign cluster was accepted");
        assert!(e.contains("another cluster"), "{e}");
        assert!(
            e.contains(&theirs._data_dir.path().join("data").display().to_string())
                || e.contains(&ours._data_dir.path().join("data").display().to_string()),
            "{e}"
        );
    }

    /// A child that takes the signal is noticed *when it goes*, not when
    /// the deadline runs out.
    ///
    /// The child is `mem::forget`ed on purpose: that is the shape of the
    /// real thing, where the `Child` lives inside a `OnceLock` that is
    /// never dropped, so `std` never reaps it and the corpse is left for
    /// `stop_and_reap` to collect. Without the `waitpid`, signal 0 keeps
    /// answering "alive" for the zombie and this takes the full budget.
    #[test]
    fn a_child_that_takes_the_signal_is_noticed_when_it_goes() {
        let child = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a stand-in postmaster");
        let pid = child.id() as i32;
        std::mem::forget(child);

        let started = Instant::now();
        assert_eq!(stop_and_reap(pid, Duration::from_secs(5)), Shutdown::Exited);
        let took = started.elapsed();

        assert!(
            took < Duration::from_millis(500),
            "waited {took:?} for a child that died immediately — the exit \
             path is sitting out its deadline instead of reaping"
        );
        assert!(
            unsafe { libc::waitpid(pid, &mut 0, libc::WNOHANG) } == -1,
            "the child was left unreaped"
        );
    }

    /// And one that refuses the signal is still killed, and still reaped.
    ///
    /// This is the other half of the class: the bound has to hold for a
    /// wedged postmaster, because a test harness must always terminate.
    #[test]
    fn a_child_that_ignores_the_signal_is_killed_at_the_deadline() {
        // The child announces itself *after* installing the trap. Signal
        // it any sooner and the default disposition kills it, which is
        // the opposite of what this test is about — the first draft of
        // this test failed exactly that way.
        let mut child = Command::new("sh")
            .args(["-c", "trap '' INT; echo ready; sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a stand-in postmaster");
        let pid = child.id() as i32;
        let mut ready = [0u8; 1];
        std::io::Read::read_exact(&mut child.stdout.take().expect("piped stdout"), &mut ready)
            .expect("the child never announced itself");
        std::mem::forget(child);

        let started = Instant::now();
        assert_eq!(
            stop_and_reap(pid, Duration::from_millis(300)),
            Shutdown::Killed
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the kill path did not respect its own bound"
        );
        assert!(
            unsafe { libc::waitpid(pid, &mut 0, libc::WNOHANG) } == -1,
            "a SIGKILLed child is still a zombie until somebody waits on it"
        );
    }

    /// Every database this harness hands out belongs to the cluster it
    /// started — the property the identity check exists to preserve.
    #[test]
    fn databases_are_created_in_our_own_cluster() {
        let pg = Pg::start().expect("start postgres");
        let url = pg.database("identity");
        let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        identify(&mut client, &pg._data_dir.path().join("data"))
            .expect("a database landed in a foreign cluster");
    }
}
