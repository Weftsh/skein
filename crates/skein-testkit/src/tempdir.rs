//! Scratch directories for the daemon harnesses, removed on drop.
//!
//! The name carries this process's pid and a per-process sequence number,
//! which is unique only while nothing is left behind. A test binary that
//! dies by signal never runs `Drop` — and the reaper `reap_on_process_exit`
//! spawns shares its process group, so a Ctrl-C takes that down too — the
//! kernel hands the pid out again, and the next binary to draw it starts
//! its own sequence at 0. `create_dir_all` succeeds on a directory that is
//! already there, so the harness used to adopt a dead run's cluster and
//! `initdb` refused it: "directory exists but is not empty", in one test
//! of a coverage run that passed alone. The claim is now `create_dir`,
//! which fails on an existing directory, and a taken name is passed over
//! rather than reused.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many names to try before giving up. A collision needs a leftover
/// from a dead process with this exact pid and sequence number, so the
/// second name is almost always free; the bound only keeps a full disk or
/// a read-only `$TMPDIR` from looping.
const ATTEMPTS: u32 = 16;

#[derive(Debug)]
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(prefix: &str) -> Result<Self, String> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        claim(
            &std::env::temp_dir(),
            (0..ATTEMPTS).map(|k| match k {
                0 => format!("{prefix}-{pid}-{seq}"),
                k => format!("{prefix}-{pid}-{seq}-{k}"),
            }),
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

/// Creates the first of `names` under `base` that did not already exist
/// and hands it back. A name that is taken belongs to somebody else — a
/// dead run, or a live one — and is neither emptied nor adopted.
fn claim(base: &Path, names: impl IntoIterator<Item = String>) -> Result<TempDir, String> {
    let mut taken = None;
    for name in names {
        let p = base.join(name);
        match std::fs::create_dir(&p) {
            Ok(()) => return Ok(TempDir(p)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => taken = Some(p),
            Err(e) => return Err(format!("create scratch directory {}: {e}", p.display())),
        }
    }
    Err(format!(
        "every scratch directory name is taken (last tried {}); clean up {}",
        taken
            .as_deref()
            .map(Path::display)
            .map_or_else(|| "nothing".to_string(), |d| d.to_string()),
        base.display()
    ))
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this guards: a directory left by a killed run, under a pid
    /// the kernel has since reused, was adopted as ours and `initdb`
    /// refused it. The leftover is neither reused nor touched.
    #[test]
    fn a_leftover_directory_is_passed_over_and_left_alone() {
        let base = TempDir::new("skein-testkit-tempdir-test").unwrap();
        let leftover = base.path().join("a").join("data");
        std::fs::create_dir_all(&leftover).unwrap();
        std::fs::write(leftover.join("PG_VERSION"), "16\n").unwrap();

        let got = claim(base.path(), ["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(got.path(), base.path().join("b"));
        assert_eq!(
            std::fs::read_to_string(leftover.join("PG_VERSION")).unwrap(),
            "16\n",
            "the stranger's directory was emptied"
        );
    }

    /// Running out of names is an error that names the collision, not a
    /// silent reuse of the last one.
    #[test]
    fn running_out_of_names_says_which_was_taken() {
        let base = TempDir::new("skein-testkit-tempdir-test").unwrap();
        std::fs::create_dir(base.path().join("a")).unwrap();
        std::fs::create_dir(base.path().join("b")).unwrap();
        let e = claim(base.path(), ["a".to_string(), "b".to_string()]).unwrap_err();
        assert!(e.contains("taken"), "{e}");
        assert!(
            e.contains(&base.path().join("b").display().to_string()),
            "{e}"
        );
        let e = claim(base.path(), []).unwrap_err();
        assert!(e.contains("nothing"), "{e}");
    }

    /// Any other failure is reported as what it is, not retried under a
    /// new name.
    #[test]
    fn a_base_that_does_not_exist_is_an_error_not_a_retry() {
        let base = TempDir::new("skein-testkit-tempdir-test").unwrap();
        let missing = base.path().join("no-such-parent");
        let e = claim(&missing, ["a".to_string(), "b".to_string()]).unwrap_err();
        assert!(e.contains("create scratch directory"), "{e}");
        assert!(e.contains("no-such-parent"), "{e}");
    }

    /// Two claims in one process never share a directory; drop removes
    /// what was claimed.
    #[test]
    fn each_claim_is_its_own_directory_and_drop_removes_it() {
        let a = TempDir::new("skein-testkit-tempdir-test").unwrap();
        let b = TempDir::new("skein-testkit-tempdir-test").unwrap();
        assert_ne!(a.path(), b.path());
        let kept = a.path().to_path_buf();
        assert!(kept.is_dir());
        drop(a);
        assert!(!kept.exists());
        assert!(b.path().is_dir());
    }
}
