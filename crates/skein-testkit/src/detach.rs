//! Long-lived helper processes must not inherit the test's descriptors.
//!
//! A test binary spawns `git` with a pipe on its stdout and reads it to
//! end. Meanwhile another test thread starts this crate's Postgres. On
//! macOS Rust cannot create that pipe and mark it close-on-exec in one
//! step — `pipe2` does not exist there — so a fork or `posix_spawn` that
//! lands in the gap inherits both ends. Postgres lives until the test
//! binary exits, the `git` read waits for the write end to close, and
//! the binary hangs forever with `git` long gone: a coverage run sat at
//! 0% CPU for forty minutes on 2026-09-07 in exactly that state, with
//! `lsof` showing the pipe held by the cluster's backends. Linux has an
//! atomic `pipe2`, which is why CI never meets it.
//!
//! The fix is at the seam that matters: whatever a helper inherited by
//! accident is closed before it execs, so no long-lived process can ever
//! hold a pipe the test is waiting on. Short-lived commands run with
//! `.output()` are not the problem — they exit.

use std::os::unix::process::CommandExt;
use std::process::Command;

/// Close every descriptor above stderr in the child before it execs.
///
/// Runs after the child's stdio is in place, so 0–2 are the ones the
/// caller asked for. Applied to Postgres, MinIO, the server under test
/// and the reaper shells — everything that outlives a test.
pub fn detached(cmd: &mut Command) -> &mut Command {
    // SAFETY: only async-signal-safe calls — `sysconf` and `close` — and
    // no allocation, which is the contract `pre_exec` asks for.
    unsafe {
        cmd.pre_exec(|| {
            let max = libc::sysconf(libc::_SC_OPEN_MAX);
            let max = if max <= 0 { 1024 } else { max as i32 };
            for fd in 3..max {
                libc::close(fd);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// A descriptor that is not close-on-exec — the shape the race
    /// leaves behind — reaches an ordinary child and does not reach a
    /// detached one.
    #[test]
    fn a_detached_child_holds_nothing_the_test_opened() {
        // `dup2` never sets close-on-exec, so this is exactly the fd a
        // lost race hands a child — at a number nothing in the child
        // opens for itself, so its presence is unambiguous.
        const LEAKED: i32 = 40;
        assert_eq!(unsafe { libc::dup2(2, LEAKED) }, LEAKED, "dup2 failed");
        let open_in_child = |detach: bool| {
            let mut c = Command::new("sh");
            c.arg("-c")
                .arg(format!(
                    "[ -e /dev/fd/{LEAKED} ] && echo open || echo closed"
                ))
                .stdin(Stdio::null());
            if detach {
                detached(&mut c);
            }
            let out = c.output().expect("spawn sh");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(
            open_in_child(false),
            "open",
            "the leaked fd did not reach an ordinary child; the premise of this test has changed"
        );
        assert_eq!(
            open_in_child(true),
            "closed",
            "the leaked fd reached a detached child"
        );
        unsafe {
            libc::close(LEAKED);
        }
    }
}
