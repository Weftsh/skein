//! A running `skein` server, for end-to-end tests.
//!
//! The binary path is passed in rather than resolved here, because
//! `env!("CARGO_BIN_EXE_skein")` only expands inside the package that
//! declares the binary. One call per suite; everything else is shared.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::minio::{ROOT_PASSWORD, ROOT_USER};

pub struct Server {
    child: Child,
    /// `http://127.0.0.1:<port>` — no trailing slash.
    pub base: String,
    pub db_url: String,
    pub store_url: String,
    bin: String,
    env: Vec<(String, String)>,
    reaped: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop_child();
    }
}

/// Configure a server before starting it.
pub struct ServerBuilder {
    bin: String,
    store_url: String,
    db_url: Option<String>,
    db_hint: String,
    env: Vec<(String, String)>,
}

impl ServerBuilder {
    /// Use this database rather than a fresh one — for a test that
    /// restarts a server against the state a previous one left.
    pub fn db_url(mut self, url: &str) -> Self {
        self.db_url = Some(url.to_string());
        self
    }

    /// Name the fresh database after the suite, so a leftover in the
    /// test cluster says where it came from.
    pub fn db_hint(mut self, hint: &str) -> Self {
        self.db_hint = hint.to_string();
        self
    }

    /// Set one environment variable. `{bind}` in the value is replaced
    /// by the address this server binds — the only way to point a
    /// variable at the server itself, since the port is not known until
    /// spawn. Setting a variable twice keeps the last value.
    pub fn env(mut self, key: &str, value: impl Into<String>) -> Self {
        let value = value.into();
        match self.env.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => self.env.push((key.to_string(), value)),
        }
        self
    }

    pub fn start(self) -> Server {
        let db_url = self
            .db_url
            .unwrap_or_else(|| crate::pg::test_db_url(&self.db_hint));
        let (child, bind) = spawn_child(&self.bin, &self.store_url, &db_url, &self.env);
        Server {
            child,
            base: format!("http://{bind}"),
            db_url,
            store_url: self.store_url,
            bin: self.bin,
            env: self.env,
            reaped: false,
        }
    }
}

fn base_command(bin: &str, store_url: &str, db_url: &str) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("SKEIN_STORE_URL", store_url)
        .env("SKEIN_DB_URL", db_url)
        .env("AWS_ACCESS_KEY_ID", ROOT_USER)
        .env("AWS_SECRET_ACCESS_KEY", ROOT_PASSWORD)
        .env("AWS_REGION", "us-east-1");
    if let Ok(p) = std::env::var("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", p);
    }
    cmd
}

fn spawn_child(
    bin: &str,
    store_url: &str,
    db_url: &str,
    env: &[(String, String)],
) -> (Child, String) {
    spawn_on_free_port(|bind| {
        let mut cmd = base_command(bin, store_url, db_url);
        cmd.env("SKEIN_BIND", bind)
            .env("SKEIN_PUBLIC_URL", format!("http://{bind}"));
        for (k, v) in env {
            cmd.env(k, v.replace("{bind}", bind));
        }
        cmd
    })
}

/// Spawn a server on a free port and block until it is serving, retrying
/// if the port was taken between choosing it and binding it.
///
/// Choosing a port by binding it and letting go is inherently racy: two
/// suites can be handed the same number, and the loser then finds a
/// perfectly *healthy* server on it — somebody else's, with somebody
/// else's database. That does not fail like a port clash; it fails like
/// the API forgetting a package exists, in whichever test lost. So every
/// spawn gets its own `SKEIN_INSTANCE_ID`, and the server on the other
/// end has to answer it back on `/healthz` before it is trusted. This is
/// stratum-core's harness, which learned it under `cargo llvm-cov`.
pub fn spawn_on_free_port(build: impl Fn(&str) -> Command) -> (Child, String) {
    for attempt in 0..8 {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe socket");
            l.local_addr().expect("probe socket address").port()
        };
        let bind = format!("127.0.0.1:{port}");
        let instance = format!("testkit-{}-{}-{attempt}", std::process::id(), port);
        let mut cmd = build(&bind);
        cmd.env("SKEIN_INSTANCE_ID", &instance)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = crate::detach::detached(&mut cmd)
            .spawn()
            .expect("spawn skein");

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                assert!(
                    attempt < 7,
                    "server exited during startup on {bind} ({status}) eight times running"
                );
                break;
            }
            match ureq::get(&format!("http://{bind}/healthz"))
                .timeout(Duration::from_millis(300))
                .call()
            {
                Ok(resp) if resp.header("x-skein-instance") == Some(instance.as_str()) => {
                    return (child, bind)
                }
                Ok(resp) => {
                    let who = resp
                        .header("x-skein-instance")
                        .unwrap_or("<none>")
                        .to_string();
                    let _ = child.kill();
                    let _ = child.wait();
                    assert!(
                        attempt < 7,
                        "a server that is not ours ({who}) answered on {bind} eight times running"
                    );
                    break;
                }
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => panic!("server never became healthy on {bind}: {e}"),
            }
        }
    }
    unreachable!("the last attempt either returns or panics")
}

/// What an HTTP exchange came back with, whatever its status.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

fn reply_of(resp: ureq::Response) -> Reply {
    let status = resp.status();
    let headers = resp
        .headers_names()
        .into_iter()
        .flat_map(|n| {
            resp.all(&n)
                .into_iter()
                .map(|v| (n.clone(), v.to_string()))
                .collect::<Vec<_>>()
        })
        .collect();
    let mut body = Vec::new();
    resp.into_reader()
        .take(512 * 1024 * 1024)
        .read_to_end(&mut body)
        .expect("read response body");
    Reply {
        status,
        headers,
        body,
    }
}

/// Send one request, and give back whatever came back — an error status
/// is an answer, not a failure.
pub fn send(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Reply {
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut req = agent.request(method, url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let out = match body {
        Some(b) => req.send_bytes(b),
        None => req.call(),
    };
    match out {
        Ok(r) | Err(ureq::Error::Status(_, r)) => reply_of(r),
        Err(e) => panic!("transport {method} {url}: {e}"),
    }
}

impl Server {
    pub fn builder(bin: &str, store_url: &str) -> ServerBuilder {
        ServerBuilder {
            bin: bin.to_string(),
            store_url: store_url.to_string(),
            db_url: None,
            db_hint: "e2e".to_string(),
            env: Vec::new(),
        }
    }

    /// `http://127.0.0.1:<port>` + path.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// `127.0.0.1:<port>` — what a container client calls the registry.
    pub fn host(&self) -> &str {
        self.base.trim_start_matches("http://")
    }

    /// Run `skein <args>` against this server's database and bucket.
    pub fn admin(&self, args: &[&str]) -> Result<String, String> {
        let out = base_command(&self.bin, &self.store_url, &self.db_url)
            .args(args)
            .output()
            .map_err(|e| format!("spawn {}: {e}", self.bin))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    /// Bootstrap the install as organization `org` and hand back the
    /// first admin's API token.
    pub fn bootstrap(&self, org: &str) -> String {
        let out = self
            .admin(&[
                "admin",
                "bootstrap",
                "--org",
                org,
                "--username",
                "admin",
                "--json",
            ])
            .unwrap_or_else(|e| panic!("bootstrap: {e}"));
        let v: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("bootstrap printed something other than JSON: {e}\n{out}"));
        v["token"]
            .as_str()
            .expect("a token in the bootstrap output")
            .to_string()
    }

    /// A JSON request with a bearer token. `(status, body-as-JSON)`, and
    /// `Null` for a body that is not JSON.
    pub fn req(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let auth = format!("Bearer {token}");
        let mut headers = vec![("Authorization", auth.as_str())];
        let bytes = body.map(|b| b.to_string().into_bytes());
        if bytes.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        let r = send(method, &self.url(path), &headers, bytes.as_deref());
        (r.status, r.json())
    }

    pub fn get(&self, path: &str, token: &str) -> (u16, serde_json::Value) {
        self.req("GET", path, token, None)
    }

    /// Any request, with exactly the headers given.
    pub fn raw(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Reply {
        send(method, &self.url(path), headers, body)
    }

    /// Mint a token for a new person with `role`, through the API, the
    /// way an admin would. Returns `(user_id, token)`.
    pub fn person(
        &self,
        admin: &str,
        username: &str,
        role: &str,
        scopes: &[&str],
    ) -> (String, String) {
        let (s, u) = self.req(
            "POST",
            "/api/v1/users",
            admin,
            Some(serde_json::json!({ "username": username, "role": role })),
        );
        assert_eq!(s, 201, "create {username}: {u}");
        let id = u["id"].as_str().unwrap().to_string();
        let (s, t) = self.req(
            "POST",
            &format!("/api/v1/users/{id}/tokens"),
            admin,
            Some(serde_json::json!({ "label": "test", "scopes": scopes })),
        );
        assert_eq!(s, 201, "token for {username}: {t}");
        (id, t["token"].as_str().unwrap().to_string())
    }

    pub fn healthy(&self) -> bool {
        ureq::get(&self.url("/healthz"))
            .timeout(Duration::from_secs(2))
            .call()
            .is_ok()
    }

    /// Stop and start the same server against the same database and
    /// bucket, on a fresh port.
    pub fn restart(&mut self) {
        self.stop_child();
        let (child, bind) = spawn_child(&self.bin, &self.store_url, &self.db_url, &self.env);
        self.child = child;
        self.base = format!("http://{bind}");
        self.reaped = false;
    }

    fn stop_child(&mut self) {
        if self.reaped {
            return;
        }
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.reaped = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_set_twice_has_one_slot() {
        let b = Server::builder("skein", "http://x")
            .env("SKEIN_A", "1")
            .env("SKEIN_A", "2");
        assert_eq!(b.env, vec![("SKEIN_A".to_string(), "2".to_string())]);
    }

    /// A healthy server that is not ours is refused and retried, rather
    /// than trusted because it answered.
    #[test]
    fn a_healthy_server_that_is_not_ours_is_refused_and_retried() {
        // A stand-in that answers /healthz with the wrong instance on the
        // first port it is given, then with the right one.
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let (mut child, bind) = spawn_on_free_port(|bind| {
            let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let script = format!(
                r#"
import http.server, os, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("x-skein-instance", "someone-else" if {n} == 0 else os.environ["SKEIN_INSTANCE_ID"])
        self.end_headers()
    def log_message(self, *a): pass
host, port = "{bind}".split(":")
http.server.HTTPServer((host, int(port)), H).serve_forever()
"#
            );
            let mut c = Command::new("python3");
            c.args(["-c", &script]);
            c
        });
        assert!(attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        assert!(bind.starts_with("127.0.0.1:"));
        let _ = child.kill();
        let _ = child.wait();
    }
}
