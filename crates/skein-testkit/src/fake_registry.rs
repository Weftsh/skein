//! A stand-in for a public package registry.
//!
//! Modelled on stratum-core's `fake_stripe`: raw TCP on `127.0.0.1:0`, a
//! recorded call list for readback, and knobs for the misbehaviour a
//! test wants to provoke. Pointed at with `SKEIN_UPSTREAM_NPM`.
//!
//! **What this fake is, and is not.** It encodes what we *believe* npmjs
//! serves: a packument with a `versions` map, a sibling `time` map
//! carrying each version's publish date, and tarballs at the URLs the
//! document names. That belief is the thing most likely to be wrong —
//! it is the same shape of mistake as stratum-core's `Retry-After`
//! classification and its runner labels, both of which produced a green
//! suite and a broken product. The `clients` CI job, which drives the
//! real `npm` against the real registry, is what checks it against the
//! real thing; this is what makes the suite hermetic in the meantime.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// One version this fake serves.
#[derive(Clone)]
pub struct Version {
    pub version: String,
    /// The SPDX expression, or `None` to declare none at all — which is
    /// the case the per-ecosystem `unknown` disposition exists for.
    pub licence: Option<String>,
    /// `YYYY-MM-DDTHH:MM:SS.000Z`, as npm emits. `None` omits the entry
    /// from `time`, which is the "upstream did not say" case.
    pub published: Option<String>,
    pub tarball: Vec<u8>,
}

impl Version {
    pub fn new(version: &str, licence: Option<&str>, published: Option<&str>) -> Version {
        Version {
            version: version.to_string(),
            licence: licence.map(str::to_string),
            published: published.map(str::to_string),
            tarball: format!("tarball of {version}").into_bytes(),
        }
    }
}

pub struct FakeRegistry {
    pub base_url: String,
    calls: Arc<Mutex<Vec<String>>>,
    packages: Arc<Mutex<BTreeMap<String, Vec<Version>>>>,
    down: Arc<Mutex<bool>>,
    tarballs_down: Arc<Mutex<bool>>,
    garbage: Arc<Mutex<bool>>,
}

impl FakeRegistry {
    pub fn start() -> FakeRegistry {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake registry");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let packages: Arc<Mutex<BTreeMap<String, Vec<Version>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let down = Arc::new(Mutex::new(false));
        let tarballs_down = Arc::new(Mutex::new(false));
        let garbage = Arc::new(Mutex::new(false));

        let (c, p, d) = (calls.clone(), packages.clone(), down.clone());
        let g = garbage.clone();
        let td = tarballs_down.clone();
        let origin = base_url.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let (c, p, d, origin) = (c.clone(), p.clone(), d.clone(), origin.clone());
                let g = g.clone();
                let td = td.clone();
                std::thread::spawn(move || {
                    let mut line = String::new();
                    let mut r = BufReader::new(&mut sock);
                    if r.read_line(&mut line).is_err() {
                        return;
                    }
                    // Drain the headers so the client is not left writing
                    // into a socket nobody is reading.
                    loop {
                        let mut h = String::new();
                        match r.read_line(&mut h) {
                            Ok(0) => break,
                            Ok(_) if h.trim().is_empty() => break,
                            Ok(_) => {}
                            Err(_) => return,
                        }
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    c.lock().unwrap().push(path.clone());

                    if *d.lock().unwrap() {
                        let _ = write!(
                            sock,
                            "HTTP/1.1 503 .\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        return;
                    }

                    if *g.lock().unwrap() {
                        let body = "{ this is not json";
                        let _ = write!(
                            sock,
                            "HTTP/1.1 200 .\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        return;
                    }

                    let pkgs = p.lock().unwrap();
                    // `/<name>/-/<file>.tgz` is a tarball; anything else
                    // is a metadata request for the name.
                    let decoded = path.replace("%2f", "/").replace("%2F", "/");
                    let decoded = decoded.trim_start_matches('/');
                    if let Some(at) = decoded.rfind("/-/") {
                        let (name, rest) = decoded.split_at(at);
                        let file = rest.trim_start_matches("/-/");
                        let bare = name.rsplit('/').next().unwrap_or(name);
                        if *td.lock().unwrap() {
                            // Metadata still answers; only the artifact
                            // does not. An upstream half up is a real
                            // shape — a CDN edge failing while the
                            // registry API is fine — and it is the only
                            // way to reach the door's artifact-fetch
                            // failure, which is a different refusal from
                            // a document it could not read.
                            let _ = write!(
                                sock,
                                "HTTP/1.1 503 .\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
                            return;
                        }
                        let found = pkgs.get(name).and_then(|vs| {
                            vs.iter()
                                .find(|v| file == format!("{bare}-{}.tgz", v.version))
                        });
                        match found {
                            Some(v) => {
                                let _ = write!(
                                    sock,
                                    "HTTP/1.1 200 .\r\nContent-Type: application/octet-stream\r\n\
                                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                                    v.tarball.len()
                                );
                                let _ = sock.write_all(&v.tarball);
                            }
                            None => {
                                let _ = write!(
                                    sock,
                                    "HTTP/1.1 404 .\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                            }
                        }
                        return;
                    }

                    match pkgs.get(decoded) {
                        Some(vs) => {
                            let body = packument(decoded, vs, &origin);
                            let _ = write!(
                                sock,
                                "HTTP/1.1 200 .\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                        }
                        None => {
                            let _ = write!(
                                sock,
                                "HTTP/1.1 404 .\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
                        }
                    }
                });
            }
        });

        FakeRegistry {
            base_url,
            calls,
            packages,
            down,
            tarballs_down,
            garbage,
        }
    }

    /// Publish a package into the fake.
    pub fn add(&self, name: &str, versions: Vec<Version>) {
        self.packages
            .lock()
            .unwrap()
            .insert(name.to_string(), versions);
    }

    /// Every path this fake was asked for, in order. The assertion that
    /// a reserved namespace is *not* fetched reads this.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// Answer 503 to everything, for the "upstream is down" case.
    pub fn outage(&self, down: bool) {
        *self.down.lock().unwrap() = down;
    }

    /// Answer 503 to *tarball* requests while metadata still works.
    pub fn tarball_outage(&self, down: bool) {
        *self.tarballs_down.lock().unwrap() = down;
    }

    /// Answer 200 with something that is not a document.
    ///
    /// A different failure from an outage and it has to stay different:
    /// "we could not ask" and "we asked and got nonsense" both mean the
    /// proxy cannot serve, but only the second says the upstream is
    /// broken rather than absent — and a registry that read nonsense as
    /// "no such package" would have a resolver cache that.
    pub fn garbage(&self, on: bool) {
        *self.garbage.lock().unwrap() = on;
    }
}

fn packument(name: &str, versions: &[Version], origin: &str) -> String {
    let bare = name.rsplit('/').next().unwrap_or(name);
    let mut vs = serde_json::Map::new();
    let mut time = serde_json::Map::new();
    for v in versions {
        let mut manifest = serde_json::json!({
            "name": name,
            "version": v.version,
            "dependencies": { "left-pad": "^1.0.0" },
            "dist": {
                "tarball": format!("{origin}/{name}/-/{bare}-{}.tgz", v.version),
            }
        });
        if let Some(l) = &v.licence {
            manifest["license"] = serde_json::json!(l);
        }
        vs.insert(v.version.clone(), manifest);
        if let Some(t) = &v.published {
            time.insert(v.version.clone(), serde_json::json!(t));
        }
    }
    let latest = versions
        .last()
        .map(|v| v.version.clone())
        .unwrap_or_default();
    serde_json::json!({
        "name": name,
        "_id": name,
        "dist-tags": { "latest": latest },
        "versions": serde_json::Value::Object(vs),
        "time": serde_json::Value::Object(time),
    })
    .to_string()
}
