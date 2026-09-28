//! What every end-to-end suite needs: a server, and a publish in the
//! shape the real client sends.

#![allow(dead_code)]

use skein_testkit::Server;

pub fn spawn(store_url: &str, hint: &str) -> Server {
    Server::builder(env!("CARGO_BIN_EXE_skein"), store_url)
        .db_hint(hint)
        .start()
}

/// Standard base64, to build an `_attachments` body the way npm does.
pub fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A publish document in npm's shape.
pub fn publish_doc(name: &str, version: &str, tarball: &[u8]) -> serde_json::Value {
    let bare = name.rsplit('/').next().unwrap_or(name);
    serde_json::json!({
        "_id": name,
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "license": "MIT",
                "dependencies": { "left-pad": "^1.0.0" },
            }
        },
        "_attachments": {
            format!("{bare}-{version}.tgz"): {
                "content_type": "application/octet-stream",
                "data": b64(tarball),
                "length": tarball.len(),
            }
        }
    })
}

/// Fetch a URL with a bearer token, returning `(status, bytes)`.
pub fn get_bytes(url: &str, token: &str) -> (u16, Vec<u8>) {
    let r = skein_testkit::server::send(
        "GET",
        url,
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    );
    (r.status, r.body)
}

/// Switch an ecosystem on, in private mode.
pub fn enable(server: &Server, admin: &str, eco: &str) {
    let (status, body) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        admin,
        Some(serde_json::json!({ "ecosystem": eco, "mode": "private" })),
    );
    assert_eq!(status, 200, "enabling {eco}: {body}");
}
