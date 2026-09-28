//! The UI: three files, compiled into the binary.
//!
//! No build step and no framework. A registry's interface is a handful of
//! tables and forms over the REST API, and an install that needs Node to
//! build its admin screen is an install with a second toolchain to keep
//! current. Everything the UI does is a call to `/api/v1/`, so anything
//! it can do a script can do too.
//!
//! Served with a Content-Security-Policy that admits scripts from this
//! origin only, and never inline: the UI renders package names, which
//! whoever publishes chooses, and a policy that refused inline script is
//! the second wall behind `textContent`.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::app::SharedState;

const INDEX: &str = include_str!("ui/index.html");
const CSS: &str = include_str!("ui/app.css");
const JS: &str = include_str!("ui/app.js");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                   img-src 'self' data:; connect-src 'self'; base-uri 'none'; \
                   form-action 'self'; frame-ancestors 'none'";

fn file(body: &'static str, content_type: &'static str, cache: &'static str) -> Response {
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    r
}

pub fn routes() -> Router<SharedState> {
    // The page is re-read on every visit so an upgrade is picked up; the
    // script and stylesheet may be cached briefly — they change only
    // with the binary, and the page names them afresh each time.
    Router::new()
        .route(
            "/",
            get(|| async { file(INDEX, "text/html; charset=utf-8", "no-cache") }),
        )
        .route(
            "/ui/app.css",
            get(|| async { file(CSS, "text/css; charset=utf-8", "max-age=300") }),
        )
        .route(
            "/ui/app.js",
            get(|| async { file(JS, "text/javascript; charset=utf-8", "max-age=300") }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The UI's first rule, checked where it can be: nothing in the
    /// script assigns markup. A package name reaches the page as text or
    /// not at all.
    #[test]
    fn the_script_never_assigns_markup() {
        // As code — a property or a call — not as the word, which the
        // comment forbidding it has to be able to say.
        for sink in [
            ".innerHTML",
            ".outerHTML",
            ".insertAdjacentHTML(",
            "document.write(",
        ] {
            assert!(!JS.contains(sink), "app.js uses {sink}");
        }
        assert!(
            !INDEX.contains("<script>"),
            "an inline script would need an unsafe CSP"
        );
        assert!(INDEX.contains(r#"<script src="/ui/app.js""#));
    }

    /// Every state-changing request from the browser carries the header
    /// the server's CSRF wall asks for.
    #[test]
    fn the_script_sends_the_csrf_header() {
        assert!(JS.contains(&format!("\"{}\": \"1\"", crate::app::CSRF_HEADER)));
    }
}
