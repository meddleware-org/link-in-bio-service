//! The OpenAPI 3.1 documents of the app and admin APIs, built from the route tables. Committed as
//! `openapi/app.json` and `openapi/admin.json`; a test fails when they differ from what the tables generate
//! (`UPDATE_OPENAPI=1 cargo test -p link-in-bio-api openapi` rewrites them).

use serde_json::{Map, Value, json};

use super::routes::{ADMIN_ROUTES, APP_ROUTES, Auth, Route};

/// The path parameters of a route, from the `{name}` segments of its path.
fn params(path: &str) -> Vec<Value> {
    // Each `{name}` segment is a path parameter, always a string.
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
        .collect()
}

/// The OpenAPI operation for one route: its summary, its security requirement and the shared error answer.
fn operation(r: &Route) -> Value {
    // The authentication kind of the route becomes the security requirement; every route shares the one error shape.
    let security = match r.auth {
        // No security requirement for a public route.
        Auth::Public => json!([]),
        Auth::Session => json!([{ "session": [] }]),
        Auth::Operator => json!([{ "access": [] }]),
    };
    let mut op = json!({
        "summary": r.summary,
        "security": security,
        "responses": {
            "default": { "description": "An error", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } } }
        },
    });
    let p = params(r.path);
    if !p.is_empty() {
        op["parameters"] = json!(p);
    }
    op
}

/// A whole document from a title, a description and a route table: the paths grouped by path, the security schemes and the shared error schemas.
fn build(title: &str, description: &str, routes: &[Route]) -> Value {
    // Several methods on one path share one path item.
    // Paths by their text, each holding its methods.
    let mut paths = Map::new();
    for r in routes {
        if let Some(m) = paths.entry(r.path).or_insert_with(|| json!({})).as_object_mut() {
            m.insert(r.method.as_str().into(), operation(r));
        }
    }
    json!({
        // The version of the OpenAPI specification the document follows.
        "openapi": "3.1.0",
        "info": {
            "title": title, "version": env!("CARGO_PKG_VERSION"), "description": description,
            // The API description carries the same licence as the code.
            "license": { "name": "0BSD", "identifier": "0BSD" },
        },
        // The paths come from the route table.
        "paths": paths,
        "components": {
            "securitySchemes": {
                // The two ways to authenticate: the session cookie, and the operator's Access token header.
                "session": { "type": "apiKey", "in": "cookie", "name": link_in_bio_auth::session::COOKIE },
                "access": { "type": "apiKey", "in": "header", "name": "Cf-Access-Jwt-Assertion" },
            },
            "schemas": {
                // Every route may answer with this error shape (see the error module).
                "Error": {
                    "type": "object",
                    "required": ["error", "code"],
                    "properties": {
                        "error": { "type": "string", "description": "What went wrong, in plain words" },
                        "code": { "type": "string" },
                        "issues": { "type": "array", "items": { "$ref": "#/components/schemas/Issue" } },
                    },
                },
                "Issue": {
                    "type": "object",
                    "required": ["path", "code", "message"],
                    "properties": { "path": { "type": "string" }, "code": { "type": "string" }, "message": { "type": "string" } },
                },
            },
        },
    })
}

/// The app API's document.
pub fn app_document() -> Value {
    build(
        // The title of the app document.
        "Link in Bio app API",
        "The account API on the app host. State-changing requests need Origin = the app origin and the \
         X-Link-In-Bio-Request header.",
        APP_ROUTES,
    )
}

/// The admin API's document.
pub fn admin_document() -> Value {
    build(
        // The title of the admin document.
        "Link in Bio admin API",
        "The operator console's API, behind Cloudflare Access and the LinkInBio Keto role.",
        ADMIN_ROUTES,
    )
}

/// Unit tests for the OpenAPI documents.
#[cfg(test)]
mod tests {
    /// `openapi/app.json` and `openapi/admin.json` are what the route tables generate (`UPDATE_OPENAPI=1` rewrites them).
    #[test]
    fn the_committed_documents_match() {
        for (file, doc) in [("app.json", super::app_document()), ("admin.json", super::admin_document())] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../openapi").join(file);
            // The committed file is the pretty-printed document with a final newline.
            let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
            // Setting the variable rewrites the files, which is how a route change is committed.
            if std::env::var("UPDATE_OPENAPI").as_deref() == Ok("1") {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, &text).unwrap();
            }
            // A missing file reads as empty, so it fails the comparison.
            let committed = std::fs::read_to_string(&path).unwrap_or_default();
            assert_eq!(
                committed, text,
                "openapi/{file} is out of date: UPDATE_OPENAPI=1 cargo test -p link-in-bio-api"
            );
        }
    }
}
