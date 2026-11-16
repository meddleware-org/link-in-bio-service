//! The OpenAPI 3.1 documents of the app and admin APIs, built from the route tables. Committed as
//! `openapi/app.json` and `openapi/admin.json`; a test fails when they differ from what the tables generate
//! (`UPDATE_OPENAPI=1 cargo test -p link-in-bio-api openapi` rewrites them).

use serde_json::{Map, Value, json};

use super::routes::{ADMIN_ROUTES, APP_ROUTES, Auth, Route};

fn params(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
        .collect()
}

fn operation(r: &Route) -> Value {
    let security = match r.auth {
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

fn build(title: &str, description: &str, routes: &[Route]) -> Value {
    let mut paths = Map::new();
    for r in routes {
        if let Some(m) = paths.entry(r.path).or_insert_with(|| json!({})).as_object_mut() {
            m.insert(r.method.as_str().into(), operation(r));
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": title, "version": env!("CARGO_PKG_VERSION"), "description": description,
            "license": { "name": "0BSD", "identifier": "0BSD" },
        },
        "paths": paths,
        "components": {
            "securitySchemes": {
                "session": { "type": "apiKey", "in": "cookie", "name": link_in_bio_auth::session::COOKIE },
                "access": { "type": "apiKey", "in": "header", "name": "Cf-Access-Jwt-Assertion" },
            },
            "schemas": {
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

pub fn app_document() -> Value {
    build(
        "Link in Bio app API",
        "The account API on the app host. State-changing requests need Origin = the app origin and the \
         X-Link-In-Bio-Request header.",
        APP_ROUTES,
    )
}

pub fn admin_document() -> Value {
    build(
        "Link in Bio admin API",
        "The operator console's API, behind Cloudflare Access and the LinkInBio Keto role.",
        ADMIN_ROUTES,
    )
}
