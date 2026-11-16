//! The shared parser vectors (`fixtures/manifests.json`) and property tests of the trust boundary.

use link_in_bio_core::manifest::{Owner, ParseOptions};
use link_in_bio_core::render::{AssetUrls, Footer, PageContext, render_page};
use link_in_bio_core::{interop, parse};
use proptest::prelude::*;
use serde_json::Value;

fn opts(owner: Option<&str>) -> ParseOptions {
    match owner {
        Some("operator") => ParseOptions { owner: Owner::Operator, check_reserved: false },
        _ => ParseOptions { owner: Owner::Tenant, check_reserved: true },
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[test]
fn shared_vectors() {
    let file: Value = serde_json::from_str(include_str!("../../../fixtures/manifests.json")).unwrap();
    for case in file["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bytes = match case.get("text") {
            Some(t) => t.as_str().unwrap().as_bytes().to_vec(),
            None => serde_json::to_vec(&case["document"]).unwrap(),
        };
        let expect = &case["expect"];
        let codes = |k: &str| -> Vec<String> {
            expect[k]
                .as_array()
                .map(|a| a.iter().map(|c| c.as_str().unwrap().to_string()).collect())
                .unwrap_or_default()
        };
        match parse(&bytes, opts(case["owner"].as_str())) {
            Ok(p) => {
                assert!(expect["ok"].as_bool().unwrap(), "{name}: expected refusal, got {:?}", p.manifest);
                let got = sorted(p.warnings.iter().map(|w| w.code.to_string()).collect());
                assert_eq!(got, sorted(codes("warnings")), "{name}: warnings");
            }
            Err(errors) => {
                assert!(!expect["ok"].as_bool().unwrap(), "{name}: expected acceptance, got {errors:?}");
                let got = sorted(errors.iter().map(|e| e.code.to_string()).collect());
                let mut want = sorted(codes("codes"));
                want.dedup();
                let mut got_dedup = got.clone();
                got_dedup.dedup();
                assert_eq!(got_dedup, want, "{name}: errors {errors:?}");
            }
        }
    }
}

fn cx() -> PageContext {
    PageContext {
        canonical: "https://ada.example.org/".into(),
        assets: AssetUrls { css: "/_/p.css".into(), js: "/_/e.js".into(), icons: "/_/i.svg".into() },
        avatar: None,
        owner: Owner::Tenant,
        footer: Footer::default(),
        brand_icons: false,
        explorer: "https://suivision.xyz".into(),
        linkset_url: None,
        actor_url: Some("https://ada.example.org/actor".into()),
        inline_sprite: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Whatever text a person types, if it is accepted it appears in the page only as text: never as markup.
    #[test]
    fn accepted_text_is_always_escaped(name in "\\PC{1,40}", title in "\\PC{1,40}", bio in "\\PC{0,60}") {
        let doc = serde_json::json!({
            "schema": 1,
            "identity": { "displayName": name, "handle": "ada", "bio": bio },
            "items": [{ "id": "a", "title": title, "url": "https://example.org/" }]
        });
        if let Ok(p) = parse(&serde_json::to_vec(&doc).unwrap(), ParseOptions::default()) {
            // The same page with plain words in place of the typed text: escaping adds no markup, so the number of
            // tags (every `<` in the document) must be identical.
            let mut plain = p.manifest.clone();
            plain.identity.display_name = "x".into();
            plain.identity.bio = p.manifest.identity.bio.as_ref().map(|_| "x".to_string());
            if let link_in_bio_core::manifest::Item::Link(l) = &mut plain.items[0] {
                l.title = "x".into();
            }
            let html = render_page(&p.manifest, &cx());
            let reference = render_page(&plain, &cx());
            prop_assert_eq!(html.matches('<').count(), reference.matches('<').count());
            let jsonld = interop::json_ld_for_html(&p.manifest, &cx());
            prop_assert!(!jsonld.contains('<'));
        }
    }

    /// The parser returns (never panics) on any JSON at all.
    #[test]
    fn parser_never_panics(v in arb_json()) {
        let _ = link_in_bio_core::manifest::parse_value(&v, ParseOptions::default());
    }
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        "\\PC{0,20}".prop_map(Value::String),
        Just(Value::String("https://example.org/".into())),
        Just(Value::from(1)),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(
                prop_oneof![
                    Just("schema".to_string()),
                    Just("identity".to_string()),
                    Just("items".to_string()),
                    Just("theme".to_string()),
                    Just("displayName".to_string()),
                    Just("handle".to_string()),
                    Just("kind".to_string()),
                    Just("url".to_string()),
                    Just("id".to_string()),
                    Just("title".to_string()),
                    "[a-z]{1,8}"
                ],
                inner,
                0..8
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}
