//! Passkey ceremonies end to end against a software authenticator (webauthn-authenticator-rs `SoftPasskey`), with the
//! state serialised to JSON in between, as the service stores it.

use link_in_bio_auth::passkey::{LoginState, Passkeys};
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

const RP: &str = "app.example.link";
const ORIGIN: &str = "https://app.example.link";

fn json<T: serde::Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap()
}

#[test]
fn register_then_sign_in_by_handle() {
    let pk = Passkeys::new(RP, ORIGIN, "Link in Bio").unwrap();
    let account = Uuid::new_v4();
    // `true`: the software token reports user verification (it has no PIN or biometric to check).
    let mut device = SoftPasskey::new(true);
    let origin = Url::parse(ORIGIN).unwrap();

    let (options, state) = pk.start_register(account, "alice", &[]).unwrap();
    assert_eq!(options["publicKey"]["rp"]["id"], RP);
    let response = device.do_registration(origin.clone(), serde_json::from_value(options).unwrap()).unwrap();
    let (cred_id, stored) = pk.finish_register(&json(&response), &state).unwrap();
    assert!(!cred_id.is_empty());
    // The same response cannot be registered twice against a fresh ceremony's state.
    let (_, other_state) = pk.start_register(account, "alice", std::slice::from_ref(&stored)).unwrap();
    assert!(pk.finish_register(&json(&response), &other_state).is_err());

    let (options, login) = pk.start_login(account, std::slice::from_ref(&stored)).unwrap();
    let login: LoginState = serde_json::from_value(json(&login)).unwrap();
    let assertion = device.do_authentication(origin.clone(), serde_json::from_value(options).unwrap()).unwrap();
    let assertion = json(&assertion);
    let (seen, _user) = Passkeys::credential_of(&assertion).unwrap();
    assert_eq!(seen, cred_id);
    let updated = pk.finish_login(&assertion, &login, account, &stored).unwrap();
    assert!(updated.is_object());
    // The same assertion for another account, or replayed against a new ceremony, fails.
    assert!(pk.finish_login(&assertion, &login, Uuid::new_v4(), &stored).is_err());
    let (_, fresh) = pk.start_login(account, std::slice::from_ref(&updated)).unwrap();
    assert!(pk.finish_login(&assertion, &fresh, account, &updated).is_err());
}

#[test]
fn user_verification_is_required() {
    let pk = Passkeys::new(RP, ORIGIN, "Link in Bio").unwrap();
    // The options require user verification, so an authenticator that cannot verify the user refuses to register.
    let mut device = SoftPasskey::new(false);
    let (options, _state) = pk.start_register(Uuid::new_v4(), "bob", &[]).unwrap();
    assert_eq!(options["publicKey"]["authenticatorSelection"]["userVerification"], "required");
    assert!(device.do_registration(Url::parse(ORIGIN).unwrap(), serde_json::from_value(options).unwrap()).is_err());
}

#[test]
fn another_origin_is_refused() {
    let pk = Passkeys::new(RP, ORIGIN, "Link in Bio").unwrap();
    let mut device = SoftPasskey::new(true);
    let (options, state) = pk.start_register(Uuid::new_v4(), "carol", &[]).unwrap();
    // A tenant page on a sibling host is not the RP's origin.
    let r = device
        .do_registration(Url::parse("https://carol.example.link").unwrap(), serde_json::from_value(options).unwrap());
    if let Ok(r) = r {
        assert!(pk.finish_register(&json(&r), &state).is_err());
    }
}

#[test]
fn discoverable_options_have_no_mediation() {
    let pk = Passkeys::new(RP, ORIGIN, "Link in Bio").unwrap();
    let (options, state) = pk.start_discoverable().unwrap();
    assert!(options.get("mediation").is_none());
    assert!(matches!(state, LoginState::Discoverable { .. }));
    assert_eq!(options["publicKey"]["userVerification"], "required");
}
