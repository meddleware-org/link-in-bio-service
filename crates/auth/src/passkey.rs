//! Passkeys (WebAuthn level 3 through kanidm's webauthn-rs). User verification is required in every ceremony; the RP
//! ID is the app host, so a passkey made for the app is never offered to a tenant page. Ceremony state is serialised
//! and kept server-side (the store's `challenges`), never sent to the browser.
//!
//! Two sign-in flows: with a handle (the account's passkeys are listed in `allowCredentials`), and discoverable (no
//! handle: the browser offers the passkeys it holds for the RP). Both end with the credential id the browser
//! returns, which the caller resolves to an account and its stored passkey.

use serde_json::Value;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("the passkey configuration is invalid: {0}")]
    Config(String),
    #[error("the passkey response is not valid")]
    Invalid,
    #[error("the passkey could not be verified")]
    Rejected,
}

pub struct Passkeys {
    webauthn: Webauthn,
}

/// What a login ceremony expects back.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "flow", rename_all = "kebab-case")]
pub enum LoginState {
    Handle { account: Uuid, state: Value },
    Discoverable { state: Value },
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, PasskeyError> {
    serde_json::to_value(v).map_err(|_| PasskeyError::Invalid)
}

fn from_value<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, PasskeyError> {
    serde_json::from_value(v.clone()).map_err(|_| PasskeyError::Invalid)
}

impl Passkeys {
    /// `rp_id` is the app host (`app.meddleware.link`); `origin` its origin (`https://app.meddleware.link`).
    pub fn new(rp_id: &str, origin: &str, rp_name: &str) -> Result<Self, PasskeyError> {
        let origin = Url::parse(origin).map_err(|e| PasskeyError::Config(e.to_string()))?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|e| PasskeyError::Config(e.to_string()))?
            .rp_name(rp_name)
            .build()
            .map_err(|e| PasskeyError::Config(e.to_string()))?;
        Ok(Self { webauthn })
    }

    /// Options for `navigator.credentials.create` and the state to keep. `existing` are the account's passkeys (the
    /// authenticator is asked not to make a second one for the same account).
    pub fn start_register(
        &self,
        account: Uuid,
        handle: &str,
        existing: &[Value],
    ) -> Result<(Value, Value), PasskeyError> {
        let exclude: Vec<CredentialID> =
            existing.iter().filter_map(|p| from_value::<Passkey>(p).ok()).map(|p| p.cred_id().clone()).collect();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(account, handle, handle, (!exclude.is_empty()).then_some(exclude))
            .map_err(|e| PasskeyError::Config(e.to_string()))?;
        Ok((to_value(&options)?, to_value(&state)?))
    }

    /// Checks the browser's response: returns the credential id and the passkey to store.
    pub fn finish_register(&self, response: &Value, state: &Value) -> Result<(Vec<u8>, Value), PasskeyError> {
        let response: RegisterPublicKeyCredential = from_value(response)?;
        let state: PasskeyRegistration = from_value(state)?;
        let passkey =
            self.webauthn.finish_passkey_registration(&response, &state).map_err(|_| PasskeyError::Rejected)?;
        Ok((AsRef::<[u8]>::as_ref(passkey.cred_id()).to_vec(), to_value(&passkey)?))
    }

    /// A sign-in for a known account (its stored passkeys).
    pub fn start_login(&self, account: Uuid, passkeys: &[Value]) -> Result<(Value, LoginState), PasskeyError> {
        let keys: Vec<Passkey> = passkeys.iter().filter_map(|p| from_value(p).ok()).collect();
        if keys.is_empty() {
            return Err(PasskeyError::Rejected);
        }
        let (options, state) =
            self.webauthn.start_passkey_authentication(&keys).map_err(|e| PasskeyError::Config(e.to_string()))?;
        Ok((to_value(&options)?, LoginState::Handle { account, state: to_value(&state)? }))
    }

    /// A sign-in without a handle (the browser chooses among the passkeys it has for this RP).
    pub fn start_discoverable(&self) -> Result<(Value, LoginState), PasskeyError> {
        let (options, state) =
            self.webauthn.start_discoverable_authentication().map_err(|e| PasskeyError::Config(e.to_string()))?;
        let mut options = to_value(&options)?;
        // webauthn-rs asks for conditional mediation (autofill); the app's button flow asks the browser directly.
        if let Some(o) = options.as_object_mut() {
            o.remove("mediation");
        }
        Ok((options, LoginState::Discoverable { state: to_value(&state)? }))
    }

    /// The credential id a sign-in response names (look the passkey up by it).
    pub fn credential_of(response: &Value) -> Result<(Vec<u8>, Option<Uuid>), PasskeyError> {
        let r: PublicKeyCredential = from_value(response)?;
        let user = r.get_user_unique_id().and_then(|b| Uuid::from_slice(b).ok());
        Ok((r.get_credential_id().to_vec(), user))
    }

    /// Checks a sign-in response against the stored passkey of `account`. Returns the passkey to store back (its
    /// counter and backup state may have changed).
    pub fn finish_login(
        &self,
        response: &Value,
        state: &LoginState,
        account: Uuid,
        stored: &Value,
    ) -> Result<Value, PasskeyError> {
        let r: PublicKeyCredential = from_value(response)?;
        let mut passkey: Passkey = from_value(stored)?;
        if r.get_credential_id() != AsRef::<[u8]>::as_ref(passkey.cred_id()) {
            return Err(PasskeyError::Rejected);
        }
        let result = match state {
            LoginState::Handle { account: expected, state } => {
                if *expected != account {
                    return Err(PasskeyError::Rejected);
                }
                let s: PasskeyAuthentication = from_value(state)?;
                self.webauthn.finish_passkey_authentication(&r, &s)
            }
            LoginState::Discoverable { state } => {
                // A user handle, when the authenticator returns one, must name the same account.
                if let Some(u) = r.get_user_unique_id()
                    && Uuid::from_slice(u).ok() != Some(account)
                {
                    return Err(PasskeyError::Rejected);
                }
                let s: DiscoverableAuthentication = from_value(state)?;
                self.webauthn.finish_discoverable_authentication_v2(&r, s, &passkey)
            }
        }
        .map_err(|_| PasskeyError::Rejected)?;
        if !result.user_verified() {
            return Err(PasskeyError::Rejected);
        }
        passkey.update_credential(&result);
        to_value(&passkey)
    }
}
