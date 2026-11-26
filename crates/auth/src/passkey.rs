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

/// Why a passkey step failed. The cause is kept coarse on purpose: a caller learns only whether the response was malformed or was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    /// The relying party was set up wrongly (its host, origin or name); a start-up error, never caused by a visitor.
    #[error("the passkey configuration is invalid: {0}")]
    Config(String),
    /// The response or the stored state could not be read.
    #[error("the passkey response is not valid")]
    Invalid,
    /// The response was well formed but did not verify: a wrong key, challenge, origin or account, or the user was not verified.
    #[error("the passkey could not be verified")]
    Rejected,
}

/// The WebAuthn relying party for the app: holds the host and origin every ceremony is bound to.
pub struct Passkeys {
    /// The library's configured relying party.
    webauthn: Webauthn,
}

/// What a login ceremony expects back.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "flow", rename_all = "kebab-case")]
pub enum LoginState {
    /// A sign-in for a named account, whose passkeys were offered.
    Handle {
        /// The account the ceremony was started for.
        account: Uuid,
        /// The library's ceremony state, as JSON.
        state: Value,
    },
    /// A sign-in without a handle, where the browser offered the passkeys it holds.
    Discoverable {
        /// The library's ceremony state, as JSON.
        state: Value,
    },
}

/// Serialise a ceremony value to JSON, so it can be stored; a failure is reported as an invalid value.
fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, PasskeyError> {
    serde_json::to_value(v).map_err(|_| PasskeyError::Invalid)
}

/// Read a ceremony value back from JSON.
fn from_value<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, PasskeyError> {
    serde_json::from_value(v.clone()).map_err(|_| PasskeyError::Invalid)
}

impl Passkeys {
    /// `rp_id` is the app host (`app.meddleware.link`); `origin` its origin (`https://app.meddleware.link`).
    pub fn new(rp_id: &str, origin: &str, rp_name: &str) -> Result<Self, PasskeyError> {
        // The origin and the host are checked by the library: the host must be a registrable suffix of the origin.
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
        // The account's existing passkeys are excluded, so an authenticator that already holds one does not make a second.
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
        // The browser's answer and the saved state are read first; anything unreadable is invalid.
        let response: RegisterPublicKeyCredential = from_value(response)?;
        let state: PasskeyRegistration = from_value(state)?;
        let passkey =
            self.webauthn.finish_passkey_registration(&response, &state).map_err(|_| PasskeyError::Rejected)?;
        Ok((AsRef::<[u8]>::as_ref(passkey.cred_id()).to_vec(), to_value(&passkey)?))
    }

    /// A sign-in for a known account (its stored passkeys).
    pub fn start_login(&self, account: Uuid, passkeys: &[Value]) -> Result<(Value, LoginState), PasskeyError> {
        // Passkeys that no longer read are skipped; with none left there is nothing to sign in with.
        let keys: Vec<Passkey> = passkeys.iter().filter_map(|p| from_value(p).ok()).collect();
        // An account with no usable passkey cannot start a passkey sign-in.
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
        // Without the `mediation` field the browser opens its own passkey chooser when the button is pressed.
        if let Some(o) = options.as_object_mut() {
            o.remove("mediation");
        }
        Ok((options, LoginState::Discoverable { state: to_value(&state)? }))
    }

    /// The credential id a sign-in response names (look the passkey up by it).
    pub fn credential_of(response: &Value) -> Result<(Vec<u8>, Option<Uuid>), PasskeyError> {
        let r: PublicKeyCredential = from_value(response)?;
        // The user handle, when the authenticator returns one, is the account id the service gave it at registration.
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
        // The response must be for the stored passkey, not another one.
        if r.get_credential_id() != AsRef::<[u8]>::as_ref(passkey.cred_id()) {
            return Err(PasskeyError::Rejected);
        }
        let result = match state {
            LoginState::Handle { account: expected, state } => {
                // The ceremony was started for one account; a response cannot be applied to another.
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
        // User verification is required even though the library does not enforce it for every flow.
        if !result.user_verified() {
            return Err(PasskeyError::Rejected);
        }
        // The counter and backup state may have changed, so the caller stores the updated passkey.
        passkey.update_credential(&result);
        to_value(&passkey)
    }
}
