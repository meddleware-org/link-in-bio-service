//! The manual provider: the operator grants (or takes back) months from the admin console. Nothing is bought, so it
//! offers no checkout method and receives no notification; it exists so every change to a paid period, granted or
//! bought, goes through the same ledger with a provider name.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::{BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Method, Outcome, ProviderEvent};

/// The provider id recorded in the ledger for an operator's grant.
pub const ID: &str = "manual";

/// The manual provider: a port with nothing to buy, so every payment operation is refused.
pub struct Manual;

#[async_trait::async_trait]
impl BillingProvider for Manual {
    /// The provider id.
    fn id(&self) -> &'static str {
        ID
    }

    /// No methods: a grant is never offered at checkout.
    fn methods(&self) -> Vec<Method> {
        Vec::new()
    }

    /// Always refused: nothing can be bought here.
    async fn create_checkout(&self, _: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        Err(BillingError::NotOffered)
    }

    /// Always refused: a manual grant is never notified.
    async fn verify_notification(
        &self,
        _: &BTreeMap<String, String>,
        _: &[u8],
        _: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        Err(BillingError::Unauthentic)
    }

    /// Always refused: there are no checkouts to ask about.
    async fn checkout_outcome(&self, _: &str) -> Result<Outcome, BillingError> {
        Err(BillingError::NotOffered)
    }
}
