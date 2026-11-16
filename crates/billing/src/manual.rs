//! The manual provider: the operator grants (or takes back) months from the admin console. Nothing is bought, so it
//! offers no checkout method and receives no notification; it exists so every change to a paid period, granted or
//! bought, goes through the same ledger with a provider name.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Method, Outcome, ProviderEvent};

pub const ID: &str = "manual";

pub struct Manual;

#[async_trait::async_trait]
impl BillingProvider for Manual {
    fn id(&self) -> &'static str {
        ID
    }

    fn methods(&self) -> Vec<Method> {
        Vec::new()
    }

    async fn create_checkout(&self, _: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        Err(BillingError::NotOffered)
    }

    async fn verify_notification(
        &self,
        _: &BTreeMap<String, String>,
        _: &[u8],
        _: DateTime<Utc>,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        Err(BillingError::Unauthentic)
    }

    async fn checkout_outcome(&self, _: &str) -> Result<Outcome, BillingError> {
        Err(BillingError::NotOffered)
    }
}
