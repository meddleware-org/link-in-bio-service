//! Bank transfer, on open standards and without a payment provider's frontend:
//!
//! - **SEPA** (EUR): the buyer's banking app scans an EPC QR code (EPC069-12; the same data as CEN EN 18184) with the
//!   payee, IBAN, amount and an ISO 11649 creditor reference (`RF…`), and pays by SEPA (Instant) Credit Transfer.
//! - **Faster Payments** (GBP): sort code, account number and the same `RF…` reference.
//!
//! The checkout is the reference. Payments are matched from the receiving bank's ISO 20022 statements:
//! camt.054 (debit/credit notification) or camt.053 (statement), which the operator imports in the console, or the
//! receiving bank's own API ([`crate::bank_feed`]: Wise, bunq, Revolut Business), which the worker polls. Every
//! credit whose reference names an open checkout, for at least its amount and in its currency, pays it. There are
//! no notifications to verify.
//!
//! The operator is the seller. The receiving bank's fees are not known in advance; there is no fixed fee per payment
//! here, so one month is the minimum.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::{
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, ProviderEvent, Seller,
};

pub const ID: &str = "bank-transfer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    Sepa { iban: String, bic: Option<String>, eur_cents_per_month: u64 },
    FasterPayments { sort_code: String, account_number: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub payee: String,
    pub scheme: Scheme,
}

pub struct BankTransfer {
    config: Config,
}

impl BankTransfer {
    pub fn new(config: Config) -> Result<Self, BillingError> {
        let bad = |m: &str| Err(BillingError::Malformed(m.into()));
        if config.payee.trim().is_empty() || config.payee.chars().count() > 70 {
            return bad("the payee name is 1 to 70 characters");
        }
        match &config.scheme {
            Scheme::Sepa { iban, bic, eur_cents_per_month } => {
                if !iban_valid(iban) {
                    return bad("the IBAN is not valid");
                }
                if bic
                    .as_ref()
                    .is_some_and(|b| !(b.len() == 8 || b.len() == 11) || !b.bytes().all(|c| c.is_ascii_alphanumeric()))
                {
                    return bad("the BIC is 8 or 11 letters and digits");
                }
                if *eur_cents_per_month == 0 {
                    return bad("the EUR price of a month is not set");
                }
            }
            Scheme::FasterPayments { sort_code, account_number } => {
                let sc: String = sort_code.chars().filter(char::is_ascii_digit).collect();
                if sc.len() != 6 || account_number.len() != 8 || !account_number.bytes().all(|b| b.is_ascii_digit()) {
                    return bad("a sort code has 6 digits and an account number 8");
                }
            }
        }
        Ok(Self { config })
    }
}

fn mod97(digits: &str) -> u32 {
    digits.bytes().fold(0u32, |acc, b| (acc * 10 + u32::from(b - b'0')) % 97)
}

/// Letters as numbers (A = 10 … Z = 35), digits as themselves (the ISO 7064 MOD 97-10 conversion).
fn numeric(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '0'..='9' => out.push(c),
            'A'..='Z' => out.push_str(&(u32::from(c) - u32::from('A') + 10).to_string()),
            _ => return None,
        }
    }
    Some(out)
}

/// The ISO 11649 creditor reference for a reference body (1 to 21 of A–Z 0–9): `RF` + two check digits + the body.
pub fn creditor_reference(body: &str) -> Option<String> {
    let body = body.to_ascii_uppercase();
    if body.is_empty() || body.len() > 21 || !body.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let n = numeric(&format!("{body}RF00"))?;
    Some(format!("RF{:02}{body}", 98 - mod97(&n)))
}

/// Whether a creditor reference is well formed and its check digits hold.
pub fn reference_valid(r: &str) -> bool {
    let r: String = r.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    if !r.starts_with("RF") || r.len() < 5 || r.len() > 25 {
        return false;
    }
    let (head, body) = r.split_at(4);
    numeric(&format!("{body}{head}")).is_some_and(|n| mod97(&n) == 1)
}

pub fn iban_valid(iban: &str) -> bool {
    let i: String = iban.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    if i.len() < 15 || i.len() > 34 || !i[..2].bytes().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    let (head, rest) = i.split_at(4);
    numeric(&format!("{rest}{head}")).is_some_and(|n| mod97(&n) == 1)
}

/// The EPC QR code payload (EPC069-12 version 002, UTF-8, SEPA Credit Transfer) with a structured reference.
pub fn epc_payload(payee: &str, iban: &str, bic: Option<&str>, amount_cents: u64, reference: &str) -> String {
    let iban: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
    format!(
        "BCD\n002\n1\nSCT\n{}\n{}\n{}\nEUR{}.{:02}\n\n{}\n\n",
        bic.unwrap_or(""),
        payee.chars().take(70).collect::<String>(),
        iban,
        amount_cents / 100,
        amount_cents % 100,
        reference
    )
}

#[async_trait::async_trait]
impl BillingProvider for BankTransfer {
    fn id(&self) -> &'static str {
        ID
    }

    fn methods(&self) -> Vec<Method> {
        let (id, label) = match self.config.scheme {
            Scheme::Sepa { .. } => ("sepa", "Bank transfer (SEPA, scan with your banking app)"),
            Scheme::FasterPayments { .. } => ("faster-payments", "Bank transfer (Faster Payments)"),
        };
        vec![Method {
            id: format!("{ID}:{id}"),
            provider: ID.into(),
            label: label.into(),
            seller: Seller::Operator,
            fees: Fees { fixed_pence: 0, percent_bps: 0 },
            recurring: false,
        }]
    }

    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        if !self.methods().iter().any(|m| m.id == req.method) {
            return Err(BillingError::NotOffered);
        }
        // 20 characters of the checkout id: unique, and short enough to type.
        let body: String = req.checkout_id.simple().to_string().to_ascii_uppercase().chars().take(20).collect();
        let reference = creditor_reference(&body).ok_or_else(|| BillingError::Malformed("reference".into()))?;
        let client = match &self.config.scheme {
            Scheme::Sepa { iban, bic, eur_cents_per_month } => {
                let cents = eur_cents_per_month * u64::from(req.months);
                json!({
                    "kind": "bank-transfer", "scheme": "sepa", "payee": self.config.payee, "iban": iban, "bic": bic,
                    "sortCode": null, "accountNumber": null, "currency": "EUR",
                    "amount": format!("{}.{:02}", cents / 100, cents % 100), "amountMinor": cents, "reference": reference,
                    "qr": epc_payload(&self.config.payee, iban, bic.as_deref(), cents, &reference),
                })
            }
            Scheme::FasterPayments { sort_code, account_number } => json!({
                "kind": "bank-transfer", "scheme": "faster-payments", "payee": self.config.payee, "iban": null, "bic": null,
                "sortCode": sort_code, "accountNumber": account_number, "currency": "GBP",
                "amount": format!("{}.{:02}", req.amount_pence / 100, req.amount_pence % 100), "amountMinor": req.amount_pence,
                "reference": reference, "qr": null,
            }),
        };
        Ok(CheckoutStart { provider_ref: reference, client })
    }

    async fn verify_notification(
        &self,
        _: &BTreeMap<String, String>,
        _: &[u8],
        _: DateTime<Utc>,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        // Bank transfers arrive as statements the operator imports (`credits_from_camt`), never as notifications.
        Err(BillingError::Unauthentic)
    }

    async fn checkout_outcome(&self, _: &str) -> Result<Outcome, BillingError> {
        Ok(Outcome::Open)
    }
}

/// One incoming credit from a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    pub reference: String,
    pub amount_minor: u64,
    pub currency: String,
    pub booked: Option<String>,
    /// The bank's own id of the entry (the account servicer reference), for the ledger.
    pub entry: String,
}

/// A decimal amount (`12.5`, `9`, `3.00`; at most two decimals, never negative) in minor units.
pub fn amount_minor(s: &str) -> Option<u64> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 2
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let f = format!("{frac:0<2}");
    whole.parse::<u64>().ok()?.checked_mul(100)?.checked_add(f.parse::<u64>().ok()?)
}

/// The first whole, valid creditor reference (`RF…`) in free text (a payment's description or remittance line). A
/// reference split by spaces is not trusted.
pub fn reference_in_text(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_uppercase)
        .find(|w| w.starts_with("RF") && reference_valid(w))
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, local: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == local)
}

/// Reads the credits (CRDT, booked) with a valid creditor reference out of a camt.053 or camt.054 document (any
/// version: elements are matched by local name). The reference is taken from the structured remittance
/// (`Strd/CdtrRefInf/Ref`), or from the unstructured text when it contains one.
pub fn credits_from_camt(xml: &str) -> Result<Vec<Credit>, BillingError> {
    let doc =
        roxmltree::Document::parse(xml).map_err(|e| BillingError::Malformed(format!("not an XML statement: {e}")))?;
    let name = |n: &roxmltree::Node, l: &str| n.is_element() && n.tag_name().name() == l;
    let mut out = Vec::new();
    for ntry in doc.descendants().filter(|n| name(n, "Ntry")) {
        if child(ntry, "CdtDbtInd").and_then(|n| n.text()) != Some("CRDT") {
            continue;
        }
        if let Some(sts) = child(ntry, "Sts") {
            let code = child(sts, "Cd").and_then(|n| n.text()).or(sts.text()).unwrap_or("").trim();
            if !code.is_empty() && code != "BOOK" {
                continue;
            }
        }
        let entry = child(ntry, "AcctSvcrRef").and_then(|n| n.text()).unwrap_or("").trim().to_string();
        let booked = child(ntry, "BookgDt")
            .and_then(|d| d.children().find(|n| n.is_element()).and_then(|n| n.text()))
            .map(String::from);
        // One entry may batch several transactions; each carries its own reference and amount.
        let txs: Vec<_> = ntry.descendants().filter(|n| name(n, "TxDtls")).collect();
        let parts: Vec<roxmltree::Node> = if txs.is_empty() { vec![ntry] } else { txs };
        for (i, part) in parts.into_iter().enumerate() {
            let amt = part
                .descendants()
                .find(|n| name(n, "Amt") && n.attribute("Ccy").is_some())
                .or_else(|| child(ntry, "Amt"));
            let Some(amt) = amt else { continue };
            let (Some(currency), Some(minor)) = (amt.attribute("Ccy"), amt.text().and_then(amount_minor)) else {
                continue;
            };
            let structured =
                part.descendants().find(|n| name(n, "CdtrRefInf")).and_then(|r| child(r, "Ref")).and_then(|n| n.text());
            let unstructured =
                part.descendants().filter(|n| name(n, "Ustrd")).filter_map(|n| n.text()).collect::<Vec<_>>().join(" ");
            let candidate = structured.map(String::from).or_else(|| reference_in_text(&unstructured));
            let Some(reference) =
                candidate.map(|r| r.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase())
            else {
                continue;
            };
            if !reference_valid(&reference) {
                continue;
            }
            out.push(Credit {
                reference,
                amount_minor: minor,
                currency: currency.to_string(),
                booked: booked.clone(),
                entry: if entry.is_empty() { format!("entry-{i}") } else { format!("{entry}-{i}") },
            });
        }
    }
    Ok(out)
}

/// The ledger event for a credit that pays its checkout.
pub fn paid_event(c: &Credit) -> ProviderEvent {
    ProviderEvent {
        event_id: format!("paid:{}", c.reference),
        provider_ref: c.reference.clone(),
        outcome: Outcome::Paid,
        months: None,
        evidence: json!({ "entry": c.entry, "amountMinor": c.amount_minor, "currency": c.currency, "booked": c.booked }),
    }
}

/// What a checkout's client data says it expects (amount in minor units, currency), to match a credit against.
pub fn expected(client: &Value) -> Option<(u64, String)> {
    Some((client["amountMinor"].as_u64()?, client["currency"].as_str()?.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creditor_references() {
        // The ISO 11649 example.
        assert_eq!(creditor_reference("539007547034").as_deref(), Some("RF18539007547034"));
        assert!(reference_valid("RF18 5390 0754 7034"));
        assert!(!reference_valid("RF19539007547034"));
        assert!(creditor_reference("").is_none());
        assert!(creditor_reference(&"A".repeat(22)).is_none());
        let r = creditor_reference("ABC123XYZ").unwrap();
        assert!(reference_valid(&r));
    }

    #[test]
    fn ibans_and_epc() {
        assert!(iban_valid("DE89 3704 0044 0532 0130 00"));
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(!iban_valid("DE89370400440532013001"));
        let p = epc_payload("Example Ltd", "DE89 3704 0044 0532 0130 00", None, 350, "RF18539007547034");
        let lines: Vec<&str> = p.split('\n').collect();
        assert_eq!(
            &lines[..10],
            &["BCD", "002", "1", "SCT", "", "Example Ltd", "DE89370400440532013000", "EUR3.50", "", "RF18539007547034"]
        );
    }

    #[test]
    fn amounts() {
        assert_eq!(amount_minor("12.5"), Some(1250));
        assert_eq!(amount_minor("9"), Some(900));
        assert_eq!(amount_minor("3.00"), Some(300));
        assert_eq!(amount_minor("1.234"), None);
        assert_eq!(amount_minor("-1"), None);
    }

    #[test]
    fn camt_054_and_053() {
        let camt054 = r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.054.001.08"><BkToCstmrDbtCdtNtfctn><Ntfctn>
  <Ntry><Amt Ccy="EUR">3.50</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts><BookgDt><Dt>2026-11-17</Dt></BookgDt>
    <AcctSvcrRef>E1</AcctSvcrRef>
    <NtryDtls><TxDtls><Amt Ccy="EUR">3.50</Amt><RmtInf><Strd><CdtrRefInf><Ref>RF18539007547034</Ref></CdtrRefInf></Strd></RmtInf></TxDtls></NtryDtls></Ntry>
  <Ntry><Amt Ccy="EUR">9.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts></Ntry>
  <Ntry><Amt Ccy="EUR">1.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>PDNG</Cd></Sts>
    <NtryDtls><TxDtls><RmtInf><Ustrd>RF18539007547034</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>
</Ntfctn></BkToCstmrDbtCdtNtfctn></Document>"#;
        let c = credits_from_camt(camt054).unwrap();
        assert_eq!(c.len(), 1, "debits and pending entries are not payments");
        assert_eq!(
            (c[0].reference.as_str(), c[0].amount_minor, c[0].currency.as_str()),
            ("RF18539007547034", 350, "EUR")
        );
        assert_eq!(c[0].booked.as_deref(), Some("2026-11-17"));
        // camt.053 (older version, status as text), the reference only in the unstructured remittance.
        let camt053 = r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.02"><BkToCstmrStmt><Stmt>
  <Ntry><Amt Ccy="GBP">9.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts>BOOK</Sts><AcctSvcrRef>X9</AcctSvcrRef>
    <NtryDtls><TxDtls><RmtInf><Ustrd>Thanks RF18 539007547034 for links</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>
  <Ntry><Amt Ccy="GBP">9.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts>BOOK</Sts>
    <NtryDtls><TxDtls><RmtInf><Ustrd>RF18539007547034</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>
</Stmt></BkToCstmrStmt></Document>"#;
        let c = credits_from_camt(camt053).unwrap();
        assert_eq!(c.len(), 1, "a reference split by a space in free text is not trusted; only a whole one");
        assert_eq!(c[0].amount_minor, 900);
        assert!(credits_from_camt("not xml").is_err());
    }
}
