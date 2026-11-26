//! The route tables: every route of the app and admin APIs once, with what it is for. The OpenAPI documents are
//! built from these (openapi.rs) and a test sends a request to every entry, so the contract, the routers and the
//! documentation cannot drift apart.

/// The HTTP methods the APIs use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A read.
    Get,
    /// An action or a create.
    Post,
    /// A replace.
    Put,
    /// A removal.
    Delete,
}

impl Method {
    /// The method's lower-case name, as OpenAPI writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            // The names are the lower-case forms OpenAPI uses.
            Method::Get => "get",
            Method::Post => "post",
            Method::Put => "put",
            Method::Delete => "delete",
        }
    }
}

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// Anyone (state-changing requests still pass the CSRF rule).
    Public,
    /// A signed-in account (the session cookie).
    Session,
    /// The operator (Cloudflare Access and the Keto role).
    Operator,
}

/// One route: its method and path (with `{name}` for a parameter), what it is for, and who may call it.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// The HTTP method.
    pub method: Method,
    /// The path, with `{name}` for each parameter.
    pub path: &'static str,
    /// What the route is for, in one line.
    pub summary: &'static str,
    /// Who may call it.
    pub auth: Auth,
}

/// A route in a table; a `const fn`, so the tables are constants.
const fn r(method: Method, path: &'static str, auth: Auth, summary: &'static str) -> Route {
    // The fields in the order the tables write them.
    Route { method, path, summary, auth }
}

// The names are used bare in the tables, so each row stays on one line.
use Auth::{Operator, Public, Session};
use Method::{Delete, Get, Post, Put};

/// Every route of the app API (the account API on the app host).
pub const APP_ROUTES: &[Route] = &[
    // What the instance offers, public, so a sign-up page can show it.
    r(Get, "/api/v1/instance", Public, "What this instance offers: product, sign-up mode, price, switches"),
    r(Get, "/api/v1/limits", Public, "Every bound the page parser enforces"),
    r(
        Post,
        "/api/v1/signup/start",
        Public,
        "Begin creating an account (18+, terms, handle, invite) with a passkey or a Sui wallet",
    ),
    r(Post, "/api/v1/signup/finish", Public, "Finish creating the account; returns its recovery codes once"),
    // Sign-in: passkey, wallet, recovery code, and sign-out.
    r(Post, "/api/v1/login/passkey/start", Public, "Begin a passkey sign-in (with a handle, or discoverable)"),
    r(Post, "/api/v1/login/passkey/finish", Public, "Finish a passkey sign-in"),
    r(Post, "/api/v1/login/wallet/start", Public, "The message a Sui wallet signs to sign in"),
    r(Post, "/api/v1/login/wallet/finish", Public, "Finish a Sui wallet sign-in"),
    r(Post, "/api/v1/login/recovery", Public, "Sign in with a one-use recovery code"),
    r(Post, "/api/v1/logout", Public, "End this session"),
    // The signed-in account: its details, deletion, export and country.
    r(Get, "/api/v1/me", Session, "The account, its sign-in methods and its paid period"),
    r(Delete, "/api/v1/me", Session, "Delete the account (type the handle to confirm)"),
    r(Get, "/api/v1/me/export", Session, "Everything stored about the account, as JSON"),
    r(Put, "/api/v1/me/country", Session, "Declare the account's country (tax evidence)"),
    // Sign-in methods: passkeys, wallets and recovery codes, never removing the last way in.
    r(Post, "/api/v1/me/passkeys/start", Session, "Begin adding a passkey"),
    r(Post, "/api/v1/me/passkeys/finish", Session, "Finish adding a passkey"),
    r(Delete, "/api/v1/me/passkeys/{id}", Session, "Remove a passkey (never the last way to sign in)"),
    r(Post, "/api/v1/me/wallets/start", Session, "Begin linking a Sui wallet"),
    r(Post, "/api/v1/me/wallets/finish", Session, "Finish linking a Sui wallet"),
    r(Delete, "/api/v1/me/wallets/{address}", Session, "Unlink a wallet (never the last way to sign in)"),
    r(Post, "/api/v1/me/recovery-codes", Session, "Replace the recovery codes; returns the new ones once"),
    // Decisions about the account, and the invites it may pass on.
    r(Get, "/api/v1/me/statements", Session, "Decisions about the account's page and its appeals"),
    r(Get, "/api/v1/me/invites", Session, "Invite codes the operator gave this account to pass on"),
    // The page: draft, preview, publish, unpublish, versions and the picture.
    r(Get, "/api/v1/page", Session, "The draft, its problems and its links' screening"),
    r(Put, "/api/v1/page", Session, "Save the draft (checked by the page parser)"),
    r(Get, "/api/v1/page/preview", Session, "The draft rendered, for the editor's sandboxed preview"),
    r(Post, "/api/v1/page/publish", Session, "Publish the draft (needs a paid period or a free account)"),
    r(Post, "/api/v1/page/unpublish", Session, "Take the page offline"),
    r(Get, "/api/v1/page/versions", Session, "Published versions (the last 20)"),
    r(Post, "/api/v1/page/versions/{version}/restore", Session, "Copy a published version into the draft"),
    r(Post, "/api/v1/page/avatar", Session, "Upload a picture (re-encoded, at most 400 x 400 and 64 KiB)"),
    // A stored picture, public, by its hash.
    r(Get, "/api/v1/assets/{file}", Public, "A stored picture by its SHA-256"),
    // Billing: methods, checkouts and refunds.
    r(Get, "/api/v1/billing", Session, "The paid period, the payment methods offered and past payments"),
    r(Post, "/api/v1/billing/checkouts", Session, "Start paying for months with one method"),
    r(Get, "/api/v1/billing/checkouts/{id}", Session, "How a checkout stands"),
    r(
        Post,
        "/api/v1/billing/events/{id}/refund-request",
        Session,
        "Ask for a refund of an unapplied Chain Payments payment instead of its months (within 30 days, once)",
    ),
    r(
        Get,
        "/api/v1/billing/refunds",
        Session,
        "What may be refunded now, worked out exactly: cancellations (14 days), unstarted months, late payments",
    ),
    r(
        Post,
        "/api/v1/billing/refund-requests",
        Session,
        "Ask for a refund (cancel, unstarted or unapplied); one open request per account, sent by the operator by hand",
    ),
    r(Post, "/api/v1/billing/refund-requests/{id}/withdraw", Session, "Withdraw the account's open refund request"),
    r(
        Post,
        "/api/v1/billing/checkouts/{id}/open-payments",
        Session,
        "Open Payments: the buyer's wallet address; returns the wallet's approval page to redirect to",
    ),
    r(
        Post,
        "/api/v1/billing/checkouts/{id}/open-payments/finish",
        Session,
        "Open Payments: back from the wallet (hash, interactRef); sends the payment",
    ),
    // Custom domains.
    r(Get, "/api/v1/domains", Session, "Custom domains and the TXT records that verify them"),
    r(Post, "/api/v1/domains", Session, "Add a custom domain (when custom domains are on)"),
    r(Delete, "/api/v1/domains/{hostname}", Session, "Remove a custom domain"),
    // Reports need no account; appeals do.
    r(Post, "/api/v1/reports", Public, "Report a page or a link (no account needed)"),
    r(Post, "/api/v1/appeals", Session, "Appeal a decision about the account's page"),
    r(
        Post,
        // A provider's signed notification; its signature is the authentication.
        "/api/v1/webhooks/{provider}",
        Public,
        "A payment provider's signed notification (square, gocardless, paddle)",
    ),
];

/// Every route of the admin API (the operator console's API).
pub const ADMIN_ROUTES: &[Route] = &[
    // The operator's own details and the overview.
    r(Get, "/api/v1/admin/me", Operator, "The operator signed in"),
    r(Get, "/api/v1/admin/overview", Operator, "Counts, queues and the switches"),
    // Accounts: list, one, flags, suspension and grants.
    r(Get, "/api/v1/admin/accounts", Operator, "Accounts by handle prefix"),
    r(Get, "/api/v1/admin/accounts/{id}", Operator, "One account: page, invite tree, billing, domains, audit"),
    r(Put, "/api/v1/admin/accounts/{id}/flags", Operator, "Operator account, free, may pass on invites, tags"),
    r(
        Post,
        "/api/v1/admin/accounts/{id}/suspend",
        Operator,
        "Suspend (policy: 410, legal: 451) with a statement of reasons",
    ),
    r(Post, "/api/v1/admin/accounts/{id}/unsuspend", Operator, "Lift a suspension"),
    r(Post, "/api/v1/admin/accounts/{id}/grant", Operator, "Give (or take back) months"),
    // Invites and the saved selections they are issued for.
    r(Get, "/api/v1/admin/invites", Operator, "Invites issued"),
    r(Post, "/api/v1/admin/invites", Operator, "Issue invite codes (to the operator, or to an account to pass on)"),
    r(Delete, "/api/v1/admin/invites/{id}", Operator, "Revoke an unredeemed invite"),
    r(Get, "/api/v1/admin/selections", Operator, "Saved selections of accounts"),
    r(Post, "/api/v1/admin/selections", Operator, "Save a selection (criteria)"),
    r(Delete, "/api/v1/admin/selections/{id}", Operator, "Delete a selection"),
    r(Get, "/api/v1/admin/selections/{id}/matches", Operator, "The accounts a selection matches now"),
    r(Post, "/api/v1/admin/selections/{id}/issue", Operator, "Issue K codes to every matching account"),
    // Moderation: reports and appeals.
    r(Get, "/api/v1/admin/reports", Operator, "Reports by status"),
    r(Post, "/api/v1/admin/reports/{id}/decide", Operator, "Decide a report (and hide its link)"),
    r(Get, "/api/v1/admin/appeals", Operator, "Appeals by status"),
    r(Post, "/api/v1/admin/appeals/{id}/decide", Operator, "Decide an appeal (and reinstate)"),
    // The blocklist and operator verdicts on links.
    r(Get, "/api/v1/admin/blocklist", Operator, "The operator's blocklist"),
    r(Post, "/api/v1/admin/blocklist", Operator, "Block a host or a URL"),
    r(Delete, "/api/v1/admin/blocklist", Operator, "Unblock (?pattern=)"),
    r(Put, "/api/v1/admin/links", Operator, "An operator verdict on a link (clean, flagged, or automatic)"),
    // The audit log.
    r(Get, "/api/v1/admin/audit", Operator, "The audit log (?subject=)"),
    r(
        Get,
        // Refunds: what to send, recording a refund sent by hand, and declining.
        "/api/v1/admin/refund-requests",
        Operator,
        "Refund requests with exactly what to send per purchase (?status=open|refunded|withdrawn|declined)",
    ),
    r(
        Post,
        "/api/v1/admin/refund-requests/{id}/refunded",
        Operator,
        "Record a refund sent by hand (its reference, and the purchase when several); takes its months back once",
    ),
    r(Post, "/api/v1/admin/refund-requests/{id}/declined", Operator, "Decline an open refund request, saying why"),
    r(
        Post,
        // Bank statements imported by hand.
        "/api/v1/admin/bank-statements",
        Operator,
        "Import an ISO 20022 camt.053/054 statement: credits pay bank-transfer checkouts by reference",
    ),
];
