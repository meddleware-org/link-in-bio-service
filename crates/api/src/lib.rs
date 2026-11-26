//! `link-in-bio-api`: the HTTP side of the service. The static router serves one page from a manifest file (the
//! operator's page); the local router is the editor's loopback backend; [`hosted`] is the hosted service (tenant
//! pages by host, the account API, the operator console's API, provider notifications, the worker).

/// The static page's site configuration.
pub mod config;
/// The security headers every page response carries.
pub mod headers;
/// The hosted service.
pub mod hosted;
/// The editor's loopback backend.
pub mod local_mode;
/// A built site: every document of one page.
pub mod site;
/// The router that serves one page from a manifest file.
pub mod static_mode;
/// RFC 3339 timestamps.
pub mod time;
