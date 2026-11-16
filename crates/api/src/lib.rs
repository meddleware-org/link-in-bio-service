//! `link-in-bio-api`: the HTTP side of the service. The static router serves one page from a manifest file (the
//! operator's page); the local router is the editor's loopback backend; [`hosted`] is the hosted service (tenant
//! pages by host, the account API, the operator console's API, provider notifications, the worker).

pub mod config;
pub mod headers;
pub mod hosted;
pub mod local_mode;
pub mod site;
pub mod static_mode;
pub mod time;
