//! `link-in-bio-api`: the HTTP side of the service. The static router serves one page from a manifest file (the
//! operator's page); the local router is the editor's loopback backend. The hosted routers (pages by host, the
//! account API, admin) join here in the next release.

pub mod config;
pub mod headers;
pub mod local_mode;
pub mod site;
pub mod static_mode;
pub mod time;
