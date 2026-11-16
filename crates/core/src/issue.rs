//! Parse results: every problem carries a JSON path, a stable code and a message in plain words.

use serde::Serialize;

/// One finding about an input document. `path` is a JSON-pointer-like path (`items/2/url`), `code` a stable
/// machine-readable token, `message` a sentence for the person editing the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub path: String,
    pub code: &'static str,
    pub message: String,
}

impl Issue {
    pub fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self { path: path.into(), code, message: message.into() }
    }
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{} ({})", self.message, self.code)
        } else {
            write!(f, "{}: {} ({})", self.path, self.message, self.code)
        }
    }
}

/// Collects errors (the document is refused) and warnings (it is accepted; something was dropped).
#[derive(Debug, Default)]
pub(crate) struct Issues {
    pub errors: Vec<Issue>,
    pub warnings: Vec<Issue>,
}

impl Issues {
    pub fn error(&mut self, path: &str, code: &'static str, message: impl Into<String>) {
        self.errors.push(Issue::new(path, code, message));
    }
    pub fn warn(&mut self, path: &str, code: &'static str, message: impl Into<String>) {
        self.warnings.push(Issue::new(path, code, message));
    }
}

/// Joins a path and a key: `join("items/2", "url")` is `items/2/url`.
pub(crate) fn join(base: &str, key: impl std::fmt::Display) -> String {
    if base.is_empty() { key.to_string() } else { format!("{base}/{key}") }
}
