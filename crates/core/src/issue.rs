//! Parse results: every problem carries a JSON path, a stable code and a message in plain words.

use serde::Serialize;

/// One finding about an input document. `path` is a JSON-pointer-like path (`items/2/url`), `code` a stable
/// machine-readable token, `message` a sentence for the person editing the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    /// Where in the document the problem is, as a path of keys and positions.
    pub path: String,
    /// A stable token that other software can match on.
    pub code: &'static str,
    /// A sentence in plain words for the person editing the page.
    pub message: String,
}

impl Issue {
    /// An issue at `path` with a stable `code` and a plain-words `message`.
    pub fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self { path: path.into(), code, message: message.into() }
    }
}

impl std::fmt::Display for Issue {
    /// Write the issue as `path: message (code)`, or `message (code)` when it is about the whole document.
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
    /// Problems that make the document refused.
    pub errors: Vec<Issue>,
    /// Problems that are reported but do not stop the document being accepted (something was dropped).
    pub warnings: Vec<Issue>,
}

impl Issues {
    /// Record an error.
    pub fn error(&mut self, path: &str, code: &'static str, message: impl Into<String>) {
        self.errors.push(Issue::new(path, code, message));
    }
    /// Record a warning.
    pub fn warn(&mut self, path: &str, code: &'static str, message: impl Into<String>) {
        self.warnings.push(Issue::new(path, code, message));
    }
}

/// Joins a path and a key: `join("items/2", "url")` is `items/2/url`.
pub(crate) fn join(base: &str, key: impl std::fmt::Display) -> String {
    // The first key of a path has no separator in front of it.
    if base.is_empty() { key.to_string() } else { format!("{base}/{key}") }
}
