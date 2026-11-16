//! Texts an audit entry declares beside its args (architect Q276, Q288, Q290): text a sandbox
//! chose, which must be cut and escaped before it is logged. The writer resolves them under its
//! lock: each raw text is masked whole with the current redactor, then cut and escaped in its
//! [`Style`], then inserted into the args, and then the whole args are redacted as before. So no
//! cut can split a form of a live session's secret and no escape can rewrite one, whichever
//! session's entry holds it.
//!
//! A composite text (the approval action text) is a list of [`Piece`]s: daemon-chosen literals
//! pass through; each raw piece is masked whole and escaped with `"` as `\"`; the assembled text
//! is cut once, never inside an escape, and its tail hash is of the masked text.

use std::sync::Arc;

use serde_json::{Map, Value};

use super::redact::Redactor;
use crate::text::{self, Style};

/// One piece of a composite text.
#[derive(Clone)]
pub enum Piece {
    /// Text the daemon chose (fixed words, numbers it counted, digests), passed through as is.
    /// It must already be printable ASCII.
    Literal(String),
    /// Text the sandbox chose: masked whole, then escaped with `"` written as `\"`.
    Raw(Arc<str>),
}

/// The shape of one declared text.
#[derive(Clone)]
pub(super) enum Shape {
    /// One raw text in a style; `cut_key`, when set, names a boolean arg that says whether the
    /// masked text was cut.
    Styled {
        raw: Arc<str>,
        style: Style,
        cut_key: Option<&'static str>,
    },
    /// A composite text, cut by [`text::cut_escaped`] at `max` bytes once assembled.
    Pieces { pieces: Vec<Piece>, max: usize },
    /// A list of raw texts, written as a JSON array in order, each masked whole and then styled
    /// on its own (architect Q291). Elements are never joined, so no cut spans two of them; a
    /// value split across two elements is a form in neither, as across two args.
    List { raws: Vec<Arc<str>>, style: Style },
}

/// One declared text: the arg it fills and how.
#[derive(Clone)]
pub(super) struct Declared {
    pub(super) key: &'static str,
    pub(super) shape: Shape,
}

impl Declared {
    /// The args this text fills.
    fn keys(&self) -> impl Iterator<Item = &'static str> {
        let cut = match &self.shape {
            Shape::Styled { cut_key, .. } => *cut_key,
            Shape::Pieces { .. } | Shape::List { .. } => None,
        };
        std::iter::once(self.key).chain(cut)
    }

    /// The text with every raw part masked by `redactor`, uncut and unescaped (architect Q276:
    /// a session's own pass before the writer's).
    pub(super) fn masked(&self, redactor: &Redactor) -> Self {
        let mask = |raw: &Arc<str>| Arc::from(redactor.redact_str(raw).as_ref());
        let shape = match &self.shape {
            Shape::Styled {
                raw,
                style,
                cut_key,
            } => Shape::Styled {
                raw: mask(raw),
                style: *style,
                cut_key: *cut_key,
            },
            Shape::Pieces { pieces, max } => Shape::Pieces {
                pieces: pieces
                    .iter()
                    .map(|p| match p {
                        Piece::Literal(l) => Piece::Literal(l.clone()),
                        Piece::Raw(r) => Piece::Raw(mask(r)),
                    })
                    .collect(),
                max: *max,
            },
            Shape::List { raws, style } => Shape::List {
                raws: raws.iter().map(mask).collect(),
                style: *style,
            },
        };
        Self {
            key: self.key,
            shape,
        }
    }

    /// Writes this text into `args`: masked whole, then cut and escaped.
    fn fill(&self, redactor: &Redactor, args: &mut Map<String, Value>) {
        match &self.shape {
            Shape::Styled {
                raw,
                style,
                cut_key,
            } => {
                let (shown, cut) = text::styled(&redactor.redact_str(raw), *style);
                args.insert(self.key.to_owned(), Value::from(shown));
                if let Some(k) = cut_key {
                    args.insert((*k).to_owned(), Value::from(cut));
                }
            }
            Shape::Pieces { pieces, max } => {
                let mut whole = String::new();
                for p in pieces {
                    match p {
                        Piece::Literal(l) => whole.push_str(l),
                        Piece::Raw(r) => whole.push_str(&text::escape_backslash_quoted(
                            redactor.redact_str(r).as_bytes(),
                        )),
                    }
                }
                let (shown, _) = text::cut_escaped(&whole, *max);
                args.insert(self.key.to_owned(), Value::from(shown));
            }
            Shape::List { raws, style } => {
                let shown: Vec<Value> = raws
                    .iter()
                    .map(|r| Value::from(text::styled(&redactor.redact_str(r), *style).0))
                    .collect();
                args.insert(self.key.to_owned(), Value::Array(shown));
            }
        }
    }
}

/// The final args of an entry: `args` with every declared text filled in, then redacted whole.
/// A declared key replaces an arg of the same name (the writer refuses such an entry first, see
/// [`collides`]); args that are not an object are replaced by an object of the texts.
pub(super) fn resolve(args: &Value, texts: &[Declared], redactor: &Redactor) -> Value {
    if texts.is_empty() {
        return redactor.redact_value(args);
    }
    let mut map = match args {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    for d in texts {
        d.fill(redactor, &mut map);
    }
    redactor.redact_value(&Value::Object(map))
}

/// Whether declared texts clash with `args` or with each other: a key used twice, or args that
/// are neither null nor an object while texts are declared.
pub(super) fn collides(args: &Value, texts: &[Declared]) -> bool {
    if texts.is_empty() {
        return false;
    }
    let mut seen: Vec<&str> = Vec::new();
    for k in texts.iter().flat_map(Declared::keys) {
        if seen.contains(&k) {
            return true;
        }
        seen.push(k);
    }
    match args {
        Value::Null => false,
        Value::Object(m) => seen.iter().any(|k| m.contains_key(*k)),
        _ => true,
    }
}

#[cfg(test)]
#[path = "declared_tests.rs"]
mod tests;
