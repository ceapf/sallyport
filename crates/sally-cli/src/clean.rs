//! The clean-check (architect Q80): `sallyd` escapes everything a sandbox chose before it sends
//! it, so a well-behaved reply is printable ASCII (plus newlines in multi-line text). Anything
//! else is escaped here with the shared escaper and marked dirty: a dirty prompt can only be
//! denied, and a command that printed dirty text exits non-zero.

/// Text after the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// What to print: the text itself, or its escaped form.
    pub text: String,
    /// Whether the text passed unchanged.
    pub clean: bool,
}

/// One line: printable ASCII only.
#[must_use]
pub fn line(s: &str) -> Checked {
    check(s, false)
}

/// Multi-line text: printable ASCII and `\n`.
#[must_use]
pub fn text(s: &str) -> Checked {
    check(s, true)
}

fn check(s: &str, newlines: bool) -> Checked {
    let ok = s
        .bytes()
        .all(|b| (b' '..=b'~').contains(&b) || (newlines && b == b'\n'));
    if ok {
        Checked {
            text: s.to_owned(),
            clean: true,
        }
    } else {
        Checked {
            text: sally_core::text::escape(s.as_bytes()),
            clean: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_ascii_passes_unchanged() {
        let all: String = (b' '..=b'~').map(char::from).collect();
        assert_eq!(
            line(&all),
            Checked {
                text: all.clone(),
                clean: true
            }
        );
        assert_eq!(text("a\nb\n").text, "a\nb\n");
        assert!(text("a\nb\n").clean);
    }

    #[test]
    fn anything_else_is_escaped_and_dirty() {
        for bad in ["a\x1b[2J", "\x7f", "\u{e9}", "a\rb", "\t", "\x00"] {
            let c = line(bad);
            assert!(!c.clean, "{bad:?}");
            assert_eq!(c.text, sally_core::text::escape(bad.as_bytes()));
            assert!(c.text.bytes().all(|b| (b' '..=b'~').contains(&b)), "{c:?}");
        }
        let nl = line("a\nb");
        assert!(!nl.clean, "a line has no newline");
        assert!(!nl.text.contains('\n'));
        assert!(!text("a\n\x1b").clean);
    }
}
