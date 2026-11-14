//! What `sally` prints when its command line does not parse (architect Q113; maintainer ruling
//! 2026-11-14): fixed text chosen by the kind of error alone. The parser's own message quotes
//! the argument it rejected, and an argument may be a secret value typed where it does not
//! belong, so no argument byte is ever printed.

use clap::error::ErrorKind;

use crate::secrets::ARGV_WARNING;

/// The message for a parse error of `kind`; `secrets` (the line names the secrets command, see
/// [`crate::secrets::names_secrets`]) adds [`ARGV_WARNING`]. Help and version are not errors and
/// never come here.
#[must_use]
pub fn parse_error(kind: ErrorKind, secrets: bool) -> String {
    let what = match kind {
        ErrorKind::UnknownArgument => "an argument was not expected",
        ErrorKind::InvalidSubcommand => "there is no such command",
        ErrorKind::MissingRequiredArgument => "an argument is missing",
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "a command is missing"
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => "a value is not valid",
        _ => "the command line was not understood",
    };
    let text = format!("sally: {what}; nothing was done (run `sally --help`)");
    if secrets {
        format!("{text}\n{ARGV_WARNING}")
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_its_fixed_phrase() {
        let cases = [
            (ErrorKind::UnknownArgument, "an argument was not expected"),
            (ErrorKind::InvalidSubcommand, "there is no such command"),
            (ErrorKind::MissingRequiredArgument, "an argument is missing"),
            (ErrorKind::MissingSubcommand, "a command is missing"),
            (
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "a command is missing",
            ),
            (ErrorKind::InvalidValue, "a value is not valid"),
            (ErrorKind::ValueValidation, "a value is not valid"),
            (
                ErrorKind::TooManyValues,
                "the command line was not understood",
            ),
        ];
        for (kind, phrase) in cases {
            assert_eq!(
                parse_error(kind, false),
                format!("sally: {phrase}; nothing was done (run `sally --help`)"),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_secrets_line_adds_the_history_warning() {
        let plain = parse_error(ErrorKind::UnknownArgument, false);
        assert!(!plain.contains(ARGV_WARNING));
        assert_eq!(
            parse_error(ErrorKind::UnknownArgument, true),
            format!("{plain}\n{ARGV_WARNING}")
        );
    }
}
