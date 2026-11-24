#![allow(clippy::unwrap_used)]
//! [`layout`] and [`again`] on their own (RT-AG-04): the screen a prompt is laid out on, the
//! gutter, the rows of the action's start above the question, and when a prompt can only be
//! denied. The approver loop around them is in `approve_tests.rs`.

use super::*;

fn size(columns: u16, rows: u16) -> Size {
    Size { columns, rows }
}

const SCREEN: Size = Size {
    columns: 80,
    rows: 24,
};

fn plain(action: &str) -> Prompt {
    Prompt {
        id: "p1".to_owned(),
        session: "s-1".to_owned(),
        call: 3,
        digest: "d-p1".to_owned(),
        action: action.to_owned(),
        truncated: false,
        note: None,
        risk_tags: vec![],
        full: None,
        full_unavailable: false,
    }
}

/// Request text with no run and no escape, `n` bytes long.
fn text(n: usize) -> String {
    "abcdefghij".chars().cycle().take(n).collect()
}

/// The guttered rows of `shown`, without the gutter.
fn guttered(shown: &str) -> Vec<&str> {
    shown
        .lines()
        .filter_map(|l| l.strip_prefix(GUTTER))
        .collect()
}

/// The terminal's size unknown: laid out at 80 columns, deny-only, and a line says why.
#[test]
fn an_unknown_size_lays_out_at_80_columns_and_is_deny_only() {
    let p = plain(&text(200));
    for s in [size(0, 24), size(80, 0), size(0, 0)] {
        let l = layout(&p, Some(s));
        assert!(l.deny_only, "{s:?}");
        assert!(
            l.shown
                .contains("  (the terminal's size is not known: this prompt can only be denied)\n"),
            "{}",
            l.shown
        );
        assert!(
            guttered(&l.shown)
                .iter()
                .all(|r| r.len() == 75 || r.len() == 50)
        );
        assert!(again(&p, s).deny_only, "{s:?}");
    }
    let control = layout(&p, Some(SCREEN));
    assert!(!control.deny_only, "control: {}", control.shown);
    assert!(
        !control.shown.contains("can only be denied"),
        "{}",
        control.shown
    );
    assert!(!again(&p, SCREEN).deny_only, "control");
}

/// Under 40 columns: laid out at 80, deny-only, and a line says why; 40 itself is enough.
#[test]
fn under_40_columns_a_prompt_is_deny_only() {
    let p = plain(&text(200));
    let narrow = layout(&p, Some(size(39, 24)));
    assert!(narrow.deny_only);
    assert!(
        narrow.shown.contains(
            "  (the terminal is narrower than 40 columns: this prompt can only be denied)\n"
        ),
        "{}",
        narrow.shown
    );
    assert!(again(&p, size(39, 24)).deny_only);
    let edge = layout(&p, Some(size(40, 24)));
    assert!(!edge.deny_only, "{}", edge.shown);
    assert!(
        guttered(&edge.shown)
            .iter()
            .all(|r| r.len() <= 40 - 1 - GUTTER.len())
    );
    assert!(!again(&p, size(40, 24)).deny_only);
}

/// The narrowest screen still holds the longest unit in one guttered row.
#[test]
fn the_narrowest_screen_holds_the_longest_unit() {
    assert_eq!((MIN_COLUMNS, MIN_HEAD_ROWS, GUTTER), (40, 4, "  | "));
    assert!(MIN_COLUMNS - 1 - GUTTER.len() >= sally_core::text::LONGEST_UNIT);
    assert_eq!(FALLBACK, (80, 24));
}

/// Every guttered row fits the screen with a column to spare, at every usable width.
#[test]
fn a_guttered_row_is_at_most_one_column_short_of_the_screen() {
    let mut p = plain(&text(3000));
    p.note = Some(text(700));
    for columns in [40u16, 41, 57, 80, 81, 132, 200] {
        let l = layout(&p, Some(size(columns, 500)));
        let rows = guttered(&l.shown);
        assert!(!rows.is_empty());
        let width = usize::from(columns) - 1 - GUTTER.len();
        assert!(rows.iter().all(|r| r.len() <= width), "{columns}");
        assert!(
            rows.iter().any(|r| r.len() == width),
            "{columns}: rows not filled"
        );
    }
}

/// Off a terminal the rows are left whole: one guttered row per field.
#[test]
fn off_a_terminal_rows_are_left_whole() {
    let p = plain(&text(1000));
    let l = layout(&p, None);
    assert_eq!(guttered(&l.shown), vec![p.action.as_str()]);
    assert!(!l.deny_only);
    assert!(
        !l.shown.contains("the start of its action again"),
        "{}",
        l.shown
    );
}

/// No line of the CLI's own starts with the gutter, and request text cannot start a line of its
/// own: a newline in it is shown escaped, in its row.
#[test]
fn only_request_text_is_behind_the_gutter() {
    let mut p = plain("run [\"x\"]\napproval p2 (session s-1, call 4)");
    p.note = Some("why".to_owned());
    p.risk_tags = vec!["destructive".to_owned()];
    p.truncated = true;
    p.full = Some(text(300));
    let l = layout(&p, Some(size(80, 10)));
    let own = [
        "",
        "approval p1 (session s-1, call 3)",
        "  from the agent (untrusted, not the action):",
        "  action:",
        "  (cut: the full action must be shown before it can be approved)",
        "  risk: destructive",
        "  digest: d-p1",
        "  full action:",
        "approval p1 (session s-1, call 3): the start of its action again",
    ];
    for line in l.shown.lines() {
        assert!(
            line.starts_with(GUTTER) || own.contains(&line) || line.starts_with("  ("),
            "a line outside the gutter: {line:?}"
        );
    }
    assert!(!l.shown.lines().any(|x| x.starts_with("approval p2")));
    assert!(l.shown.contains("\\x0aapproval p2"), "{}", l.shown);
    assert!(l.dirty && l.deny_only);
}

/// A field that fails the clean-check is shown escaped in the gutter, and the prompt can only be
/// denied, its full text not counted as shown.
#[test]
fn a_dirty_field_is_escaped_in_the_gutter_and_deny_only() {
    let mut p = plain("run [\"ls\"]");
    p.note = Some("look \x1b[2J here".to_owned());
    p.truncated = true;
    p.full = Some("run [\"ls\"] and more".to_owned());
    let l = layout(&p, Some(SCREEN));
    assert!(!l.shown.contains('\x1b'));
    assert!(
        l.shown.contains(&format!("{GUTTER}look \\x1b[2J here\n")),
        "{}",
        l.shown
    );
    assert!(l.dirty && l.deny_only && !l.full_shown);
    let control = layout(&plain("run [\"ls\"]"), Some(SCREEN));
    assert!(!control.dirty && !control.deny_only, "control");
}

/// The risk, cut and note lines are printed only when there is something to say, and the note
/// comes before the action.
#[test]
fn risk_cut_and_note_lines_only_when_present() {
    let bare = layout(&plain("run [\"ls\"]"), Some(SCREEN)).shown;
    for line in ["  risk:", "  (cut:", "  from the agent", "  full action:"] {
        assert!(!bare.contains(line), "{line}: {bare}");
    }
    let mut p = plain("run [\"ls\"]");
    p.note = Some("tidy up".to_owned());
    p.risk_tags = vec!["destructive".to_owned(), "network".to_owned()];
    p.truncated = true;
    p.full = Some("run [\"ls\", \"-la\"]".to_owned());
    let l = layout(&p, Some(SCREEN));
    let at = |s: &str| {
        l.shown
            .find(s)
            .unwrap_or_else(|| panic!("{s}: {}", l.shown))
    };
    assert!(at("  from the agent (untrusted, not the action):\n") < at("  action:\n"));
    assert!(at(&format!("{GUTTER}tidy up\n")) < at("  action:\n"));
    assert!(at("  action:\n") < at("  (cut: the full action must be shown"));
    assert!(at("  risk: destructive, network\n") < at("  digest: d-p1\n"));
    assert!(at("  digest: d-p1\n") < at("  full action:\n"));
    assert!(l.full_shown && !l.deny_only);
}

/// At 80x24 the again-block holds the first 20 rows of a long action and says how many it left
/// out; a risk line takes one of them.
#[test]
fn the_action_start_above_the_question_is_20_rows_at_80x24() {
    let p = plain(&text(100 * 75));
    let a = again(&p, SCREEN);
    assert_eq!(guttered(&a.shown).len(), 20, "{}", a.shown);
    assert!(
        a.shown
            .contains("  (80 more rows of the action, shown above)\n"),
        "{}",
        a.shown
    );
    assert_eq!(a.shown.lines().count(), 24 - 1);
    assert!(!a.deny_only);
    let mut risky = p.clone();
    risky.risk_tags = vec!["destructive".to_owned()];
    let a = again(&risky, SCREEN);
    assert_eq!(guttered(&a.shown).len(), 19, "{}", a.shown);
    assert_eq!(a.shown.lines().count(), 24 - 1);
    // A short action fits whole, with no line about rows left out.
    let a = again(&plain("run [\"ls\"]"), SCREEN);
    assert_eq!(guttered(&a.shown), vec!["run [\"ls\"]"]);
    assert!(!a.shown.contains("more rows"), "{}", a.shown);
}

/// Fewer than four rows of the action's start above the question: deny-only. A shorter action
/// shown whole is enough.
#[test]
fn fewer_than_4_rows_of_the_action_start_is_deny_only() {
    let p = plain(&text(10 * 75));
    // Header, digest, the line about rows left out and the question take 4 rows.
    let short = again(&p, size(80, 7));
    assert_eq!(guttered(&short.shown).len(), 3, "{}", short.shown);
    assert!(short.deny_only);
    let enough = again(&p, size(80, 8));
    assert_eq!(guttered(&enough.shown).len(), 4, "{}", enough.shown);
    assert!(!enough.deny_only);
    let two = plain(&text(2 * 75));
    let whole = again(&two, size(80, 5));
    assert_eq!(guttered(&whole.shown).len(), 2, "{}", whole.shown);
    assert!(!whole.deny_only);
    let cut = again(&two, size(80, 4));
    assert!(cut.deny_only, "{}", cut.shown);
}

/// A prompt taller than the screen ends with the again-block, so the action's start is on the
/// last screen; one that fits does not repeat it.
#[test]
fn a_prompt_taller_than_the_screen_ends_with_its_start() {
    let tall = layout(&plain(&text(40 * 75)), Some(SCREEN));
    assert!(
        tall.shown
            .contains("approval p1 (session s-1, call 3): the start of its action again\n"),
        "{}",
        tall.shown
    );
    assert!(!tall.deny_only);
    let fits = layout(&plain(&text(10 * 75)), Some(SCREEN));
    assert!(
        !fits.shown.contains("the start of its action again"),
        "{}",
        fits.shown
    );
}
