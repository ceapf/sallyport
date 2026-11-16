#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::audit::{NewEntry, secret_forms};
use crate::text::Quote;

const MAX: usize = 64;

/// Every style the writer knows. [`slot`] matches every variant, so a new one fails to compile
/// until it has a slot, and [`every_style_is_in_the_list`] fails until it is listed here.
const STYLES: [Style; 6] = [
    Style::Hex { max: MAX },
    Style::HexCounted { max: MAX },
    Style::Text {
        max: MAX,
        quote: Quote::None,
    },
    Style::Text {
        max: MAX,
        quote: Quote::Hex,
    },
    Style::Text {
        max: MAX,
        quote: Quote::Backslash,
    },
    Style::Plain { max: MAX },
];

const fn slot(s: Style) -> usize {
    match s {
        Style::Hex { .. } => 0,
        Style::HexCounted { .. } => 1,
        Style::Text {
            quote: Quote::None, ..
        } => 2,
        Style::Text {
            quote: Quote::Hex, ..
        } => 3,
        Style::Text {
            quote: Quote::Backslash,
            ..
        } => 4,
        Style::Plain { .. } => 5,
    }
}

#[test]
fn every_style_is_in_the_list() {
    let mut slots: Vec<usize> = STYLES.iter().map(|&s| slot(s)).collect();
    slots.sort_unstable();
    assert_eq!(slots, (0..STYLES.len()).collect::<Vec<_>>());
}

/// Every shape of a declared text. A new shape fails to compile here until it has a slot, and
/// [`every_shape_is_in_the_property_test`] fails until the property test covers it.
const fn shape_slot(s: &Shape) -> usize {
    match s {
        Shape::Styled { .. } => 0,
        Shape::Pieces { .. } => 1,
        Shape::List { .. } => 2,
    }
}

/// The shapes [`every_style_masks_every_form_at_every_offset_before_it_cuts_or_escapes`] and
/// [`a_composite_text_masks_each_raw_piece_then_escapes_assembles_and_cuts`] cover.
fn tested_shapes() -> Vec<Shape> {
    let style = Style::Hex { max: MAX };
    vec![
        Shape::Styled {
            raw: Arc::from(""),
            style,
            cut_key: None,
        },
        Shape::Pieces {
            pieces: Vec::new(),
            max: MAX,
        },
        Shape::List {
            raws: Vec::new(),
            style,
        },
    ]
}

#[test]
fn every_shape_is_in_the_property_test() {
    let mut slots: Vec<usize> = tested_shapes().iter().map(shape_slot).collect();
    slots.sort_unstable();
    assert_eq!(slots, vec![0, 1, 2]);
}

/// The elements of a declared list of `raws`, resolved by `r`.
fn listed(raws: &[&str], style: Style, r: &Redactor) -> Vec<String> {
    let d = Declared {
        key: "l",
        shape: Shape::List {
            raws: raws.iter().map(|&s| Arc::from(s)).collect(),
            style,
        },
    };
    let v = resolve(&Value::Null, &[d], r);
    v["l"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_owned())
        .collect()
}

/// A value with a quote, a backslash and a non-printable byte: the escape rewrites each.
const VALUE: &str = "q\"u\\o\x01te-secret-value-0123456789";

fn styled_text(raw: &str, style: Style, r: &Redactor) -> (String, bool) {
    let d = Declared {
        key: "t",
        shape: Shape::Styled {
            raw: Arc::from(raw),
            style,
            cut_key: Some("t_cut"),
        },
    };
    let v = resolve(&Value::Null, &[d], r);
    (
        v["t"].as_str().unwrap().to_owned(),
        v["t_cut"].as_bool().unwrap(),
    )
}

/// No 8-byte run of `form`, nor of its spelling in `style`, is in `out`.
fn holds_none_of(out: &str, form: &str, style: Style) -> Result<(), String> {
    let spelt = text::styled(form, unbounded(style)).0;
    for whole in [form, spelt.as_str()] {
        for w in whole.as_bytes().windows(8) {
            let w = String::from_utf8_lossy(w);
            if out.contains(w.as_ref()) {
                return Err(format!("{w:?} of {form:?} in {out:?}"));
            }
        }
    }
    Ok(())
}

const fn unbounded(s: Style) -> Style {
    match s {
        Style::Hex { .. } => Style::Hex { max: usize::MAX },
        Style::HexCounted { .. } => Style::HexCounted { max: usize::MAX },
        Style::Text { quote, .. } => Style::Text {
            max: usize::MAX,
            quote,
        },
        Style::Plain { .. } => Style::Plain { max: usize::MAX },
    }
}

/// Architect Q288 condition 5: every form of a value with a quote, a backslash and a
/// non-printable byte, at every offset up to past the cap, in every style: no run of the form
/// or of its escaped spelling survives; the placeholder is there when the text was not cut; the
/// hex and text styles are printable ASCII. Control (hand-checked): styling before masking.
#[test]
fn every_style_masks_every_form_at_every_offset_before_it_cuts_or_escapes() {
    let r = Redactor::new([("Y", VALUE)]);
    for form in secret_forms(VALUE) {
        let form = form.expose();
        for offset in 0..MAX + 8 {
            let raw = format!("{}{form}{}", "a".repeat(offset), "z".repeat(20));
            for style in STYLES {
                let (out, cut) = styled_text(&raw, style, &r);
                holds_none_of(&out, form, style).unwrap();
                if !cut {
                    assert!(out.contains("[REDACTED:Y]"), "{style:?} {out:?}");
                }
                // The counted tail `…(+N)` is the one non-ASCII part of the hex styles.
                let body = out.split('\u{2026}').next().unwrap_or_default();
                if !matches!(style, Style::Plain { .. }) {
                    assert!(body.bytes().all(|b| (b' '..=b'~').contains(&b)), "{out:?}");
                }
                // Architect Q291: the same text as the first, middle and last element of a
                // list, beside form-free neighbours that are written as on their own.
                let n = "neighbour";
                for at in 0..3 {
                    let mut raws = [n, n, n];
                    raws[at] = raw.as_str();
                    let got = listed(&raws, style, &r);
                    assert_eq!(got.len(), 3);
                    assert_eq!(got[at], out, "{style:?} at {at}");
                    for (i, e) in got.iter().enumerate().filter(|&(i, _)| i != at) {
                        assert_eq!(e, &text::styled(n, style).0, "{style:?} {i}");
                    }
                }
            }
        }
    }
}

#[test]
fn an_empty_list_is_an_empty_array() {
    let d = Declared {
        key: "l",
        shape: Shape::List {
            raws: Vec::new(),
            style: Style::Hex { max: 9 },
        },
    };
    let v = resolve(&serde_json::json!({"a": 1}), &[d], &Redactor::default());
    assert_eq!(v, serde_json::json!({"a": 1, "l": []}));
}

/// Architect Q276: a 24-byte canary at byte 220 or straddling byte 256 of a 300+ byte text;
/// whether it was cut is judged on the masked text.
#[test]
fn a_hex_text_is_masked_before_its_cut_and_its_cut_is_judged_masked() {
    let canary = "canary0123456789abcdefgh";
    let r = Redactor::new([("C", canary)]);
    let at = |offset: usize, len: usize| {
        let tail = len - offset - canary.len();
        format!("{}{canary}{}", "a".repeat(offset), "b".repeat(tail))
    };
    let hex = Style::Hex { max: 256 };
    // 265 raw bytes, 253 once masked: not cut.
    let (out, cut) = styled_text(&at(220, 265), hex, &r);
    assert!(
        !cut && out.contains("[REDACTED:C]") && !out.contains("canary01"),
        "{out}"
    );
    let (out, cut) = styled_text(&at(220, 310), hex, &r);
    assert!(cut && out.contains("[REDACTED:C]"), "{out}");
    let (out, cut) = styled_text(&at(250, 310), hex, &r);
    assert!(
        cut && !out.contains("canary") && out.ends_with("a[REDAC"),
        "{out}"
    );
}

fn action(r: &Redactor, raw: &str, max: usize) -> String {
    let d = Declared {
        key: "action",
        shape: Shape::Pieces {
            pieces: vec![
                Piece::Literal("fetch ".into()),
                Piece::Literal("\"".into()),
                Piece::Raw(Arc::from(raw)),
                Piece::Literal("\" body 3 bytes".into()),
            ],
            max,
        },
    };
    resolve(&Value::Null, &[d], r)["action"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Architect Q288 (action text a, d): each raw piece is masked whole, then escaped with `\"`,
/// then the text is assembled and cut once; the tail's hash is of the masked text.
#[test]
fn a_composite_text_masks_each_raw_piece_then_escapes_assembles_and_cuts() {
    let r = Redactor::new([("Y", VALUE)]);
    let url = format!("https://x.test/{VALUE}/{}", "p".repeat(40));
    let masked = format!("https://x.test/[REDACTED:Y]/{}", "p".repeat(40));
    let whole = format!("fetch \"{masked}\" body 3 bytes");
    assert_eq!(action(&r, &url, 1000), whole);
    let (cut, was_cut) = text::cut_escaped(&whole, 40);
    assert!(was_cut);
    assert_eq!(action(&r, &url, 40), cut);
    for form in secret_forms(VALUE) {
        for max in [20, 30, 40, 1000] {
            let raw = format!("https://x.test/{}", form.expose());
            let out = action(&r, &raw, max);
            let style = Style::Text {
                max: usize::MAX,
                quote: Quote::Backslash,
            };
            holds_none_of(&out, form.expose(), style).unwrap();
        }
    }
}

/// Architect Q288 (a): [`assembled`] is the human's text: literals as they are, raw pieces
/// escaped with `\"`, nothing masked and nothing cut; with no form and no cut it is the
/// writer's text too.
#[test]
fn assembled_is_the_unmasked_uncut_text_the_writer_assembles() {
    let raw = format!("a\"b\\c\u{202e}{VALUE}{}", "q".repeat(300));
    let pieces = vec![
        Piece::Literal("run ".into()),
        Piece::Raw(Arc::from(raw.as_str())),
        Piece::Literal(" end".into()),
        Piece::Raw(Arc::from("")),
    ];
    let whole = assembled(&pieces);
    assert_eq!(
        whole,
        format!("run {} end", text::escape_backslash_quoted(raw.as_bytes()))
    );
    assert!(
        whole.contains(&text::escape_backslash_quoted(VALUE.as_bytes())),
        "assembled masks nothing"
    );
    assert!(whole.len() > 300, "assembled cuts nothing");
    let d = Declared {
        key: "a",
        shape: Shape::Pieces {
            pieces,
            max: usize::MAX,
        },
    };
    assert_eq!(
        resolve(&Value::Null, &[d], &Redactor::default())["a"],
        Value::from(whole)
    );
    assert_eq!(assembled(&[]), "");
}

/// With no form in it, a composite text is exactly the cut of its escaped assembly.
#[test]
fn a_composite_text_without_a_form_is_the_cut_of_its_escaped_assembly() {
    let raw = "a\"b\\c\u{202e}";
    let whole = format!(
        "fetch \"{}\" body 3 bytes",
        text::escape_backslash_quoted(raw.as_bytes())
    );
    assert_eq!(whole, "fetch \"a\\\"b\\\\c\\u{202e}\" body 3 bytes");
    for max in [5, 12, 18, 1000] {
        assert_eq!(
            action(&Redactor::default(), raw, max),
            text::cut_escaped(&whole, max).0
        );
    }
}

#[test]
fn texts_fill_args_and_the_whole_is_redacted() {
    let r = Redactor::new([("Y", VALUE)]);
    let d = Declared {
        key: "target",
        shape: Shape::Styled {
            raw: Arc::from("/x"),
            style: Style::Hex { max: 256 },
            cut_key: Some("target_cut"),
        },
    };
    let args = serde_json::json!({"target_bytes": 2, "note": VALUE});
    let v = resolve(&args, &[d], &r);
    assert_eq!(
        v,
        serde_json::json!({
            "target_bytes": 2, "note": "[REDACTED:Y]", "target": "/x", "target_cut": false
        })
    );
    assert_eq!(resolve(&args, &[], &r), r.redact_value(&args));
    let plain = Declared {
        key: "t",
        shape: Shape::Styled {
            raw: Arc::from("v"),
            style: Style::Plain { max: 9 },
            cut_key: None,
        },
    };
    assert_eq!(
        resolve(&Value::from(3), std::slice::from_ref(&plain), &r),
        serde_json::json!({"t": "v"}),
        "args that are not an object give way to the texts"
    );
    let over = serde_json::json!({"t": "arg"});
    assert_eq!(resolve(&over, &[plain], &r), serde_json::json!({"t": "v"}));
}

#[test]
fn a_key_used_twice_or_args_that_are_not_an_object_collide() {
    let styled = |key, cut_key| Declared {
        key,
        shape: Shape::Styled {
            raw: Arc::from("v"),
            style: Style::Hex { max: 9 },
            cut_key,
        },
    };
    let pieces = |key| Declared {
        key,
        shape: Shape::Pieces {
            pieces: Vec::new(),
            max: 9,
        },
    };
    let list = |key| Declared {
        key,
        shape: Shape::List {
            raws: Vec::new(),
            style: Style::Hex { max: 9 },
        },
    };
    let obj = serde_json::json!({"a": 1});
    assert!(!collides(&obj, &[list("l")]));
    assert!(collides(&obj, &[list("a")]));
    assert!(collides(&obj, &[list("l"), pieces("l")]));
    assert!(collides(&Value::from(1), &[list("l")]));
    assert!(!collides(&obj, &[]));
    assert!(!collides(&Value::from(1), &[]));
    assert!(!collides(&Value::Null, &[styled("t", Some("t_cut"))]));
    assert!(!collides(&obj, &[styled("t", Some("t_cut")), pieces("p")]));
    assert!(collides(&obj, &[styled("a", None)]));
    assert!(collides(&obj, &[styled("t", Some("a"))]));
    assert!(collides(&obj, &[pieces("a")]));
    assert!(collides(&obj, &[styled("t", None), pieces("t")]));
    assert!(collides(&obj, &[styled("t", Some("u")), styled("u", None)]));
    assert!(collides(&Value::from(1), &[styled("t", None)]));
    assert!(collides(&serde_json::json!([1]), &[pieces("p")]));
}

/// Architect Q276, Q290 condition 6: a session's own pass masks declared texts uncut and
/// unescaped, so the writer still cuts and escapes after its own mask.
#[test]
fn redacted_masks_declared_texts_uncut_and_unescaped() {
    let r = Redactor::new([("Y", VALUE)]);
    let raw = format!("{}\"{VALUE}", "a".repeat(300));
    let e = NewEntry::new(crate::audit::Actor::Sallyd, "egress.request")
        .text("target", raw.as_str(), Style::Hex { max: 256 })
        .pieces(
            "action",
            vec![Piece::Literal("x ".into()), Piece::Raw(Arc::from(VALUE))],
            100,
        )
        .texts(
            "keys",
            vec![Arc::from("k"), Arc::from(raw.as_str())],
            Style::HexCounted { max: 64 },
        )
        .redacted(&r);
    let v = e.resolved(&Redactor::default());
    assert_eq!(
        v["target"],
        text::styled(
            &format!("{}\"[REDACTED:Y]", "a".repeat(300)),
            Style::Hex { max: 256 }
        )
        .0
    );
    assert_eq!(v["action"], "x [REDACTED:Y]");
    let masked = format!("{}\"[REDACTED:Y]", "a".repeat(300));
    let key = text::styled(&masked, Style::HexCounted { max: 64 }).0;
    assert_eq!(v["keys"], serde_json::json!(["k", key]));
    // Control: without the session's pass, an empty writer redactor logs the value's spelling.
    let bare = NewEntry::new(crate::audit::Actor::Sallyd, "egress.request")
        .pieces("action", vec![Piece::Raw(Arc::from(VALUE))], 100)
        .resolved(&Redactor::default());
    assert!(bare["action"].as_str().unwrap().contains("secret-value"));
}

/// Architect Q290 condition 5: `Debug` holds no declared text.
#[test]
fn debug_omits_declared_texts() {
    let e = NewEntry::new(crate::audit::Actor::Sallyd, "egress.request")
        .text("t", VALUE, Style::Plain { max: 99 })
        .pieces("p", vec![Piece::Raw(Arc::from(VALUE))], 99)
        .texts("l", vec![Arc::from(VALUE)], Style::Plain { max: 99 });
    let d = format!("{e:?}");
    assert!(!d.contains("secret-value"), "{d}");
}
