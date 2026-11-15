//! The scripted model: a script is data, never code (architect rulings on R3, Q46, Q103).
//!
//! A script is JSON Lines text; each line is exactly one of:
//! - `{"content": "<text>"}`: an assistant message;
//! - `{"tool_calls": [{"name": "<tool>", "arguments": {…}}, …]}`: an assistant message that
//!   calls tools;
//! - `{"fail": true}`: the backend fails.
//!
//! The whole script is parsed before anything launches. Duplicate keys, any other shape, an
//! extra key in a call and every cap below are refused with an error naming the line.

use std::fmt;

use serde::Deserialize;
use serde::de::{Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Bytes of a script at most (Q103).
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;
/// Bytes of one script line at most.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Turns of a script at most.
pub const MAX_TURNS: usize = 1024;
/// Calls of one turn at most.
pub const MAX_CALLS: usize = 8;

/// One scripted turn.
#[derive(Debug, Clone, PartialEq)]
pub enum Turn {
    /// An assistant message.
    Content(String),
    /// An assistant message that calls tools, in order.
    ToolCalls(Vec<Call>),
    /// The backend fails.
    Fail,
}

/// One scripted tool call.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    /// The tool name.
    pub name: String,
    /// The call's arguments.
    pub arguments: Map<String, Value>,
}

/// A parsed script: its turns and the SHA-256 (hex) of its text.
#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    /// The turns, in order.
    pub turns: Vec<Turn>,
    /// SHA-256 of the script text, hex.
    pub sha256: String,
}

/// Why a script is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScriptError {
    /// The text is longer than [`MAX_SCRIPT_BYTES`].
    #[error("script: {0} bytes exceed the {MAX_SCRIPT_BYTES}-byte limit")]
    TooLarge(usize),
    /// The script has more than [`MAX_TURNS`] turns.
    #[error("script: more than {MAX_TURNS} turns")]
    TooManyTurns,
    /// A line is wrong; the message names what.
    #[error("script line {line}: {what}")]
    Line {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        what: String,
    },
}

/// A JSON value parsed with duplicate keys refused at every depth (serde_json keeps the last).
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, b: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(b)))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(n)))
            }
            fn visit_u64<E>(self, n: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(n)))
            }
            fn visit_f64<E>(self, n: f64) -> Result<Strict, E> {
                Ok(Strict(Value::from(n)))
            }
            fn visit_str<E>(self, s: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(s.to_owned())))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = s.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some((k, Strict(v))) = m.next_entry::<String, Strict>()? {
                    if out.insert(k, v).is_some() {
                        return Err(A::Error::custom("duplicate key"));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

fn strict(text: &str) -> Result<Value, String> {
    serde_json::from_str::<Strict>(text)
        .map(|Strict(v)| v)
        .map_err(|e| e.to_string())
}

fn call(v: Value) -> Result<Call, String> {
    let bad = || "a call has exactly a string name and object arguments".to_string();
    let Value::Object(mut o) = v else {
        return Err(bad());
    };
    match (o.remove("name"), o.remove("arguments"), o.is_empty()) {
        (Some(Value::String(name)), Some(Value::Object(arguments)), true) => {
            Ok(Call { name, arguments })
        }
        _ => Err(bad()),
    }
}

impl Turn {
    /// One script line; the error names what is wrong.
    pub fn parse(line: &str) -> Result<Self, String> {
        if line.len() > MAX_LINE_BYTES {
            return Err(format!("longer than {MAX_LINE_BYTES} bytes"));
        }
        let one_key = || "a line is an object with exactly one key".to_string();
        let Value::Object(o) = strict(line)? else {
            return Err(one_key());
        };
        if o.len() != 1 {
            return Err(one_key());
        }
        let Some((key, value)) = o.into_iter().next() else {
            return Err(one_key());
        };
        match (key.as_str(), value) {
            ("content", Value::String(s)) => Ok(Self::Content(s)),
            ("fail", Value::Bool(true)) => Ok(Self::Fail),
            ("tool_calls", Value::Array(calls)) => {
                if calls.len() > MAX_CALLS {
                    return Err(format!("more than {MAX_CALLS} calls in one turn"));
                }
                calls
                    .into_iter()
                    .map(call)
                    .collect::<Result<_, _>>()
                    .map(Self::ToolCalls)
            }
            _ => Err("unknown line shape".into()),
        }
    }
}

impl Script {
    /// Parses a whole script; blank lines are skipped.
    pub fn parse(text: &str) -> Result<Self, ScriptError> {
        if text.len() > MAX_SCRIPT_BYTES {
            return Err(ScriptError::TooLarge(text.len()));
        }
        let mut turns = Vec::new();
        for (i, l) in text.lines().enumerate() {
            if l.trim().is_empty() {
                continue;
            }
            if turns.len() == MAX_TURNS {
                return Err(ScriptError::TooManyTurns);
            }
            let turn = Turn::parse(l).map_err(|what| ScriptError::Line { line: i + 1, what })?;
            turns.push(turn);
        }
        let sha256 = Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Self { turns, sha256 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(text: &str) -> String {
        Script::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn parses_the_three_shapes() {
        let s = Script::parse(
            "{\"content\":\"hi\"}\n\n{\"tool_calls\":[{\"name\":\"fs.read\",\"arguments\":{\"path\":\"/w\"}}]}\n{\"fail\":true}\n",
        )
        .unwrap();
        assert_eq!(s.turns.len(), 3);
        assert_eq!(s.turns[0], Turn::Content("hi".into()));
        assert!(
            matches!(&s.turns[1], Turn::ToolCalls(c) if c.len() == 1 && c[0].name == "fs.read")
        );
        assert_eq!(s.turns[2], Turn::Fail);
    }

    #[test]
    fn hashes_the_text() {
        let s = Script::parse("{\"fail\":true}").unwrap();
        assert_eq!(s.sha256.len(), 64);
        assert_ne!(s.sha256, Script::parse("{\"fail\":true}\n").unwrap().sha256);
    }

    #[test]
    fn refuses_other_shapes_naming_the_line() {
        assert!(err("{\"content\":\"a\"}\n{\"x\":1}").starts_with("script line 2:"));
        assert!(err("{\"content\":1}").contains("unknown"));
        assert!(err("{\"fail\":false}").contains("unknown"));
        assert!(err("{\"content\":\"a\",\"fail\":true}").contains("exactly one key"));
        assert!(err("[]").contains("script line 1"));
        assert!(err("{}").contains("exactly one key"));
        assert!(err("not json").contains("script line 1"));
    }

    #[test]
    fn refuses_duplicate_keys() {
        assert!(err("{\"content\":\"a\",\"content\":\"b\"}").contains("duplicate"));
        let dup = "{\"tool_calls\":[{\"name\":\"a\",\"name\":\"b\",\"arguments\":{}}]}";
        assert!(err(dup).contains("duplicate"));
    }

    #[test]
    fn a_call_has_exactly_name_and_arguments() {
        for bad in [
            "{\"tool_calls\":[{\"name\":\"a\"}]}",
            "{\"tool_calls\":[{\"arguments\":{}}]}",
            "{\"tool_calls\":[{\"name\":\"a\",\"arguments\":{},\"id\":\"x\"}]}",
            "{\"tool_calls\":[{\"name\":1,\"arguments\":{}}]}",
            "{\"tool_calls\":[{\"name\":\"a\",\"arguments\":[]}]}",
            "{\"tool_calls\":[1]}",
        ] {
            assert!(Script::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn caps_hold_at_their_boundaries() {
        let call = "{\"name\":\"a\",\"arguments\":{}}";
        let calls = |n: usize| format!("{{\"tool_calls\":[{}]}}", vec![call; n].join(","));
        assert!(Script::parse(&calls(MAX_CALLS)).is_ok());
        assert!(err(&calls(MAX_CALLS + 1)).contains("calls"));

        let turns = |n: usize| "{\"fail\":true}\n".repeat(n);
        assert!(Script::parse(&turns(MAX_TURNS)).is_ok());
        assert_eq!(
            err(&turns(MAX_TURNS + 1)),
            ScriptError::TooManyTurns.to_string()
        );

        let pad = |n: usize| format!("{{\"content\":\"{}\"}}", "a".repeat(n - 14));
        assert!(Script::parse(&pad(MAX_LINE_BYTES)).is_ok());
        assert!(err(&pad(MAX_LINE_BYTES + 1)).contains("longer than"));

        let big = |n: usize| format!("{}\n", "a".repeat(n - 1));
        assert_eq!(
            err(&big(MAX_SCRIPT_BYTES + 1)),
            ScriptError::TooLarge(MAX_SCRIPT_BYTES + 1).to_string()
        );
        let exactly = "{\"fail\":true}\n".repeat(MAX_SCRIPT_BYTES / 14);
        assert!(exactly.len() <= MAX_SCRIPT_BYTES);
    }
}
