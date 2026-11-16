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

#![deny(clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::body::Chat;
use super::server::{Backend, BackendError, Reply};
use crate::rpc::json;
use crate::rpc::message::{MAX_DEPTH, too_deep};

/// Bytes of a script at most (Q103).
pub const MAX_SCRIPT_BYTES: usize = sally_proto::MAX_SCRIPT_BYTES;
/// Bytes of one script line at most.
pub const MAX_LINE_BYTES: usize = 65_536;
/// Turns of a script at most.
pub const MAX_TURNS: usize = sally_proto::MAX_TURNS;
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
    #[error("model.script: {0} bytes exceed the {MAX_SCRIPT_BYTES}-byte limit")]
    TooLarge(usize),
    /// The script has more than [`MAX_TURNS`] turns.
    #[error("model.script: more than {MAX_TURNS} turns")]
    TooManyTurns,
    /// A line is wrong; the message names what.
    #[error("model.script line {line}: {what}")]
    Line {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        what: String,
    },
    /// A driven script has this turn (1-based) after a content or fail turn, which ends it.
    #[error("model.script turn {0}: follows a content or fail turn, which ends a driven script")]
    AfterEnd(usize),
}

/// One line as JSON: nested at most as deep as a frame on the agent socket, then parsed by the
/// broker's one strict parse (duplicate keys refused at every depth; architect ruling Q11).
fn strict(text: &str) -> Result<Value, String> {
    if too_deep(text.as_bytes(), MAX_DEPTH) {
        return Err(format!("nested deeper than {MAX_DEPTH}"));
    }
    json::parse(text.as_bytes()).map_err(|e| e.to_string())
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

    /// Whether the script may drive a session: a content or fail turn is its last, as a model's
    /// message ends its turn, so a step that reports `done` leaves nothing behind it.
    ///
    /// # Errors
    /// [`ScriptError::AfterEnd`] with the first turn that follows one.
    pub fn driven(&self) -> Result<(), ScriptError> {
        let end = self
            .turns
            .iter()
            .position(|t| matches!(t, Turn::Content(_) | Turn::Fail));
        match end {
            Some(i) if i + 1 < self.turns.len() => Err(ScriptError::AfterEnd(i + 2)),
            _ => Ok(()),
        }
    }
}

/// The scripted model as a [`Backend`]: the script's turns in order, one per request, and every
/// request it was given. A request past the last turn, and a `fail` turn, fail like the
/// backend: the broker answers 502. A streamed request gets the role, then the content or the
/// calls, then the finish reason, as three chunks. Tool-call ids are `call_<request>_<index>`.
#[derive(Debug, Default)]
pub struct Scripted {
    turns: Mutex<VecDeque<Turn>>,
    served: Mutex<usize>,
    /// The first [`MAX_SEEN`] checked requests, in order (a test's view of what was asked).
    pub seen: Mutex<Vec<Chat>>,
}

/// Requests [`Scripted::seen`] keeps at most; later ones are answered but not kept.
pub const MAX_SEEN: usize = 64;

fn locked<V>(m: &Mutex<V>) -> std::sync::MutexGuard<'_, V> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Scripted {
    /// A backend answering with `script`'s turns.
    #[must_use]
    pub fn from_script(script: &Script) -> Self {
        Self {
            turns: Mutex::new(script.turns.iter().cloned().collect()),
            ..Self::default()
        }
    }

    /// Turns not yet served.
    #[must_use]
    pub fn left(&self) -> usize {
        locked(&self.turns).len()
    }

    fn next(&self, chat: Chat) -> (usize, Option<Turn>, bool) {
        let stream = chat.stream;
        let mut seen = locked(&self.seen);
        if seen.len() < MAX_SEEN {
            seen.push(chat);
        }
        drop(seen);
        let mut served = locked(&self.served);
        *served += 1;
        (*served, locked(&self.turns).pop_front(), stream)
    }

    /// The scripted answer to `chat`.
    ///
    /// # Errors
    /// [`BackendError`] for a `fail` turn, or when the script has no turn left.
    pub fn complete(&self, chat: Chat) -> Result<Reply, BackendError> {
        let (request, turn, stream) = self.next(chat);
        let Some((mut msg, finish)) = turn.and_then(|t| message(request, &t)) else {
            return Err(BackendError);
        };
        let id = format!("chatcmpl-scripted-{request}");
        if !stream {
            msg.insert("role".into(), json!("assistant"));
            let msg = Value::Object(msg);
            return Ok(Reply::Whole(json!({
                "id": id,
                "object": "chat.completion",
                "model": "scripted",
                "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            })));
        }
        let chunk = |delta: Value, finish: Value| {
            json!({
                "id": id,
                "object": "chat.completion.chunk",
                "model": "scripted",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            })
        };
        let events = [
            chunk(json!({"role": "assistant"}), Value::Null),
            chunk(Value::Object(msg), Value::Null),
            chunk(json!({}), json!(finish)),
        ];
        let (tx, rx) = mpsc::channel(events.len());
        for e in events {
            // The channel holds every event: a full or closed channel cannot happen here.
            let _ = tx.try_send(e);
        }
        Ok(Reply::Stream(rx))
    }
}

/// The assistant message (or delta) of a turn, and its finish reason; `None` for a `fail` turn.
fn message(request: usize, turn: &Turn) -> Option<(Map<String, Value>, &'static str)> {
    let mut m = Map::new();
    match turn {
        Turn::Content(content) => {
            m.insert("content".into(), Value::from(content.as_str()));
            Some((m, "stop"))
        }
        Turn::ToolCalls(calls) => {
            let calls: Vec<Value> = calls
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    json!({
                        "index": i,
                        "id": format!("call_{request}_{i}"),
                        "type": "function",
                        "function": {
                            "name": c.name,
                            "arguments": Value::Object(c.arguments.clone()).to_string(),
                        },
                    })
                })
                .collect();
            m.insert("content".into(), Value::Null);
            m.insert("tool_calls".into(), Value::Array(calls));
            Some((m, "tool_calls"))
        }
        Turn::Fail => None,
    }
}

impl Backend for Arc<Scripted> {
    async fn complete(&self, chat: Chat) -> Result<Reply, BackendError> {
        Scripted::complete(self, chat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(text: &str) -> String {
        Script::parse(text).unwrap_err().to_string()
    }

    fn chat(stream: bool) -> Chat {
        Chat {
            body: Map::new(),
            stream,
            max_tokens: 16,
            messages: 1,
        }
    }

    fn backend(text: &str) -> Scripted {
        Scripted::from_script(&Script::parse(text).unwrap())
    }

    #[test]
    fn a_whole_reply_is_a_chat_completion_with_the_scripted_message() {
        let b = backend("{\"content\":\"hi\"}\n{\"fail\":true}");
        assert_eq!(b.left(), 2);
        let Ok(Reply::Whole(v)) = b.complete(chat(false)) else {
            panic!("not whole")
        };
        assert_eq!(v["id"], "chatcmpl-scripted-1");
        assert_eq!(v["choices"][0]["message"]["role"], "assistant");
        assert_eq!(v["choices"][0]["message"]["content"], "hi");
        assert_eq!(v["choices"][0]["finish_reason"], "stop");
        assert_eq!(b.left(), 1);
        assert_eq!(b.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn tool_calls_get_ids_from_the_request_and_their_index() {
        let b = backend(
            "{\"tool_calls\":[{\"name\":\"a\",\"arguments\":{\"k\":1}},{\"name\":\"b\",\"arguments\":{}}]}",
        );
        let Ok(Reply::Whole(v)) = b.complete(chat(false)) else {
            panic!()
        };
        let m = &v["choices"][0]["message"];
        assert_eq!(v["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(m["content"], Value::Null);
        assert_eq!(m["tool_calls"][0]["id"], "call_1_0");
        assert_eq!(m["tool_calls"][1]["id"], "call_1_1");
        assert_eq!(m["tool_calls"][0]["function"]["name"], "a");
        assert_eq!(m["tool_calls"][0]["function"]["arguments"], "{\"k\":1}");
        assert_eq!(m["tool_calls"][1]["index"], 1);
    }

    #[test]
    fn a_stream_is_the_role_then_the_message_then_the_finish_reason() {
        let b = backend("{\"content\":\"hi\"}");
        let Ok(Reply::Stream(mut rx)) = b.complete(chat(true)) else {
            panic!("not a stream")
        };
        let mut chunks = Vec::new();
        while let Ok(c) = rx.try_recv() {
            chunks.push(c);
        }
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "hi");
        assert_eq!(chunks[1]["choices"][0]["finish_reason"], Value::Null);
        assert_eq!(chunks[2]["choices"][0]["finish_reason"], "stop");
        assert_eq!(chunks[2]["object"], "chat.completion.chunk");
    }

    #[test]
    fn a_fail_turn_and_a_request_past_the_end_fail_the_backend() {
        let b = backend("{\"fail\":true}");
        assert!(b.complete(chat(false)).is_err());
        assert!(b.complete(chat(false)).is_err());
        assert_eq!(b.left(), 0);
        assert_eq!(b.seen.lock().unwrap().len(), 2, "both requests were seen");
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
        assert!(err("{\"content\":\"a\"}\n{\"x\":1}").starts_with("model.script line 2:"));
        assert!(err("{\"content\":1}").contains("unknown"));
        assert!(err("{\"fail\":false}").contains("unknown"));
        assert!(err("{\"content\":\"a\",\"fail\":true}").contains("exactly one key"));
        assert!(err("[]").contains("script line 1"));
        assert!(err("{}").contains("exactly one key"));
        assert!(err("not json").contains("script line 1"));
    }

    #[test]
    fn nesting_is_bounded_as_on_the_agent_socket() {
        let nest = |n: usize| {
            format!(
                "{{\"tool_calls\":[{{\"name\":\"a\",\"arguments\":{{\"k\":{}{}}}}}]}}",
                "[".repeat(n),
                "]".repeat(n)
            )
        };
        // The line's own object, the list, the call and its arguments hold four levels.
        assert!(Script::parse(&nest(MAX_DEPTH - 4)).is_ok());
        assert!(err(&nest(MAX_DEPTH - 3)).contains("nested deeper"));
    }

    #[test]
    fn the_backend_keeps_at_most_max_seen_requests() {
        let b = backend(&"{\"fail\":true}\n".repeat(MAX_SEEN + 2));
        for _ in 0..MAX_SEEN + 2 {
            let _ = b.complete(chat(false));
        }
        assert_eq!(b.seen.lock().unwrap().len(), MAX_SEEN);
        assert_eq!(b.left(), 0);
    }

    #[test]
    fn refuses_duplicate_keys() {
        assert!(err("{\"content\":\"a\",\"content\":\"b\"}").contains("repeated key"));
        let dup = "{\"tool_calls\":[{\"name\":\"a\",\"name\":\"b\",\"arguments\":{}}]}";
        assert!(err(dup).contains("repeated key"));
        let deep = "{\"tool_calls\":[{\"name\":\"a\",\"arguments\":{\"k\":{\"x\":1,\"x\":2}}}]}";
        assert!(err(deep).contains("repeated key"));
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
    fn rt_drv_08_caps_hold_at_their_boundaries() {
        assert_eq!((MAX_LINE_BYTES, MAX_CALLS), (64 * 1024, 8));
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
        let line = |n: usize| format!("{}\n", pad(n - 1));
        let mut exactly = line(MAX_LINE_BYTES).repeat(MAX_SCRIPT_BYTES / MAX_LINE_BYTES);
        let rest = MAX_SCRIPT_BYTES % MAX_LINE_BYTES;
        if rest > 0 {
            exactly.push_str(&line(rest));
        }
        assert_eq!(exactly.len(), MAX_SCRIPT_BYTES);
        assert!(Script::parse(&exactly).is_ok());
    }

    #[test]
    fn a_driven_script_ends_at_its_first_message_or_failure() {
        let call = "{\"tool_calls\":[{\"name\":\"a\",\"arguments\":{}}]}\n";
        for good in [
            String::new(),
            call.repeat(3),
            format!("{call}{call}{{\"content\":\"bye\"}}\n"),
            format!("{call}{{\"fail\":true}}\n"),
        ] {
            let s = Script::parse(&good).unwrap();
            assert_eq!(s.driven(), Ok(()), "{good}");
        }
        for (bad, turn) in [
            (format!("{{\"content\":\"hi\"}}\n{call}"), 2),
            (
                format!("{call}{{\"fail\":true}}\n\n{{\"content\":\"x\"}}\n"),
                3,
            ),
            ("{\"content\":\"a\"}\n{\"content\":\"b\"}\n".to_owned(), 2),
        ] {
            let s = Script::parse(&bad).unwrap();
            assert_eq!(s.driven(), Err(ScriptError::AfterEnd(turn)), "{bad}");
        }
        assert_eq!(
            ScriptError::AfterEnd(2).to_string(),
            "model.script turn 2: follows a content or fail turn, which ends a driven script"
        );
    }
}
