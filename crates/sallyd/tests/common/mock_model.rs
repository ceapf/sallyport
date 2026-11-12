//! The scripted mock model (architect ruling Q3): a `sallyd::llm::server::Backend` for tests
//! only. It lives in the test tree; `sallyd` has no mock, no script parser and no switch for one.
//!
//! A script is JSON Lines under `tests/redteam/attacks/model_scripts/`; each request takes the
//! next line. A line is exactly one of:
//! - `{"content": "<text>"}`: an assistant message;
//! - `{"tool_calls": [{"name": "<tool>", "arguments": {…}}, …]}`: an assistant message that
//!   calls tools (ids `call_<request>_<index>`, `finish_reason: "tool_calls"`);
//! - `{"fail": true}`: the backend fails (the broker answers 502).
//!
//! Any other shape is a script error. A request past the last line fails like `{"fail": true}`.
//! A streamed request gets the role, then the content or the calls, then the finish reason, as
//! three chunks.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sallyd::llm::body::Chat;
use sallyd::llm::server::{Backend, BackendError, Reply};
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;

/// One scripted turn.
#[derive(Debug, Clone, PartialEq)]
pub enum Turn {
    Content(String),
    ToolCalls(Vec<(String, Map<String, Value>)>),
    Fail,
}

impl Turn {
    /// One script line; the error names what is wrong.
    pub fn parse(line: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let Some(obj) = v.as_object().filter(|o| o.len() == 1) else {
            return Err("a line is an object with exactly one key".into());
        };
        match obj.iter().next() {
            Some((k, Value::String(s))) if k == "content" => Ok(Self::Content(s.clone())),
            Some((k, Value::Bool(true))) if k == "fail" => Ok(Self::Fail),
            Some((k, Value::Array(calls))) if k == "tool_calls" => calls
                .iter()
                .map(call)
                .collect::<Result<_, _>>()
                .map(Self::ToolCalls),
            _ => Err(format!("unknown line {line}")),
        }
    }
}

fn call(v: &Value) -> Result<(String, Map<String, Value>), String> {
    let o = v
        .as_object()
        .filter(|o| o.len() == 2)
        .ok_or("a call has name and arguments")?;
    match (o.get("name"), o.get("arguments")) {
        (Some(Value::String(n)), Some(Value::Object(a))) => Ok((n.clone(), a.clone())),
        _ => Err("a call has a string name and object arguments".into()),
    }
}

/// The mock: the script's turns in order, and every request it was given.
#[derive(Debug, Default)]
pub struct MockModel {
    turns: Mutex<VecDeque<Turn>>,
    served: Mutex<usize>,
    /// The checked requests, in order.
    pub seen: Mutex<Vec<Chat>>,
}

/// `tests/redteam/attacks/model_scripts/<name>`.
pub fn script_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/redteam/attacks/model_scripts")
        .join(name)
}

impl MockModel {
    /// Parses a script; a malformed line is an error naming it.
    pub fn parse(text: &str) -> Result<Self, String> {
        let turns = text
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, l)| Turn::parse(l).map_err(|e| format!("line {}: {e}", i + 1)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            turns: Mutex::new(turns),
            ..Self::default()
        })
    }

    /// Loads `tests/redteam/attacks/model_scripts/<name>`; panics on a broken fixture.
    pub fn load(name: &str) -> Arc<Self> {
        let text = std::fs::read_to_string(script_path(name)).unwrap();
        Arc::new(Self::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}")))
    }

    /// Turns not yet served.
    pub fn left(&self) -> usize {
        self.turns.lock().unwrap().len()
    }

    fn next(&self, chat: Chat) -> (usize, Option<Turn>, bool) {
        let stream = chat.stream;
        self.seen.lock().unwrap().push(chat);
        let mut served = self.served.lock().unwrap();
        *served += 1;
        (*served, self.turns.lock().unwrap().pop_front(), stream)
    }
}

/// The assistant message (or delta) of a turn, and its finish reason.
fn message(request: usize, turn: &Turn) -> (Value, &'static str) {
    match turn {
        Turn::Content(content) => (json!({"content": content}), "stop"),
        Turn::ToolCalls(calls) => {
            let calls: Vec<Value> = calls
                .iter()
                .enumerate()
                .map(|(i, (name, arguments))| {
                    json!({
                        "index": i,
                        "id": format!("call_{request}_{i}"),
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": Value::Object(arguments.clone()).to_string(),
                        },
                    })
                })
                .collect();
            (json!({"content": null, "tool_calls": calls}), "tool_calls")
        }
        Turn::Fail => (Value::Null, "stop"),
    }
}

/// The backend a test hands the server; the test keeps the [`MockModel`] to inspect.
pub struct Backed(pub Arc<MockModel>);

impl Backend for Backed {
    async fn complete(&self, chat: Chat) -> Result<Reply, BackendError> {
        self.0.complete(chat)
    }
}

impl MockModel {
    /// The scripted answer to `chat`.
    pub fn complete(&self, chat: Chat) -> Result<Reply, BackendError> {
        let (request, turn, stream) = self.next(chat);
        let turn = match turn {
            None | Some(Turn::Fail) => return Err(BackendError),
            Some(t) => t,
        };
        let (mut msg, finish) = message(request, &turn);
        let id = format!("chatcmpl-mock-{request}");
        if !stream {
            msg["role"] = json!("assistant");
            return Ok(Reply::Whole(json!({
                "id": id,
                "object": "chat.completion",
                "model": "mock",
                "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            })));
        }
        let chunk = |delta: Value, finish: Value| {
            json!({
                "id": id,
                "object": "chat.completion.chunk",
                "model": "mock",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            })
        };
        let events = [
            chunk(json!({"role": "assistant"}), Value::Null),
            chunk(msg, Value::Null),
            chunk(json!({}), json!(finish)),
        ];
        let (tx, rx) = mpsc::channel(events.len());
        for e in events {
            tx.try_send(e).unwrap();
        }
        Ok(Reply::Stream(rx))
    }
}
