//! The chat-completion request body from the untrusted harness (ARCHITECTURE §4.4, Task 7
//! decision 1). Bounds first: the size and the nesting depth are checked on the raw bytes. Then
//! every member, at every level, must be on the allowlist and of the right shape; anything else
//! is refused with the path of the member. `n` must be 1, message content is text only, the
//! token limit is at most the session's context, and `model` is dropped (the session's model is
//! used). A key repeated in any object is malformed. Tool and function names match
//! `[A-Za-z0-9_-]{1,64}`; `tool_calls` belong to assistant messages and `tool_call_id` to tool
//! messages (architect ruling Q11). What passes is forwarded as checked: nothing the harness sent
//! reaches the backend unless this module named it.
#![deny(clippy::indexing_slicing)]

use serde_json::{Map, Value};

use crate::rpc::json;
use crate::rpc::message::too_deep;

/// Largest body accepted (ARCHITECTURE §4.4: 4 MiB).
pub const MAX_BODY: usize = 4 * 1024 * 1024;
/// Deepest nesting accepted (tool parameter schemas nest).
pub const MAX_DEPTH: usize = 64;
/// Messages per request at most.
pub const MAX_MESSAGES: usize = 1024;
/// Tools per request, and tool calls per message, at most.
pub const MAX_TOOLS: usize = 128;
/// Stop sequences at most (the OpenAI limit).
pub const MAX_STOP: usize = 4;
/// Longest stop sequence, in bytes.
pub const MAX_STOP_BYTES: usize = 256;
/// Longest `model`, message `name` or call id, in bytes.
pub const MAX_NAME_BYTES: usize = 256;
/// Longest tool or function name, in bytes (the OpenAI limit).
pub const MAX_FUNCTION_NAME: usize = 64;

/// Message roles accepted.
const ROLES: [&str; 5] = ["system", "developer", "user", "assistant", "tool"];
/// Members of a message.
// TODO(#55): M4 checks what the stock openai client replays (null refusal, annotations, …).
const MESSAGE: [&str; 5] = ["role", "content", "name", "tool_calls", "tool_call_id"];
/// Top-level members (ARCHITECTURE §4.4).
const TOP: [&str; 17] = [
    "model",
    "messages",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "stop",
    "seed",
    "stream",
    "stream_options",
    "response_format",
    "presence_penalty",
    "frequency_penalty",
    "n",
];

/// Why a body was refused. The stable code goes to the audit entry and the 400 reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Over [`MAX_BODY`].
    TooLarge,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Not UTF-8 JSON, or not an object.
    Malformed,
    /// A member that is not on the allowlist.
    UnknownField,
    /// A member of the wrong type or value.
    BadValue,
    /// A required member is absent.
    Missing,
    /// More items than the limit allows.
    TooMany,
    /// A content part other than text (images, audio and files are refused in v1).
    NonTextPart,
    /// `n` other than 1.
    NotOne,
    /// A token limit above the session's context, or both token-limit members at once.
    TokenLimit,
}

impl Reason {
    /// The stable code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "body-too-large",
            Self::TooDeep => "too-deep",
            Self::Malformed => "malformed",
            Self::UnknownField => "unknown-field",
            Self::BadValue => "bad-value",
            Self::Missing => "missing-field",
            Self::TooMany => "too-many",
            Self::NonTextPart => "non-text-part",
            Self::NotOne => "n-must-be-1",
            Self::TokenLimit => "token-limit",
        }
    }
}

/// A refused body: why, and the path of the member (`messages[2].content[0].type`); empty for
/// the body as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Why.
    pub reason: Reason,
    /// Where.
    pub field: String,
}

fn refuse(reason: Reason, field: impl Into<String>) -> Refusal {
    Refusal {
        reason,
        field: field.into(),
    }
}

/// A body that passed: what is forwarded, and what the audit entry records.
#[derive(Debug, Clone, PartialEq)]
pub struct Chat {
    /// The checked members, without `model`.
    pub body: Map<String, Value>,
    /// Whether the reply streams.
    pub stream: bool,
    /// The token limit the backend must hold: the requested one, or the session's context when
    /// none was requested (architect ruling Q2: the bound is always explicit).
    pub max_tokens: u64,
    /// How many messages.
    pub messages: usize,
}

/// Checks a body against the allowlist; `context` is the session's `model.context`.
///
/// # Errors
/// [`Refusal`] with the reason and the member's path.
pub fn check(bytes: &[u8], context: u64) -> Result<Chat, Refusal> {
    if bytes.len() > MAX_BODY {
        return Err(refuse(Reason::TooLarge, ""));
    }
    if too_deep(bytes, MAX_DEPTH) {
        return Err(refuse(Reason::TooDeep, ""));
    }
    let Ok(Value::Object(mut body)) = json::parse(bytes) else {
        return Err(refuse(Reason::Malformed, ""));
    };
    if let Some(k) = body.keys().find(|k| !TOP.contains(&k.as_str())) {
        return Err(refuse(Reason::UnknownField, k.as_str()));
    }
    if let Some(m) = body.remove("model") {
        name(&m, "model")?;
    }
    let messages = messages(body.get("messages"))?;
    let max_tokens = token_limit(&body, context)?.unwrap_or(context);
    let stream = flag(&body, "stream")?.unwrap_or(false);
    flag(&body, "parallel_tool_calls")?;
    number(&body, "temperature", 0.0, 2.0)?;
    number(&body, "top_p", 0.0, 1.0)?;
    number(&body, "presence_penalty", -2.0, 2.0)?;
    number(&body, "frequency_penalty", -2.0, 2.0)?;
    if let Some(s) = body.get("seed")
        && s.as_i64().is_none()
    {
        return Err(refuse(Reason::BadValue, "seed"));
    }
    if let Some(n) = body.get("n") {
        match n.as_u64() {
            Some(1) => {}
            Some(_) => return Err(refuse(Reason::NotOne, "n")),
            None => return Err(refuse(Reason::BadValue, "n")),
        }
    }
    if let Some(t) = body.get("tools") {
        tools(t)?;
    }
    if let Some(c) = body.get("tool_choice") {
        tool_choice(c)?;
    }
    if let Some(s) = body.get("stop") {
        stop(s)?;
    }
    if let Some(o) = body.get("stream_options") {
        let o = object(o, "stream_options", &["include_usage"])?;
        flag(o, "include_usage").map_err(|r| prefixed(r, "stream_options"))?;
    }
    if let Some(f) = body.get("response_format") {
        response_format(f)?;
    }
    Ok(Chat {
        body,
        stream,
        max_tokens,
        messages,
    })
}

/// `messages`: required, 1 to [`MAX_MESSAGES`]; each checked.
fn messages(v: Option<&Value>) -> Result<usize, Refusal> {
    let list = match v {
        None => return Err(refuse(Reason::Missing, "messages")),
        Some(Value::Array(a)) if !a.is_empty() => a,
        Some(_) => return Err(refuse(Reason::BadValue, "messages")),
    };
    if list.len() > MAX_MESSAGES {
        return Err(refuse(Reason::TooMany, "messages"));
    }
    for (i, m) in list.iter().enumerate() {
        message(m).map_err(|r| prefixed(r, &format!("messages[{i}]")))?;
    }
    Ok(list.len())
}

/// One message: a known role and only the members of [`MESSAGE`].
fn message(v: &Value) -> Result<(), Refusal> {
    let m = object(v, "", &MESSAGE)?;
    let role = match m.get("role").and_then(Value::as_str) {
        Some(r) if ROLES.contains(&r) => r,
        Some(_) => return Err(refuse(Reason::BadValue, "role")),
        None if m.contains_key("role") => return Err(refuse(Reason::BadValue, "role")),
        None => return Err(refuse(Reason::Missing, "role")),
    };
    if role != "assistant" && m.contains_key("tool_calls") {
        return Err(refuse(Reason::UnknownField, "tool_calls"));
    }
    if role != "tool" && m.contains_key("tool_call_id") {
        return Err(refuse(Reason::UnknownField, "tool_call_id"));
    }
    if let Some(c) = m.get("content") {
        content(c)?;
    }
    if let Some(n) = m.get("name") {
        name(n, "name")?;
    }
    if let Some(id) = m.get("tool_call_id") {
        name(id, "tool_call_id")?;
    }
    if let Some(calls) = m.get("tool_calls") {
        let Value::Array(calls) = calls else {
            return Err(refuse(Reason::BadValue, "tool_calls"));
        };
        if calls.len() > MAX_TOOLS {
            return Err(refuse(Reason::TooMany, "tool_calls"));
        }
        for (i, c) in calls.iter().enumerate() {
            tool_call(c).map_err(|r| prefixed(r, &format!("tool_calls[{i}]")))?;
        }
    }
    Ok(())
}

/// Content: a string, `null`, or an array of text parts.
fn content(v: &Value) -> Result<(), Refusal> {
    match v {
        Value::String(_) | Value::Null => Ok(()),
        Value::Array(parts) => {
            for (i, p) in parts.iter().enumerate() {
                let at = format!("content[{i}]");
                // The kind decides first: an image part is refused as one, whatever it holds.
                match p.get("type").and_then(Value::as_str) {
                    Some("text") => {}
                    Some(_) => return Err(refuse(Reason::NonTextPart, format!("{at}.type"))),
                    None if p.is_object() => {
                        return Err(refuse(Reason::BadValue, format!("{at}.type")));
                    }
                    None => return Err(refuse(Reason::BadValue, at)),
                }
                let p = object(p, &at, &["type", "text"])?;
                if !p.get("text").is_some_and(Value::is_string) {
                    return Err(refuse(Reason::BadValue, format!("{at}.text")));
                }
            }
            Ok(())
        }
        _ => Err(refuse(Reason::BadValue, "content")),
    }
}

/// An assistant's tool call: `{id, type: "function", function: {name, arguments}}`.
fn tool_call(v: &Value) -> Result<(), Refusal> {
    let c = object(v, "", &["id", "type", "function"])?;
    name(c.get("id").unwrap_or(&Value::Null), "id")?;
    function_type(c)?;
    let f = object(
        c.get("function").unwrap_or(&Value::Null),
        "function",
        &["name", "arguments"],
    )?;
    function_name(f.get("name").unwrap_or(&Value::Null), "function.name")?;
    if !f.get("arguments").is_some_and(Value::is_string) {
        return Err(refuse(Reason::BadValue, "function.arguments"));
    }
    Ok(())
}

/// `tools`: at most [`MAX_TOOLS`] of `{type: "function", function: {name, description?,
/// parameters?, strict?}}`.
fn tools(v: &Value) -> Result<(), Refusal> {
    let Value::Array(list) = v else {
        return Err(refuse(Reason::BadValue, "tools"));
    };
    if list.len() > MAX_TOOLS {
        return Err(refuse(Reason::TooMany, "tools"));
    }
    for (i, t) in list.iter().enumerate() {
        tool(t).map_err(|r| prefixed(r, &format!("tools[{i}]")))?;
    }
    Ok(())
}

fn tool(v: &Value) -> Result<(), Refusal> {
    let t = object(v, "", &["type", "function"])?;
    function_type(t)?;
    let f = object(
        t.get("function").unwrap_or(&Value::Null),
        "function",
        &["name", "description", "parameters", "strict"],
    )?;
    function_name(f.get("name").unwrap_or(&Value::Null), "function.name")?;
    if f.get("description").is_some_and(|d| !d.is_string()) {
        return Err(refuse(Reason::BadValue, "function.description"));
    }
    if f.get("parameters").is_some_and(|p| !p.is_object()) {
        return Err(refuse(Reason::BadValue, "function.parameters"));
    }
    flag(f, "strict").map_err(|r| prefixed(r, "function"))?;
    Ok(())
}

/// `tool_choice`: `none`, `auto`, `required`, or `{type: "function", function: {name}}`.
fn tool_choice(v: &Value) -> Result<(), Refusal> {
    if let Value::String(s) = v {
        return if ["none", "auto", "required"].contains(&s.as_str()) {
            Ok(())
        } else {
            Err(refuse(Reason::BadValue, "tool_choice"))
        };
    }
    let c = object(v, "tool_choice", &["type", "function"])?;
    function_type(c).map_err(|r| prefixed(r, "tool_choice"))?;
    let f = object(
        c.get("function").unwrap_or(&Value::Null),
        "tool_choice.function",
        &["name"],
    )?;
    function_name(
        f.get("name").unwrap_or(&Value::Null),
        "tool_choice.function.name",
    )
}

/// `stop`: a string, or at most [`MAX_STOP`] strings; each at most [`MAX_STOP_BYTES`].
fn stop(v: &Value) -> Result<(), Refusal> {
    let short = |s: &Value| s.as_str().is_some_and(|s| s.len() <= MAX_STOP_BYTES);
    match v {
        Value::String(_) if short(v) => Ok(()),
        Value::Array(a) if a.len() > MAX_STOP => Err(refuse(Reason::TooMany, "stop")),
        Value::Array(a) if a.iter().all(short) => Ok(()),
        _ => Err(refuse(Reason::BadValue, "stop")),
    }
}

/// `response_format`: `{type: text | json_object}` or `{type: json_schema, json_schema: {…}}`.
fn response_format(v: &Value) -> Result<(), Refusal> {
    let f = object(v, "response_format", &["type", "json_schema"])?;
    let schema = f.get("json_schema");
    match f.get("type").and_then(Value::as_str) {
        Some("text" | "json_object") if schema.is_none() => Ok(()),
        Some("json_schema") if schema.is_some_and(Value::is_object) => Ok(()),
        Some("json_schema") => Err(refuse(Reason::BadValue, "response_format.json_schema")),
        _ => Err(refuse(Reason::BadValue, "response_format.type")),
    }
}

/// `max_tokens` or `max_completion_tokens` (not both): 1 to `context`.
fn token_limit(body: &Map<String, Value>, context: u64) -> Result<Option<u64>, Refusal> {
    let (a, b) = (body.get("max_tokens"), body.get("max_completion_tokens"));
    let (key, v) = match (a, b) {
        (Some(_), Some(_)) => return Err(refuse(Reason::TokenLimit, "max_completion_tokens")),
        (Some(v), None) => ("max_tokens", v),
        (None, Some(v)) => ("max_completion_tokens", v),
        (None, None) => return Ok(None),
    };
    match v.as_u64() {
        Some(n) if (1..=context).contains(&n) => Ok(Some(n)),
        Some(0) | None => Err(refuse(Reason::BadValue, key)),
        Some(_) => Err(refuse(Reason::TokenLimit, key)),
    }
}

/// `type` must be `"function"`.
fn function_type(o: &Map<String, Value>) -> Result<(), Refusal> {
    if o.get("type").and_then(Value::as_str) == Some("function") {
        Ok(())
    } else {
        Err(refuse(Reason::BadValue, "type"))
    }
}

/// A non-empty string of at most [`MAX_NAME_BYTES`].
fn name(v: &Value, at: &str) -> Result<(), Refusal> {
    match v.as_str() {
        Some(s) if !s.is_empty() && s.len() <= MAX_NAME_BYTES => Ok(()),
        _ => Err(refuse(Reason::BadValue, at)),
    }
}

/// A tool or function name: `[A-Za-z0-9_-]{1,64}`.
fn function_name(v: &Value, at: &str) -> Result<(), Refusal> {
    let ok = |s: &str| {
        (1..=MAX_FUNCTION_NAME).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    match v.as_str() {
        Some(s) if ok(s) => Ok(()),
        _ => Err(refuse(Reason::BadValue, at)),
    }
}

/// `key`, if present, must be a boolean.
fn flag(o: &Map<String, Value>, key: &str) -> Result<Option<bool>, Refusal> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(refuse(Reason::BadValue, key)),
    }
}

/// `key`, if present, must be a number in `lo..=hi`.
fn number(o: &Map<String, Value>, key: &str, lo: f64, hi: f64) -> Result<(), Refusal> {
    match o.get(key).map(Value::as_f64) {
        None => Ok(()),
        Some(Some(x)) if (lo..=hi).contains(&x) => Ok(()),
        Some(_) => Err(refuse(Reason::BadValue, key)),
    }
}

/// `v` as an object whose members are all in `allowed`.
fn object<'a>(v: &'a Value, at: &str, allowed: &[&str]) -> Result<&'a Map<String, Value>, Refusal> {
    let Value::Object(o) = v else {
        return Err(refuse(Reason::BadValue, at));
    };
    match o.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(refuse(Reason::UnknownField, join(at, k))),
        None => Ok(o),
    }
}

/// The refusal with `prefix` in front of its path.
fn prefixed(r: Refusal, prefix: &str) -> Refusal {
    Refusal {
        field: join(prefix, &r.field),
        ..r
    }
}

fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_owned(),
        (false, true) => a.to_owned(),
        (false, false) => format!("{a}.{b}"),
    }
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod tests;
