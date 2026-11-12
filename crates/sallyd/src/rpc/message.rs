//! One JSON-RPC 2.0 message from an untrusted peer (Task 7 decision 3): bounds first, then the
//! parse. The nesting depth is counted over the raw bytes before `serde_json` sees them, a batch
//! (a JSON array) is refused, and every member of the envelope is checked strictly: `jsonrpc`
//! must be `"2.0"`, an `id` is an integer or a string of at most [`MAX_ID_BYTES`], a `method` is a
//! string of at most [`MAX_METHOD_BYTES`], `params` is an object, and no other member is allowed.
//! A key repeated in any object is a parse error ([`super::json`]).
#![deny(clippy::indexing_slicing)]

use serde_json::{Map, Value};

/// Deepest nesting of arrays and objects accepted, the envelope included.
pub const MAX_DEPTH: usize = 64;
/// Longest string `id` accepted, in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Longest `method` accepted, in bytes.
pub const MAX_METHOD_BYTES: usize = 64;

/// JSON-RPC: the bytes are not JSON.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: the JSON is not a valid request.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: the method does not exist (or is not on the allowlist).
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC: the parameters are not valid.
pub const INVALID_PARAMS: i64 = -32602;
/// JSON-RPC: the server failed.
pub const INTERNAL_ERROR: i64 = -32603;

/// A request id: an integer or a bounded string. `null` and fractions are refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Id {
    /// An integer id.
    Num(i64),
    /// A string id.
    Str(String),
}

impl Id {
    /// The id as JSON, for a reply.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Num(n) => Value::from(*n),
            Self::Str(s) => Value::from(s.as_str()),
        }
    }
}

/// A well-formed message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A request: it expects a reply.
    Request {
        /// Its id.
        id: Id,
        /// Its method.
        method: String,
        /// Its parameters; an absent `params` is an empty object.
        params: Map<String, Value>,
    },
    /// A notification: no id, no reply.
    Notification {
        /// Its method.
        method: String,
        /// Its parameters; an absent `params` is an empty object.
        params: Map<String, Value>,
    },
    /// A response (`result` or `error` with an id, no method). The broker sends no requests, so
    /// none is ever expected.
    Response,
}

/// Why a message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Not UTF-8 JSON.
    Parse,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A JSON array: batches are not served.
    Batch,
    /// Not a JSON object.
    NotObject,
    /// `jsonrpc` is missing or not `"2.0"`.
    Version,
    /// The `id` is `null`, a fraction, out of range, too long or of another type.
    Id,
    /// The `method` is not a string or is too long.
    Method,
    /// `params` is present and not an object.
    Params,
    /// A member other than `jsonrpc`, `id`, `method`, `params`, `result`, `error`, or a response
    /// that is not exactly one of `result` and `error` with an id.
    Shape,
}

impl Reason {
    /// The JSON-RPC error code of the reply.
    #[must_use]
    pub fn code(self) -> i64 {
        match self {
            Self::Parse | Self::TooDeep => PARSE_ERROR,
            Self::Params => INVALID_PARAMS,
            Self::Batch
            | Self::NotObject
            | Self::Version
            | Self::Id
            | Self::Method
            | Self::Shape => INVALID_REQUEST,
        }
    }

    /// The stable code written to the audit log and the reply's `data.reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse-error",
            Self::TooDeep => "too-deep",
            Self::Batch => "batch",
            Self::NotObject => "not-object",
            Self::Version => "bad-version",
            Self::Id => "bad-id",
            Self::Method => "bad-method",
            Self::Params => "bad-params",
            Self::Shape => "bad-shape",
        }
    }
}

/// A refused message: why, and its id when one could be read (the reply carries it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// Why.
    pub reason: Reason,
    /// The id, if the envelope had a valid one.
    pub id: Option<Id>,
}

impl From<Reason> for Rejected {
    fn from(reason: Reason) -> Self {
        Self { reason, id: None }
    }
}

/// Envelope members a message may carry.
const MEMBERS: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];

/// Parses one message (one frame, without its newline).
///
/// # Errors
/// [`Rejected`] with the reason and, when it was valid, the id.
pub fn parse(frame: &[u8]) -> Result<Message, Rejected> {
    if too_deep(frame, MAX_DEPTH) {
        return Err(Reason::TooDeep.into());
    }
    let value = super::json::parse(frame).map_err(|_| Reason::Parse)?;
    let obj = match value {
        Value::Object(o) => o,
        Value::Array(_) => return Err(Reason::Batch.into()),
        _ => return Err(Reason::NotObject.into()),
    };
    envelope(obj)
}

/// Checks the members of an object already parsed.
fn envelope(mut obj: Map<String, Value>) -> Result<Message, Rejected> {
    let id = match obj.remove("id") {
        None => None,
        Some(v) => Some(id(&v).ok_or(Reason::Id)?),
    };
    let fail = |reason: Reason| Rejected {
        reason,
        id: id.clone(),
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(fail(Reason::Version));
    }
    if obj.keys().any(|k| !MEMBERS.contains(&k.as_str())) {
        return Err(fail(Reason::Shape));
    }
    let Some(method) = obj.remove("method") else {
        let one = obj.contains_key("result") != obj.contains_key("error");
        let only = !obj.contains_key("params");
        return if id.is_some() && one && only {
            Ok(Message::Response)
        } else {
            Err(fail(Reason::Shape))
        };
    };
    if obj.contains_key("result") || obj.contains_key("error") {
        return Err(fail(Reason::Shape));
    }
    let method = match method {
        Value::String(m) if m.len() <= MAX_METHOD_BYTES => m,
        _ => return Err(fail(Reason::Method)),
    };
    let params = match obj.remove("params") {
        None => Map::new(),
        Some(Value::Object(p)) => p,
        Some(_) => return Err(fail(Reason::Params)),
    };
    Ok(match id {
        Some(id) => Message::Request { id, method, params },
        None => Message::Notification { method, params },
    })
}

/// The id, if it is an `i64` or a string of at most [`MAX_ID_BYTES`].
fn id(v: &Value) -> Option<Id> {
    match v {
        Value::Number(n) => n.as_i64().map(Id::Num),
        Value::String(s) if s.len() <= MAX_ID_BYTES => Some(Id::Str(s.clone())),
        _ => None,
    }
}

/// Whether arrays and objects in `bytes` nest deeper than `max`, counting brackets outside
/// strings. Malformed input may count wrongly; the parser refuses it afterwards anyway.
#[must_use]
pub fn too_deep(bytes: &[u8], max: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(s: &str) -> Result<Message, Rejected> {
        parse(s.as_bytes())
    }

    fn reason(s: &str) -> Reason {
        p(s).unwrap_err().reason
    }

    fn nested(n: usize) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","method":"m","params":{{"a":{}0{}}}}}"#,
            "[".repeat(n),
            "]".repeat(n)
        )
    }

    #[test]
    fn a_request_parses_with_its_id_method_and_params() {
        let m = p(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"a":1}}"#).unwrap();
        let Message::Request { id, method, params } = m else {
            panic!("not a request: {m:?}");
        };
        assert_eq!(id, Id::Num(7));
        assert_eq!(method, "tools/list");
        assert_eq!(params["a"], json!(1));
    }

    #[test]
    fn absent_params_are_an_empty_object() {
        let m = p(r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#).unwrap();
        assert_eq!(
            m,
            Message::Request {
                id: Id::Str("x".into()),
                method: "ping".into(),
                params: Map::new()
            }
        );
    }

    #[test]
    fn a_message_without_an_id_is_a_notification() {
        let m = p(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#).unwrap();
        assert!(
            matches!(m, Message::Notification { ref method, .. } if method == "notifications/cancelled")
        );
    }

    #[test]
    fn responses_need_an_id_and_exactly_one_of_result_and_error() {
        assert_eq!(
            p(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Ok(Message::Response)
        );
        assert_eq!(
            p(r#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#),
            Ok(Message::Response)
        );
        assert_eq!(reason(r#"{"jsonrpc":"2.0","result":{}}"#), Reason::Shape);
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#),
            Reason::Shape
        );
        assert_eq!(reason(r#"{"jsonrpc":"2.0","id":1}"#), Reason::Shape);
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1,"result":{},"params":{}}"#),
            Reason::Shape
        );
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1,"method":"m","result":{}}"#),
            Reason::Shape
        );
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1,"method":"m","error":{}}"#),
            Reason::Shape
        );
    }

    #[test]
    fn a_batch_is_refused() {
        assert_eq!(
            reason(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#),
            Reason::Batch
        );
        assert_eq!(Reason::Batch.code(), INVALID_REQUEST);
    }

    #[test]
    fn non_objects_and_non_json_are_refused() {
        assert_eq!(reason("3"), Reason::NotObject);
        assert_eq!(reason(r#""s""#), Reason::NotObject);
        assert_eq!(reason("{"), Reason::Parse);
        assert_eq!(reason(""), Reason::Parse);
        assert_eq!(
            parse(b"{\"a\":\"\xff\"}").unwrap_err().reason,
            Reason::Parse
        );
        // A repeated member could show one method to a reader and another to the broker.
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}"#),
            Reason::Parse
        );
        assert_eq!(Reason::Parse.code(), PARSE_ERROR);
    }

    #[test]
    fn the_version_must_be_2_0() {
        assert_eq!(reason(r#"{"id":1,"method":"m"}"#), Reason::Version);
        assert_eq!(
            reason(r#"{"jsonrpc":"1.0","id":1,"method":"m"}"#),
            Reason::Version
        );
        assert_eq!(
            reason(r#"{"jsonrpc":2.0,"id":1,"method":"m"}"#),
            Reason::Version
        );
    }

    #[test]
    fn a_refusal_keeps_a_valid_id_for_the_reply() {
        let r = p(r#"{"jsonrpc":"1.0","id":"a","method":"m"}"#).unwrap_err();
        assert_eq!(r.id, Some(Id::Str("a".into())));
        let r = p(r#"{"jsonrpc":"2.0","id":3,"method":5}"#).unwrap_err();
        assert_eq!((r.reason, r.id), (Reason::Method, Some(Id::Num(3))));
    }

    #[test]
    fn ids_are_integers_or_bounded_strings() {
        let ok = |id: &str| p(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"m"}}"#));
        assert!(ok("-9223372036854775808").is_ok());
        assert!(ok("9223372036854775807").is_ok());
        assert!(ok(&format!(r#""{}""#, "a".repeat(MAX_ID_BYTES))).is_ok());
        for bad in [
            "null",
            "1.5",
            "1e3",
            "9223372036854775808",
            "true",
            "[]",
            "{}",
            &format!(r#""{}""#, "a".repeat(MAX_ID_BYTES + 1)),
        ] {
            assert_eq!(ok(bad).unwrap_err().reason, Reason::Id, "{bad}");
        }
    }

    #[test]
    fn methods_are_bounded_strings() {
        let m = |name: &str| p(&format!(r#"{{"jsonrpc":"2.0","id":1,"method":{name}}}"#));
        assert!(m(&format!(r#""{}""#, "a".repeat(MAX_METHOD_BYTES))).is_ok());
        let long = format!(r#""{}""#, "a".repeat(MAX_METHOD_BYTES + 1));
        assert_eq!(m(&long).unwrap_err().reason, Reason::Method);
        assert_eq!(m("null").unwrap_err().reason, Reason::Method);
    }

    #[test]
    fn params_must_be_an_object() {
        for bad in ["[1]", "1", "null", r#""x""#] {
            let s = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"m","params":{bad}}}"#);
            assert_eq!(reason(&s), Reason::Params, "{bad}");
        }
        assert_eq!(Reason::Params.code(), INVALID_PARAMS);
    }

    #[test]
    fn unknown_members_are_refused() {
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1,"method":"m","extra":1}"#),
            Reason::Shape
        );
    }

    #[test]
    fn nesting_is_bounded_before_the_parse() {
        // The envelope and params objects count: 2 + n.
        assert!(parse(nested(MAX_DEPTH - 2).as_bytes()).is_ok());
        assert_eq!(
            parse(nested(MAX_DEPTH - 1).as_bytes()).unwrap_err().reason,
            Reason::TooDeep
        );
        // Far deeper than serde_json's own recursion limit still ends as TooDeep, not a crash.
        assert_eq!(
            parse("[".repeat(100_000).as_bytes()).unwrap_err().reason,
            Reason::TooDeep
        );
        assert_eq!(Reason::TooDeep.code(), PARSE_ERROR);
    }

    #[test]
    fn brackets_inside_strings_do_not_count() {
        let inner = format!(r#""{}\"{}""#, "[".repeat(200), "{".repeat(200));
        let s = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"m","params":{{"a":{inner}}}}}"#);
        assert!(parse(s.as_bytes()).is_ok());
    }

    #[test]
    fn depth_counting_follows_closing_brackets_and_escapes() {
        assert!(!too_deep(b"[][][]", 1));
        assert!(too_deep(b"[[]]", 1));
        assert!(!too_deep(b"[{}]", 2));
        assert!(too_deep(b"[{[]}]", 2));
        // An escaped quote does not end the string; the brackets after it are inside it.
        assert!(!too_deep(br#"["\"[[["]"#, 1));
        // An escaped backslash does end the escape; the quote after it closes the string.
        assert!(too_deep(br#"["\\"[[]]"#, 2));
        // Unbalanced closers never underflow.
        assert!(!too_deep(b"]]]][", 1));
        assert!(too_deep(b"]]]][[", 1));
    }

    #[test]
    fn reasons_have_stable_codes() {
        let all = [
            Reason::Parse,
            Reason::TooDeep,
            Reason::Batch,
            Reason::NotObject,
            Reason::Version,
            Reason::Id,
            Reason::Method,
            Reason::Params,
            Reason::Shape,
        ];
        let names: Vec<_> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            names,
            [
                "parse-error",
                "too-deep",
                "batch",
                "not-object",
                "bad-version",
                "bad-id",
                "bad-method",
                "bad-params",
                "bad-shape"
            ]
        );
        for r in [
            Reason::NotObject,
            Reason::Version,
            Reason::Id,
            Reason::Method,
            Reason::Shape,
        ] {
            assert_eq!(r.code(), INVALID_REQUEST);
        }
    }

    #[test]
    fn ids_round_trip_to_json() {
        assert_eq!(Id::Num(-4).to_value(), json!(-4));
        assert_eq!(Id::Str("q".into()).to_value(), json!("q"));
    }
}
