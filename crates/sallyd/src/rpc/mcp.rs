//! The MCP subset `agent.sock` serves (AMENDMENTS-01 §3.1; Task 7 decision 3): pure decisions
//! over one parsed message. Which lifecycle a request belongs to, whether its method is on the
//! allowlist, and the exact reply shapes of each lifecycle.
//!
//! Shapes follow the MCP specification revisions 2026-07-28 and 2025-11-25 as published at
//! <https://modelcontextprotocol.io/specification/2026-07-28> and its schema
//! (`schema/2026-07-28/schema.ts` in `modelcontextprotocol/modelcontextprotocol`), read
//! 2026-11-11. Lifecycle rules (architect ruling Q6):
//! - A request whose `params._meta` carries the 2026 keys is served under 2026 rules; the version
//!   must be [`MODERN`], else `-32022`. Carrying one key without the other is `-32602`, never a
//!   fallback to the legacy rules.
//! - `initialize` makes the connection legacy: the client's version is echoed if it is in
//!   [`LEGACY`], else the latest legacy version is offered. A second `initialize` is `-32600`.
//! - A request without the 2026 keys is served only on a legacy connection; elsewhere `-32602`.
//! - `ping` and `notifications/initialized` exist only in the legacy lifecycle;
//!   `server/discover` only in 2026. `notifications/cancelled` is valid in both (its 2026 params
//!   carry no protocol keys).
//! - `resultType`, `ttlMs` and `cacheScope` appear on 2026 replies only. The tool table is the
//!   session's, so it is never cached: `ttlMs` 0, `cacheScope` `"private"`.
#![deny(clippy::indexing_slicing)]

use serde_json::{Map, Value, json};

use super::message::{INVALID_PARAMS, INVALID_REQUEST, Id, MAX_ID_BYTES, METHOD_NOT_FOUND};

/// The stateless revision served.
pub const MODERN: &str = "2026-07-28";
/// The newest legacy revision: offered when a client asks for one not served.
pub const NEWEST_LEGACY: &str = "2025-11-25";
/// Legacy revisions served through `initialize`, newest first.
pub const LEGACY: [&str; 3] = [NEWEST_LEGACY, "2025-06-18", "2025-03-26"];
/// `_meta` key of a 2026 request's protocol version.
pub const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key of a 2026 request's client capabilities.
pub const META_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key of the server's identity on a 2026 discover result.
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
/// MCP 2026: the requested protocol version is not supported.
pub const UNSUPPORTED_VERSION: i64 = -32022;
/// Implementation-defined server error (`-32000`): a limit refused the request.
pub const SERVER_LIMIT: i64 = -32000;
/// Longest tool name accepted in `tools/call`, in bytes (the spec's SHOULD: 1–128).
pub const MAX_TOOL_NAME: usize = 128;
/// Longest version string kept from a request (for the reply and the audit entry), in bytes.
pub const MAX_VERSION_BYTES: usize = 64;
/// The server's name in `serverInfo`.
pub const SERVER_NAME: &str = "sallyport";

/// Every method name the session socket knows. Anything else is `-32601` + `rpc.deny`.
pub const SESSION_METHODS: [&str; 7] = [
    "server/discover",
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
    "notifications/cancelled",
];
/// The control socket's methods. Task 12 fills it; until then every method is `-32601`.
pub const CONTROL_METHODS: [&str; 0] = [];

/// The lifecycle a request is served under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// 2026-07-28: per-request version in `_meta`.
    Modern,
    /// 2025-11-25 and earlier: after `initialize`.
    Legacy,
}

impl Era {
    /// The name in audit entries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "2026",
            Self::Legacy => "legacy",
        }
    }
}

/// An allowed request.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    /// `server/discover` (2026).
    Discover,
    /// `initialize` (legacy): the version the reply names.
    Initialize {
        /// The negotiated version.
        version: &'static str,
    },
    /// `ping` (legacy).
    Ping,
    /// `tools/list`.
    ToolsList,
    /// `tools/call`.
    ToolsCall {
        /// The tool.
        name: String,
        /// Its arguments (an empty object when absent).
        arguments: Map<String, Value>,
    },
}

/// An allowed notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// `notifications/initialized` on a legacy connection: accepted, nothing to do.
    Initialized,
    /// `notifications/cancelled`.
    Cancelled {
        /// The request it cancels.
        request: Id,
    },
}

/// Why a request or notification was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not on the allowlist (or not a request / notification method).
    MethodNotFound,
    /// On the allowlist, but not in this lifecycle (`ping` in 2026, `server/discover` legacy).
    WrongLifecycle,
    /// No 2026 keys, and the connection did not `initialize`.
    MissingVersion,
    /// One 2026 key without the other, or a key of the wrong type.
    BadMeta,
    /// A 2026 version other than [`MODERN`] (cut to [`MAX_VERSION_BYTES`]).
    UnsupportedVersion(String),
    /// `initialize` on a connection that already did.
    SecondInitialize,
    /// A parameter that is missing, unknown or of the wrong type: its name.
    BadParams(&'static str),
}

impl Refusal {
    /// The JSON-RPC error code.
    #[must_use]
    pub fn code(&self) -> i64 {
        match self {
            Self::MethodNotFound | Self::WrongLifecycle => METHOD_NOT_FOUND,
            Self::MissingVersion | Self::BadMeta | Self::BadParams(_) => INVALID_PARAMS,
            Self::UnsupportedVersion(_) => UNSUPPORTED_VERSION,
            Self::SecondInitialize => INVALID_REQUEST,
        }
    }

    /// The stable reason code (audit entry and `data.reason`).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::MethodNotFound => "method-not-found",
            Self::WrongLifecycle => "wrong-lifecycle",
            Self::MissingVersion => "missing-protocol-version",
            Self::BadMeta => "bad-meta",
            Self::UnsupportedVersion(_) => "unsupported-protocol-version",
            Self::SecondInitialize => "second-initialize",
            Self::BadParams(_) => "bad-params",
        }
    }

    /// The error object of the reply.
    #[must_use]
    pub fn error(&self) -> Value {
        let data = match self {
            Self::UnsupportedVersion(requested) => json!({
                "reason": self.reason(),
                "supported": supported(),
                "requested": requested,
            }),
            Self::BadParams(field) => json!({"reason": self.reason(), "field": field}),
            _ => json!({"reason": self.reason()}),
        };
        json!({"code": self.code(), "message": self.message(), "data": data})
    }

    fn message(&self) -> &'static str {
        match self {
            Self::MethodNotFound | Self::WrongLifecycle => "Method not found",
            Self::MissingVersion | Self::BadMeta | Self::BadParams(_) => "Invalid params",
            Self::UnsupportedVersion(_) => "Unsupported protocol version",
            Self::SecondInitialize => "Invalid Request",
        }
    }
}

/// Every version served, newest first.
#[must_use]
pub fn supported() -> Vec<&'static str> {
    std::iter::once(MODERN).chain(LEGACY).collect()
}

/// Classifies a request. `legacy` says whether this connection completed `initialize`.
///
/// # Errors
/// [`Refusal`] for anything not served.
pub fn classify(
    method: &str,
    params: &Map<String, Value>,
    legacy: bool,
) -> Result<(Era, Call), Refusal> {
    match method {
        "server/discover" | "ping" | "tools/list" | "tools/call" => {}
        "initialize" => return initialize(params, legacy).map(|c| (Era::Legacy, c)),
        _ => return Err(Refusal::MethodNotFound),
    }
    let era = era(params, legacy)?;
    let call = match (era, method) {
        (Era::Modern, "server/discover") | (Era::Legacy, "ping") => {
            only(params, &["_meta"])?;
            if era == Era::Modern {
                Call::Discover
            } else {
                Call::Ping
            }
        }
        (_, "tools/list") => {
            if params.contains_key("cursor") {
                // No cursor is ever issued: every one is invalid.
                return Err(Refusal::BadParams("cursor"));
            }
            only(params, &["_meta"])?;
            Call::ToolsList
        }
        (_, "tools/call") => tools_call(params)?,
        _ => return Err(Refusal::WrongLifecycle),
    };
    Ok((era, call))
}

/// Classifies a notification.
///
/// # Errors
/// [`Refusal`] for anything not accepted.
pub fn classify_note(
    method: &str,
    params: &Map<String, Value>,
    legacy: bool,
) -> Result<Note, Refusal> {
    match method {
        "notifications/initialized" if legacy => Ok(Note::Initialized),
        "notifications/initialized" => Err(Refusal::WrongLifecycle),
        "notifications/cancelled" => {
            only(params, &["_meta", "requestId", "reason"])?;
            let request = match params.get("requestId") {
                Some(Value::Number(n)) => n.as_i64().map(Id::Num),
                Some(Value::String(s)) if s.len() <= MAX_ID_BYTES => Some(Id::Str(s.clone())),
                _ => None,
            };
            if params.get("reason").is_some_and(|r| !r.is_string()) {
                return Err(Refusal::BadParams("reason"));
            }
            request
                .map(|request| Note::Cancelled { request })
                .ok_or(Refusal::BadParams("requestId"))
        }
        _ => Err(Refusal::MethodNotFound),
    }
}

/// The lifecycle of a non-`initialize` request.
fn era(params: &Map<String, Value>, legacy: bool) -> Result<Era, Refusal> {
    let meta = match params.get("_meta") {
        None => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => return Err(Refusal::BadParams("_meta")),
    };
    let version = meta.and_then(|m| m.get(META_VERSION));
    let capabilities = meta.and_then(|m| m.get(META_CAPABILITIES));
    match (version, capabilities) {
        (None, None) if legacy => Ok(Era::Legacy),
        (None, None) => Err(Refusal::MissingVersion),
        (Some(Value::String(v)), Some(Value::Object(_))) if v == MODERN => Ok(Era::Modern),
        (Some(Value::String(v)), Some(Value::Object(_))) => {
            Err(Refusal::UnsupportedVersion(cut(v, MAX_VERSION_BYTES)))
        }
        _ => Err(Refusal::BadMeta),
    }
}

/// `initialize`: `protocolVersion` (string), `capabilities` (object), optional `clientInfo`
/// (object) and `_meta`.
fn initialize(params: &Map<String, Value>, legacy: bool) -> Result<Call, Refusal> {
    if legacy {
        return Err(Refusal::SecondInitialize);
    }
    only(
        params,
        &["_meta", "protocolVersion", "capabilities", "clientInfo"],
    )?;
    let Some(requested) = params.get("protocolVersion").and_then(Value::as_str) else {
        return Err(Refusal::BadParams("protocolVersion"));
    };
    if !params.get("capabilities").is_some_and(Value::is_object) {
        return Err(Refusal::BadParams("capabilities"));
    }
    if params.get("clientInfo").is_some_and(|c| !c.is_object()) {
        return Err(Refusal::BadParams("clientInfo"));
    }
    Ok(Call::Initialize {
        version: negotiate(requested),
    })
}

/// The legacy version the reply names: the client's if served, else the newest.
#[must_use]
pub fn negotiate(requested: &str) -> &'static str {
    LEGACY
        .into_iter()
        .find(|v| *v == requested)
        .unwrap_or(NEWEST_LEGACY)
}

/// `tools/call`: `name` (1–[`MAX_TOOL_NAME`] bytes), optional `arguments` (object), `_meta`.
fn tools_call(params: &Map<String, Value>) -> Result<Call, Refusal> {
    only(params, &["_meta", "name", "arguments"])?;
    let name = match params.get("name") {
        Some(Value::String(n)) if (1..=MAX_TOOL_NAME).contains(&n.len()) => n.clone(),
        _ => return Err(Refusal::BadParams("name")),
    };
    let arguments = match params.get("arguments") {
        None => Map::new(),
        Some(Value::Object(a)) => a.clone(),
        Some(_) => return Err(Refusal::BadParams("arguments")),
    };
    Ok(Call::ToolsCall { name, arguments })
}

/// Every member of `params` is in `allowed`.
fn only(params: &Map<String, Value>, allowed: &[&str]) -> Result<(), Refusal> {
    if params.keys().any(|k| !allowed.contains(&k.as_str())) {
        Err(Refusal::BadParams("unknown"))
    } else {
        Ok(())
    }
}

/// At most `max` bytes of `s`, cut on a character boundary.
fn cut(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_owned()
}

/// A built-in tool as `tools/list` describes it. Names and descriptions are static strings
/// compiled into the broker (AMENDMENTS-01 §3.1): never manifest or user text.
#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    /// Its name on the wire.
    pub name: &'static str,
    /// Its description.
    pub description: &'static str,
    /// Its argument schema (a JSON Schema object).
    pub input_schema: Value,
}

/// What a tool call returned: one text block, and whether it is an error (`denied: <code>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutcome {
    /// `isError`.
    pub is_error: bool,
    /// The text.
    pub text: String,
}

/// The `server/discover` result (2026).
#[must_use]
pub fn discover_result() -> Value {
    json!({
        "resultType": "complete",
        "supportedVersions": supported(),
        "capabilities": {"tools": {}},
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": {META_SERVER_INFO: server_info()},
    })
}

/// The `initialize` result (legacy).
#[must_use]
pub fn initialize_result(version: &str) -> Value {
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {}},
        "serverInfo": server_info(),
    })
}

/// The `ping` result (legacy).
#[must_use]
pub fn ping_result() -> Value {
    json!({})
}

/// The `tools/list` result.
#[must_use]
pub fn tools_list_result(era: Era, tools: &[Tool]) -> Value {
    let list: Vec<Value> = tools
        .iter()
        .map(|t| json!({"name": t.name, "description": t.description, "inputSchema": t.input_schema}))
        .collect();
    match era {
        Era::Modern => json!({
            "resultType": "complete",
            "tools": list,
            "ttlMs": 0,
            "cacheScope": "private",
        }),
        Era::Legacy => json!({"tools": list}),
    }
}

/// The `tools/call` result.
#[must_use]
pub fn tools_call_result(era: Era, out: &ToolOutcome) -> Value {
    let mut r = json!({
        "content": [{"type": "text", "text": out.text}],
        "isError": out.is_error,
    });
    if let (Era::Modern, Some(o)) = (era, r.as_object_mut()) {
        o.insert("resultType".into(), Value::from("complete"));
    }
    r
}

fn server_info() -> Value {
    json!({"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")})
}

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
