#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::{Map, Value, json};

use super::*;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn the_codes_and_limits_are_the_ruled_values() {
    assert_eq!((SERVER_LIMIT, UNSUPPORTED_VERSION), (-32000, -32022));
    assert_eq!((MAX_TOOL_NAME, MAX_VERSION_BYTES), (128, 64));
}

fn modern() -> Value {
    json!({META_VERSION: MODERN, META_CAPABILITIES: {}})
}

fn with_meta(mut p: Value) -> Map<String, Value> {
    p["_meta"] = modern();
    obj(p)
}

fn init(version: &str) -> Map<String, Value> {
    obj(
        json!({"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}),
    )
}

#[test]
fn modern_requests_classify_with_their_meta() {
    let p = with_meta(json!({}));
    assert_eq!(
        classify("server/discover", &p, false),
        Ok((Era::Modern, Call::Discover))
    );
    assert_eq!(
        classify("tools/list", &p, false),
        Ok((Era::Modern, Call::ToolsList))
    );
    // The 2026 keys win on a legacy connection too.
    assert_eq!(
        classify("tools/list", &p, true),
        Ok((Era::Modern, Call::ToolsList))
    );
    let p = with_meta(json!({"name": "fs_read", "arguments": {"path": "a"}}));
    assert_eq!(
        classify("tools/call", &p, false),
        Ok((
            Era::Modern,
            Call::ToolsCall {
                name: "fs_read".into(),
                arguments: obj(json!({"path": "a"}))
            }
        ))
    );
}

#[test]
fn a_request_without_meta_needs_a_legacy_connection() {
    let p = Map::new();
    assert_eq!(
        classify("tools/list", &p, false),
        Err(Refusal::MissingVersion)
    );
    assert_eq!(
        classify("tools/list", &p, true),
        Ok((Era::Legacy, Call::ToolsList))
    );
    // `_meta` without the 2026 keys (a progress token) is still legacy.
    let p = obj(json!({"_meta": {"progressToken": 1}}));
    assert_eq!(
        classify("tools/list", &p, false),
        Err(Refusal::MissingVersion)
    );
    assert_eq!(
        classify("tools/list", &p, true),
        Ok((Era::Legacy, Call::ToolsList))
    );
    assert_eq!(Refusal::MissingVersion.code(), INVALID_PARAMS);
}

#[test]
fn partial_or_mistyped_meta_never_falls_back_to_legacy() {
    for meta in [
        json!({META_VERSION: MODERN}),
        json!({META_CAPABILITIES: {}}),
        json!({META_VERSION: 2026, META_CAPABILITIES: {}}),
        json!({META_VERSION: MODERN, META_CAPABILITIES: []}),
        json!({META_VERSION: null, META_CAPABILITIES: {}}),
    ] {
        let p = obj(json!({ "_meta": meta }));
        assert_eq!(
            classify("tools/list", &p, true),
            Err(Refusal::BadMeta),
            "{p:?}"
        );
    }
    let p = obj(json!({"_meta": "x"}));
    assert_eq!(
        classify("tools/list", &p, true),
        Err(Refusal::BadParams("_meta"))
    );
    assert_eq!(Refusal::BadMeta.code(), INVALID_PARAMS);
}

#[test]
fn an_unsupported_modern_version_names_the_supported_ones() {
    let p = obj(json!({"_meta": {META_VERSION: "1900-01-01", META_CAPABILITIES: {}}}));
    let r = classify("tools/list", &p, false).unwrap_err();
    assert_eq!(r, Refusal::UnsupportedVersion("1900-01-01".into()));
    let e = r.error();
    assert_eq!(e["code"], json!(-32022));
    assert_eq!(e["message"], json!("Unsupported protocol version"));
    assert_eq!(
        e["data"],
        json!({
            "reason": "unsupported-protocol-version",
            "supported": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"],
            "requested": "1900-01-01"
        })
    );
    // A legacy version in the 2026 keys is not 2026.
    let p = obj(json!({"_meta": {META_VERSION: "2025-11-25", META_CAPABILITIES: {}}}));
    assert!(matches!(
        classify("tools/list", &p, false),
        Err(Refusal::UnsupportedVersion(_))
    ));
}

#[test]
fn a_long_requested_version_is_cut_on_a_character_boundary() {
    let long = format!("{}é", "v".repeat(MAX_VERSION_BYTES - 1));
    let p = obj(json!({"_meta": {META_VERSION: long, META_CAPABILITIES: {}}}));
    let Err(Refusal::UnsupportedVersion(v)) = classify("tools/list", &p, false) else {
        panic!("not refused");
    };
    assert_eq!(v, "v".repeat(MAX_VERSION_BYTES - 1));
    let exact = "v".repeat(MAX_VERSION_BYTES + 5);
    let p = obj(json!({"_meta": {META_VERSION: exact, META_CAPABILITIES: {}}}));
    let Err(Refusal::UnsupportedVersion(v)) = classify("tools/list", &p, false) else {
        panic!("not refused");
    };
    assert_eq!(v.len(), MAX_VERSION_BYTES);
}

#[test]
fn each_legacy_version_is_echoed() {
    for v in LEGACY {
        assert_eq!(
            classify("initialize", &init(v), false),
            Ok((Era::Legacy, Call::Initialize { version: v }))
        );
        assert_eq!(initialize_result(v)["protocolVersion"], json!(v));
    }
}

#[test]
fn version_2025_11_25_initializes_and_lists() {
    legacy_lists("2025-11-25");
}

#[test]
fn version_2025_06_18_initializes_and_lists() {
    legacy_lists("2025-06-18");
}

#[test]
fn version_2025_03_26_initializes_and_lists() {
    legacy_lists("2025-03-26");
}

fn legacy_lists(v: &str) {
    let (era, call) = classify("initialize", &init(v), false).unwrap();
    assert_eq!(
        call,
        Call::Initialize {
            version: negotiate(v)
        }
    );
    assert_eq!(negotiate(v), v);
    assert_eq!(
        classify("tools/list", &Map::new(), true),
        Ok((Era::Legacy, Call::ToolsList))
    );
    assert_eq!(era, Era::Legacy);
}

#[test]
fn an_unknown_legacy_version_gets_the_newest() {
    for v in ["2024-11-05", "1.0.0", "", "2026-07-28"] {
        assert_eq!(
            classify("initialize", &init(v), false),
            Ok((
                Era::Legacy,
                Call::Initialize {
                    version: NEWEST_LEGACY
                }
            ))
        );
    }
    assert_eq!(LEGACY[0], NEWEST_LEGACY);
}

#[test]
fn a_second_initialize_is_an_invalid_request() {
    assert_eq!(
        classify("initialize", &init("2025-11-25"), true),
        Err(Refusal::SecondInitialize)
    );
    assert_eq!(Refusal::SecondInitialize.code(), INVALID_REQUEST);
}

#[test]
fn initialize_params_are_checked() {
    let bad = |p: Value| classify("initialize", &obj(p), false).unwrap_err();
    assert_eq!(
        bad(json!({"capabilities": {}})),
        Refusal::BadParams("protocolVersion")
    );
    assert_eq!(
        bad(json!({"protocolVersion": 1, "capabilities": {}})),
        Refusal::BadParams("protocolVersion")
    );
    assert_eq!(
        bad(json!({"protocolVersion": "2025-11-25"})),
        Refusal::BadParams("capabilities")
    );
    assert_eq!(
        bad(json!({"protocolVersion": "2025-11-25", "capabilities": []})),
        Refusal::BadParams("capabilities")
    );
    assert_eq!(
        bad(json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": "c"})),
        Refusal::BadParams("clientInfo")
    );
    assert_eq!(
        bad(json!({"protocolVersion": "2025-11-25", "capabilities": {}, "x": 1})),
        Refusal::BadParams("unknown")
    );
    // clientInfo is optional; _meta is allowed.
    let ok = obj(json!({"protocolVersion": "2025-11-25", "capabilities": {}, "_meta": {}}));
    assert!(classify("initialize", &ok, false).is_ok());
}

#[test]
fn methods_outside_a_lifecycle_are_not_found() {
    // ping is gone in 2026; server/discover does not exist in the legacy lifecycle.
    assert_eq!(
        classify("ping", &with_meta(json!({})), false),
        Err(Refusal::WrongLifecycle)
    );
    assert_eq!(
        classify("server/discover", &Map::new(), true),
        Err(Refusal::WrongLifecycle)
    );
    assert_eq!(
        classify("ping", &Map::new(), true),
        Ok((Era::Legacy, Call::Ping))
    );
    assert_eq!(Refusal::WrongLifecycle.code(), METHOD_NOT_FOUND);
}

#[test]
fn methods_off_the_allowlist_are_not_found() {
    for m in [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
        "roots/list",
        "logging/setLevel",
        "completion/complete",
        "subscriptions/listen",
        "tasks/list",
        "secrets.set",
        "sessions.create",
        "infer.load",
        "approvals.decide",
        "manifests.save",
        "audit.note",
        "notifications/initialized",
        "notifications/cancelled",
        "",
        "tools/list ",
        "Tools/list",
    ] {
        assert_eq!(
            classify(m, &with_meta(json!({})), true),
            Err(Refusal::MethodNotFound),
            "{m}"
        );
    }
    assert_eq!(Refusal::MethodNotFound.code(), METHOD_NOT_FOUND);
}

#[test]
fn no_control_method_resolves_on_the_session_table() {
    // Architect Q1: two tables, never shared. The control table's own names, and every method
    // the control socket will ever serve (ARCHITECTURE §4.1 families), miss the session table.
    for m in CONTROL_METHODS {
        assert!(!SESSION_METHODS.contains(&m));
    }
    let families = [
        "doctor.",
        "manifests.",
        "models.",
        "hf.",
        "jobs.",
        "infer.",
        "chat.",
        "sessions.",
        "ui.",
        "approvals.",
        "secrets.",
        "audit.",
    ];
    for m in SESSION_METHODS {
        assert!(!families.iter().any(|f| m.starts_with(f)), "{m}");
    }
}

#[test]
fn tools_list_refuses_cursors_and_unknown_params() {
    let p = with_meta(json!({"cursor": "c"}));
    assert_eq!(
        classify("tools/list", &p, false),
        Err(Refusal::BadParams("cursor"))
    );
    let p = with_meta(json!({"x": 1}));
    assert_eq!(
        classify("tools/list", &p, false),
        Err(Refusal::BadParams("unknown"))
    );
    let p = with_meta(json!({"x": 1}));
    assert_eq!(
        classify("server/discover", &p, false),
        Err(Refusal::BadParams("unknown"))
    );
    assert_eq!(
        classify("ping", &obj(json!({"x": 1})), true),
        Err(Refusal::BadParams("unknown"))
    );
}

#[test]
fn tools_call_params_are_checked() {
    let call = |p: Value| classify("tools/call", &with_meta(p), false);
    assert!(call(json!({"name": "n".repeat(MAX_TOOL_NAME)})).is_ok());
    assert_eq!(call(json!({"name": ""})), Err(Refusal::BadParams("name")));
    assert_eq!(
        call(json!({"name": "n".repeat(MAX_TOOL_NAME + 1)})),
        Err(Refusal::BadParams("name"))
    );
    assert_eq!(call(json!({})), Err(Refusal::BadParams("name")));
    assert_eq!(call(json!({"name": 1})), Err(Refusal::BadParams("name")));
    assert_eq!(
        call(json!({"name": "a", "arguments": []})),
        Err(Refusal::BadParams("arguments"))
    );
    assert_eq!(
        call(json!({"name": "a", "arguments": "{}"})),
        Err(Refusal::BadParams("arguments"))
    );
    // MRTR retry members are not served (the broker never sends input_required).
    assert_eq!(
        call(json!({"name": "a", "requestState": "s"})),
        Err(Refusal::BadParams("unknown"))
    );
    let (_, c) = call(json!({"name": "a"})).unwrap();
    assert_eq!(
        c,
        Call::ToolsCall {
            name: "a".into(),
            arguments: Map::new()
        }
    );
}

#[test]
fn notifications_classify_per_lifecycle() {
    let none = Map::new();
    assert_eq!(
        classify_note("notifications/initialized", &none, true),
        Ok(Note::Initialized)
    );
    assert_eq!(
        classify_note("notifications/initialized", &none, false),
        Err(Refusal::WrongLifecycle)
    );
    for legacy in [false, true] {
        let p = obj(json!({"requestId": 4, "reason": "user"}));
        assert_eq!(
            classify_note("notifications/cancelled", &p, legacy),
            Ok(Note::Cancelled {
                request: Id::Num(4)
            })
        );
        let p = obj(json!({"requestId": "a", "_meta": {}}));
        assert_eq!(
            classify_note("notifications/cancelled", &p, legacy),
            Ok(Note::Cancelled {
                request: Id::Str("a".into())
            })
        );
    }
    for m in [
        "notifications/roots/list_changed",
        "notifications/progress",
        "tools/list",
        "",
    ] {
        assert_eq!(
            classify_note(m, &none, true),
            Err(Refusal::MethodNotFound),
            "{m}"
        );
    }
}

#[test]
fn cancel_params_are_checked() {
    let note = |p: Value| classify_note("notifications/cancelled", &obj(p), false);
    let long = "i".repeat(MAX_ID_BYTES + 1);
    for bad in [
        json!({}),
        json!({"requestId": null}),
        json!({"requestId": 1.5}),
        json!({"requestId": long}),
    ] {
        assert_eq!(
            note(bad.clone()),
            Err(Refusal::BadParams("requestId")),
            "{bad}"
        );
    }
    assert!(note(json!({"requestId": "i".repeat(MAX_ID_BYTES)})).is_ok());
    assert_eq!(
        note(json!({"requestId": 1, "reason": 2})),
        Err(Refusal::BadParams("reason"))
    );
    assert_eq!(
        note(json!({"requestId": 1, "x": 2})),
        Err(Refusal::BadParams("unknown"))
    );
}

#[test]
fn modern_results_carry_result_type_and_cache_fields() {
    let tools = [Tool {
        name: "fs_read",
        description: "Read a file.",
        input_schema: json!({"type": "object"}),
    }];
    assert_eq!(
        tools_list_result(Era::Modern, &tools),
        json!({
            "resultType": "complete",
            "tools": [{"name": "fs_read", "description": "Read a file.", "inputSchema": {"type": "object"}}],
            "ttlMs": 0,
            "cacheScope": "private"
        })
    );
    let out = ToolOutcome {
        is_error: true,
        text: "denied: tool_not_granted".into(),
    };
    assert_eq!(
        tools_call_result(Era::Modern, &out),
        json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "denied: tool_not_granted"}],
            "isError": true
        })
    );
    let d = discover_result();
    assert_eq!(d["resultType"], json!("complete"));
    assert_eq!(d["supportedVersions"], json!(supported()));
    assert_eq!(d["capabilities"], json!({"tools": {}}));
    assert_eq!(
        (d["ttlMs"].clone(), d["cacheScope"].clone()),
        (json!(0), json!("private"))
    );
    assert_eq!(d["_meta"][META_SERVER_INFO]["name"], json!(SERVER_NAME));
}

#[test]
fn legacy_results_have_only_their_schema_fields() {
    let tools = [Tool {
        name: "a",
        description: "b",
        input_schema: json!({}),
    }];
    assert_eq!(
        tools_list_result(Era::Legacy, &tools),
        json!({"tools": [{"name": "a", "description": "b", "inputSchema": {}}]})
    );
    let out = ToolOutcome {
        is_error: false,
        text: "ok".into(),
    };
    assert_eq!(
        tools_call_result(Era::Legacy, &out),
        json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
    );
    let i = initialize_result("2025-06-18");
    assert_eq!(
        i,
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")}
        })
    );
    assert_eq!(ping_result(), json!({}));
}

#[test]
fn refusals_have_stable_codes_and_messages() {
    let all = [
        (
            Refusal::MethodNotFound,
            -32601,
            "method-not-found",
            "Method not found",
        ),
        (
            Refusal::WrongLifecycle,
            -32601,
            "wrong-lifecycle",
            "Method not found",
        ),
        (
            Refusal::MissingVersion,
            -32602,
            "missing-protocol-version",
            "Invalid params",
        ),
        (Refusal::BadMeta, -32602, "bad-meta", "Invalid params"),
        (
            Refusal::UnsupportedVersion("x".into()),
            -32022,
            "unsupported-protocol-version",
            "Unsupported protocol version",
        ),
        (
            Refusal::SecondInitialize,
            -32600,
            "second-initialize",
            "Invalid Request",
        ),
        (
            Refusal::BadParams("name"),
            -32602,
            "bad-params",
            "Invalid params",
        ),
    ];
    for (r, code, reason, message) in all {
        let e = r.error();
        assert_eq!((r.code(), r.reason()), (code, reason));
        assert_eq!(
            (e["code"].clone(), e["message"].clone()),
            (json!(code), json!(message))
        );
        assert_eq!(e["data"]["reason"], json!(reason));
    }
    assert_eq!(
        Refusal::BadParams("name").error()["data"]["field"],
        json!("name")
    );
    assert_eq!(Era::Modern.as_str(), "2026");
    assert_eq!(Era::Legacy.as_str(), "legacy");
}
