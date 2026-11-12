#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::{Value, json};

use super::*;

#[test]
fn the_body_cap_is_4_mib() {
    assert_eq!(MAX_BODY, 4_194_304);
}

const CONTEXT: u64 = 8192;

fn base() -> Value {
    json!({"messages": [{"role": "user", "content": "hi"}]})
}

fn with(key: &str, v: Value) -> Value {
    let mut b = base();
    b[key] = v;
    b
}

fn run(v: &Value) -> Result<Chat, Refusal> {
    check(&serde_json::to_vec(v).unwrap(), CONTEXT)
}

fn denied(v: &Value) -> (Reason, String) {
    let r = run(v).unwrap_err();
    (r.reason, r.field)
}

fn deny(v: &Value, reason: Reason, field: &str) {
    assert_eq!(denied(v), (reason, field.to_owned()), "{v}");
}

fn msg(m: Value) -> Value {
    json!({ "messages": [m] })
}

#[test]
fn a_minimal_body_passes() {
    let c = run(&base()).unwrap();
    assert_eq!(c.messages, 1);
    assert!(!c.stream);
    // No limit requested: the session's context is the explicit bound (ruling Q2).
    assert_eq!(c.max_tokens, CONTEXT);
    assert_eq!(Value::Object(c.body), base());
}

#[test]
fn every_allowlisted_member_passes_together() {
    let v = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "developer", "content": [{"type": "text", "text": "d"}]},
            {"role": "user", "content": "u", "name": "alice"},
            {"role": "assistant", "content": null, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "fs_read", "arguments": "{}"}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "out"}
        ],
        "tools": [{"type": "function", "function": {
            "name": "fs_read", "description": "d", "parameters": {"type": "object"}, "strict": true
        }}],
        "tool_choice": {"type": "function", "function": {"name": "fs_read"}},
        "parallel_tool_calls": false,
        "temperature": 0.7,
        "top_p": 1,
        "max_tokens": 100,
        "stop": ["a", "b"],
        "seed": -3,
        "stream": true,
        "stream_options": {"include_usage": true},
        "response_format": {"type": "json_schema", "json_schema": {"name": "x"}},
        "presence_penalty": -2,
        "frequency_penalty": 2,
        "n": 1
    });
    let c = run(&v).unwrap();
    assert!(c.stream);
    assert_eq!(c.max_tokens, 100);
    assert_eq!(c.messages, 5);
    assert!(!c.body.contains_key("model"), "model is dropped");
    // 16 members sent, `model` dropped.
    assert_eq!(c.body.len(), 15);
}

#[test]
fn the_model_member_is_dropped_but_still_checked() {
    let c = run(&with("model", json!("../../etc/passwd"))).unwrap();
    assert!(!c.body.contains_key("model"));
    deny(&with("model", json!(3)), Reason::BadValue, "model");
    deny(&with("model", json!("")), Reason::BadValue, "model");
    let long = "m".repeat(MAX_NAME_BYTES + 1);
    deny(&with("model", json!(long)), Reason::BadValue, "model");
    assert!(run(&with("model", json!("m".repeat(MAX_NAME_BYTES)))).is_ok());
}

#[test]
fn unknown_top_level_members_are_refused() {
    for k in [
        "logit_bias",
        "logprobs",
        "user",
        "functions",
        "audio",
        "modalities",
        "store",
    ] {
        deny(&with(k, json!(1)), Reason::UnknownField, k);
    }
}

#[test]
fn every_top_level_member_is_known() {
    // Each allowlisted member, alone with a valid value, passes.
    let valid = [
        ("tools", json!([])),
        ("tool_choice", json!("auto")),
        ("parallel_tool_calls", json!(true)),
        ("temperature", json!(1)),
        ("top_p", json!(0.5)),
        ("max_tokens", json!(1)),
        ("max_completion_tokens", json!(1)),
        ("stop", json!("x")),
        ("seed", json!(1)),
        ("stream", json!(false)),
        ("stream_options", json!({})),
        ("response_format", json!({"type": "text"})),
        ("presence_penalty", json!(0)),
        ("frequency_penalty", json!(0)),
        ("n", json!(1)),
        ("model", json!("x")),
    ];
    for (k, v) in valid {
        assert!(run(&with(k, v)).is_ok(), "{k}");
    }
}

#[test]
fn n_must_be_one() {
    deny(&with("n", json!(5)), Reason::NotOne, "n");
    deny(&with("n", json!(0)), Reason::NotOne, "n");
    deny(&with("n", json!("1")), Reason::BadValue, "n");
    deny(&with("n", json!(1.5)), Reason::BadValue, "n");
}

#[test]
fn the_token_limit_is_bounded_by_the_context() {
    let c = run(&with("max_tokens", json!(CONTEXT))).unwrap();
    assert_eq!(c.max_tokens, CONTEXT);
    let c = run(&with("max_tokens", json!(1))).unwrap();
    assert_eq!(c.max_tokens, 1);
    let c = run(&with("max_completion_tokens", json!(7))).unwrap();
    assert_eq!(c.max_tokens, 7);
    deny(
        &with("max_tokens", json!(CONTEXT + 1)),
        Reason::TokenLimit,
        "max_tokens",
    );
    deny(
        &with("max_tokens", json!(1_000_000_000u64)),
        Reason::TokenLimit,
        "max_tokens",
    );
    deny(
        &with("max_completion_tokens", json!(CONTEXT + 1)),
        Reason::TokenLimit,
        "max_completion_tokens",
    );
    deny(
        &with("max_tokens", json!(0)),
        Reason::BadValue,
        "max_tokens",
    );
    deny(
        &with("max_tokens", json!(-1)),
        Reason::BadValue,
        "max_tokens",
    );
    deny(
        &with("max_tokens", json!(1.5)),
        Reason::BadValue,
        "max_tokens",
    );
    let mut both = with("max_tokens", json!(1));
    both["max_completion_tokens"] = json!(1);
    deny(&both, Reason::TokenLimit, "max_completion_tokens");
}

#[test]
fn messages_are_required_and_bounded() {
    deny(&json!({}), Reason::Missing, "messages");
    deny(&json!({"messages": []}), Reason::BadValue, "messages");
    deny(&json!({"messages": {}}), Reason::BadValue, "messages");
    let one = json!({"role": "user", "content": "x"});
    let max = json!({ "messages": vec![one.clone(); MAX_MESSAGES] });
    assert_eq!(run(&max).unwrap().messages, MAX_MESSAGES);
    let over = json!({ "messages": vec![one; MAX_MESSAGES + 1] });
    deny(&over, Reason::TooMany, "messages");
}

#[test]
fn message_roles_and_members_are_allowlisted() {
    deny(
        &msg(json!({"content": "x"})),
        Reason::Missing,
        "messages[0].role",
    );
    deny(
        &msg(json!({"role": "root", "content": "x"})),
        Reason::BadValue,
        "messages[0].role",
    );
    deny(
        &msg(json!({"role": 1, "content": "x"})),
        Reason::BadValue,
        "messages[0].role",
    );
    deny(
        &msg(json!({"role": "user", "content": "x", "audio": {}})),
        Reason::UnknownField,
        "messages[0].audio",
    );
    deny(&msg(json!("user")), Reason::BadValue, "messages[0]");
    deny(
        &msg(json!({"role": "user", "name": 3})),
        Reason::BadValue,
        "messages[0].name",
    );
    deny(
        &msg(json!({"role": "tool", "tool_call_id": ""})),
        Reason::BadValue,
        "messages[0].tool_call_id",
    );
    // The path names the right message.
    let v = json!({"messages": [{"role": "user"}, {"role": "x"}]});
    deny(&v, Reason::BadValue, "messages[1].role");
}

#[test]
fn content_is_text_only() {
    let parts = |p: Value| msg(json!({"role": "user", "content": p}));
    assert!(run(&parts(json!([]))).is_ok());
    assert!(
        run(&parts(
            json!([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}])
        ))
        .is_ok()
    );
    for kind in ["image_url", "input_audio", "file", "refusal"] {
        deny(
            &parts(json!([{"type": "text", "text": "a"}, {"type": kind}])),
            Reason::NonTextPart,
            "messages[0].content[1].type",
        );
    }
    deny(
        &parts(json!([{"type": "text", "text": "a", "image_url": "x"}])),
        Reason::UnknownField,
        "messages[0].content[0].image_url",
    );
    deny(
        &parts(json!([{"type": "text"}])),
        Reason::BadValue,
        "messages[0].content[0].text",
    );
    deny(
        &parts(json!([{"text": "a"}])),
        Reason::BadValue,
        "messages[0].content[0].type",
    );
    deny(
        &parts(json!(["a"])),
        Reason::BadValue,
        "messages[0].content[0]",
    );
    deny(&parts(json!(3)), Reason::BadValue, "messages[0].content");
    deny(
        &parts(json!({"type": "text"})),
        Reason::BadValue,
        "messages[0].content",
    );
}

#[test]
fn tool_calls_in_messages_are_checked() {
    let call = |c: Value| msg(json!({"role": "assistant", "tool_calls": [c]}));
    let good = json!({"id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}});
    assert!(run(&call(good.clone())).is_ok());
    let mut bad = good.clone();
    bad["type"] = json!("code");
    deny(
        &call(bad),
        Reason::BadValue,
        "messages[0].tool_calls[0].type",
    );
    let mut bad = good.clone();
    bad["function"]["arguments"] = json!({});
    deny(
        &call(bad),
        Reason::BadValue,
        "messages[0].tool_calls[0].function.arguments",
    );
    let mut bad = good.clone();
    bad["function"]["code"] = json!("x");
    deny(
        &call(bad),
        Reason::UnknownField,
        "messages[0].tool_calls[0].function.code",
    );
    let mut bad = good.clone();
    bad["extra"] = json!(1);
    deny(
        &call(bad),
        Reason::UnknownField,
        "messages[0].tool_calls[0].extra",
    );
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("id");
    deny(&call(bad), Reason::BadValue, "messages[0].tool_calls[0].id");
    let mut bad = good.clone();
    bad["function"]["name"] = json!(null);
    deny(
        &call(bad),
        Reason::BadValue,
        "messages[0].tool_calls[0].function.name",
    );
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("function");
    deny(
        &call(bad),
        Reason::BadValue,
        "messages[0].tool_calls[0].function",
    );
    deny(
        &msg(json!({"role": "assistant", "tool_calls": {}})),
        Reason::BadValue,
        "messages[0].tool_calls",
    );
    let many = msg(json!({"role": "assistant", "tool_calls": vec![good.clone(); MAX_TOOLS]}));
    assert!(run(&many).is_ok());
    let over = msg(json!({"role": "assistant", "tool_calls": vec![good; MAX_TOOLS + 1]}));
    deny(&over, Reason::TooMany, "messages[0].tool_calls");
}

#[test]
fn tools_are_function_definitions() {
    let t = |f: Value| with("tools", json!([{"type": "function", "function": f}]));
    assert!(run(&t(json!({"name": "f"}))).is_ok());
    deny(
        &t(json!({"name": "f", "code": "x"})),
        Reason::UnknownField,
        "tools[0].function.code",
    );
    deny(&t(json!({})), Reason::BadValue, "tools[0].function.name");
    deny(
        &t(json!({"name": "f", "description": 1})),
        Reason::BadValue,
        "tools[0].function.description",
    );
    deny(
        &t(json!({"name": "f", "parameters": []})),
        Reason::BadValue,
        "tools[0].function.parameters",
    );
    deny(
        &t(json!({"name": "f", "strict": "yes"})),
        Reason::BadValue,
        "tools[0].function.strict",
    );
    deny(
        &with(
            "tools",
            json!([{"type": "retrieval", "function": {"name": "f"}}]),
        ),
        Reason::BadValue,
        "tools[0].type",
    );
    deny(
        &with("tools", json!([{"type": "function"}])),
        Reason::BadValue,
        "tools[0].function",
    );
    deny(&with("tools", json!({})), Reason::BadValue, "tools");
    let one = json!({"type": "function", "function": {"name": "f"}});
    assert!(run(&with("tools", json!(vec![one.clone(); MAX_TOOLS]))).is_ok());
    deny(
        &with("tools", json!(vec![one; MAX_TOOLS + 1])),
        Reason::TooMany,
        "tools",
    );
}

#[test]
fn tool_choice_is_a_mode_or_one_function() {
    for m in ["none", "auto", "required"] {
        assert!(run(&with("tool_choice", json!(m))).is_ok(), "{m}");
    }
    deny(
        &with("tool_choice", json!("any")),
        Reason::BadValue,
        "tool_choice",
    );
    deny(
        &with("tool_choice", json!(1)),
        Reason::BadValue,
        "tool_choice",
    );
    deny(
        &with(
            "tool_choice",
            json!({"type": "function", "function": {"name": "f", "x": 1}}),
        ),
        Reason::UnknownField,
        "tool_choice.function.x",
    );
    deny(
        &with(
            "tool_choice",
            json!({"type": "tool", "function": {"name": "f"}}),
        ),
        Reason::BadValue,
        "tool_choice.type",
    );
    deny(
        &with("tool_choice", json!({"type": "function", "function": {}})),
        Reason::BadValue,
        "tool_choice.function.name",
    );
}

#[test]
fn stop_is_bounded() {
    assert!(run(&with("stop", json!(vec!["s"; MAX_STOP]))).is_ok());
    deny(
        &with("stop", json!(vec!["s"; MAX_STOP + 1])),
        Reason::TooMany,
        "stop",
    );
    assert!(run(&with("stop", json!("s".repeat(MAX_STOP_BYTES)))).is_ok());
    deny(
        &with("stop", json!("s".repeat(MAX_STOP_BYTES + 1))),
        Reason::BadValue,
        "stop",
    );
    deny(
        &with("stop", json!(["s".repeat(MAX_STOP_BYTES + 1)])),
        Reason::BadValue,
        "stop",
    );
    deny(&with("stop", json!([1])), Reason::BadValue, "stop");
    deny(&with("stop", json!(1)), Reason::BadValue, "stop");
}

#[test]
fn sampling_numbers_are_in_range() {
    for (k, lo, hi) in [
        ("temperature", 0.0, 2.0),
        ("top_p", 0.0, 1.0),
        ("presence_penalty", -2.0, 2.0),
        ("frequency_penalty", -2.0, 2.0),
    ] {
        assert!(run(&with(k, json!(lo))).is_ok(), "{k} lo");
        assert!(run(&with(k, json!(hi))).is_ok(), "{k} hi");
        deny(&with(k, json!(lo - 0.01)), Reason::BadValue, k);
        deny(&with(k, json!(hi + 0.01)), Reason::BadValue, k);
        deny(&with(k, json!("1")), Reason::BadValue, k);
    }
    deny(&with("seed", json!(1.5)), Reason::BadValue, "seed");
    deny(&with("seed", json!("1")), Reason::BadValue, "seed");
}

#[test]
fn flags_are_booleans() {
    for k in ["stream", "parallel_tool_calls"] {
        deny(&with(k, json!(1)), Reason::BadValue, k);
    }
    deny(
        &with("stream_options", json!({"include_usage": "yes"})),
        Reason::BadValue,
        "stream_options.include_usage",
    );
    deny(
        &with("stream_options", json!({"chunk": 1})),
        Reason::UnknownField,
        "stream_options.chunk",
    );
    deny(
        &with("stream_options", json!(true)),
        Reason::BadValue,
        "stream_options",
    );
}

#[test]
fn response_format_is_one_of_three() {
    for t in ["text", "json_object"] {
        assert!(
            run(&with("response_format", json!({"type": t}))).is_ok(),
            "{t}"
        );
        deny(
            &with("response_format", json!({"type": t, "json_schema": {}})),
            Reason::BadValue,
            "response_format.type",
        );
    }
    deny(
        &with("response_format", json!({"type": "json_schema"})),
        Reason::BadValue,
        "response_format.json_schema",
    );
    deny(
        &with(
            "response_format",
            json!({"type": "json_schema", "json_schema": "x"}),
        ),
        Reason::BadValue,
        "response_format.json_schema",
    );
    deny(
        &with("response_format", json!({"type": "xml"})),
        Reason::BadValue,
        "response_format.type",
    );
    deny(
        &with("response_format", json!({"type": "text", "grammar": "x"})),
        Reason::UnknownField,
        "response_format.grammar",
    );
}

#[test]
fn the_size_limit_is_checked_first() {
    let mut big = vec![b' '; MAX_BODY + 1];
    big[0] = b'{';
    assert_eq!(check(&big, CONTEXT).unwrap_err().reason, Reason::TooLarge);
    // Exactly the limit is parsed (and here refused for its content, not its size).
    let body = serde_json::to_vec(&base()).unwrap();
    let mut exact = body.clone();
    exact.resize(MAX_BODY, b' ');
    assert!(check(&exact, CONTEXT).is_ok());
}

#[test]
fn nesting_is_bounded() {
    let deep = |n: usize| {
        format!(
            r#"{{"messages":[{{"role":"user"}}],"tools":[{{"type":"function","function":{{"name":"f","parameters":{{"a":{}1{}}}}}}}]}}"#,
            "[".repeat(n),
            "]".repeat(n)
        )
    };
    // body, tools, tool, function, parameters: 5 levels before the arrays.
    assert!(check(deep(MAX_DEPTH - 5).as_bytes(), CONTEXT).is_ok());
    assert_eq!(
        check(deep(MAX_DEPTH - 4).as_bytes(), CONTEXT)
            .unwrap_err()
            .reason,
        Reason::TooDeep
    );
}

#[test]
fn non_objects_are_malformed() {
    for b in [&b"[]"[..], b"1", b"", b"{", b"{\"messages\":\"\xff\"}"] {
        assert_eq!(check(b, CONTEXT).unwrap_err().reason, Reason::Malformed);
    }
}

#[test]
fn tool_and_function_names_are_restricted() {
    let t = |n: &str| {
        with(
            "tools",
            json!([{"type": "function", "function": {"name": n}}]),
        )
    };
    for good in ["a", "fs_read", "A-b_9", &"n".repeat(MAX_FUNCTION_NAME)] {
        assert!(run(&t(good)).is_ok(), "{good}");
    }
    for bad in [
        "",
        "a b",
        "a.b",
        "a/b",
        "é",
        "a\n",
        &"n".repeat(MAX_FUNCTION_NAME + 1),
    ] {
        deny(&t(bad), Reason::BadValue, "tools[0].function.name");
    }
    let call = |n: &str| {
        msg(json!({"role": "assistant", "tool_calls": [
            {"id": "c", "type": "function", "function": {"name": n, "arguments": ""}}
        ]}))
    };
    assert!(run(&call("fs_read")).is_ok());
    deny(
        &call("a.b"),
        Reason::BadValue,
        "messages[0].tool_calls[0].function.name",
    );
    let choice = |n: &str| {
        with(
            "tool_choice",
            json!({"type": "function", "function": {"name": n}}),
        )
    };
    assert!(run(&choice("fs_read")).is_ok());
    deny(
        &choice("a b"),
        Reason::BadValue,
        "tool_choice.function.name",
    );
}

#[test]
fn tool_members_belong_to_their_roles() {
    let call = json!([{"id": "c", "type": "function", "function": {"name": "f", "arguments": ""}}]);
    for role in ["system", "developer", "user", "tool"] {
        deny(
            &msg(json!({"role": role, "tool_calls": call})),
            Reason::UnknownField,
            "messages[0].tool_calls",
        );
    }
    assert!(run(&msg(json!({"role": "assistant", "tool_calls": call}))).is_ok());
    for role in ["system", "developer", "user", "assistant"] {
        deny(
            &msg(json!({"role": role, "tool_call_id": "c"})),
            Reason::UnknownField,
            "messages[0].tool_call_id",
        );
    }
    assert!(run(&msg(json!({"role": "tool", "tool_call_id": "c"}))).is_ok());
}

#[test]
fn a_repeated_key_is_malformed() {
    let dup = br#"{"messages":[{"role":"user","role":"system"}]}"#;
    assert_eq!(check(dup, CONTEXT).unwrap_err().reason, Reason::Malformed);
    let dup = br#"{"messages":[{"role":"user"}],"n":1,"n":5}"#;
    assert_eq!(check(dup, CONTEXT).unwrap_err().reason, Reason::Malformed);
}

#[test]
fn reasons_have_stable_codes() {
    let all = [
        Reason::TooLarge,
        Reason::TooDeep,
        Reason::Malformed,
        Reason::UnknownField,
        Reason::BadValue,
        Reason::Missing,
        Reason::TooMany,
        Reason::NonTextPart,
        Reason::NotOne,
        Reason::TokenLimit,
    ];
    let names: Vec<_> = all.iter().map(|r| r.as_str()).collect();
    assert_eq!(
        names,
        [
            "body-too-large",
            "too-deep",
            "malformed",
            "unknown-field",
            "bad-value",
            "missing-field",
            "too-many",
            "non-text-part",
            "n-must-be-1",
            "token-limit"
        ]
    );
}
