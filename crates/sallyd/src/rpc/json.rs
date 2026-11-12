//! Strict JSON for untrusted peers: `serde_json` keeps the last of two equal keys, so a peer
//! could show one value to a reader and another to the broker. This parse refuses an object
//! that repeats a key, at any depth (architect ruling Q11, Task 7). Depth is bounded by the
//! caller before this runs.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Parses `bytes` as one JSON value, refusing duplicate keys.
///
/// # Errors
/// The parse error (malformed JSON, trailing bytes, or a repeated key).
pub fn parse(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(v) = de::Deserialize::deserialize(&mut de)?;
    de.end()?;
    Ok(v)
}

/// A [`Value`] that refused duplicate keys while it was built.
struct Strict(Value);

impl<'de> de::Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without repeated keys")
    }

    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        Number::from_f64(n)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_owned()))
    }

    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom("repeated key"));
            }
            let Strict(v) = map.next_value()?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    /// What the visitor says it expects, as serde shows it in an error.
    struct Expecting;

    impl fmt::Display for Expecting {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            StrictVisitor.expecting(f)
        }
    }

    #[test]
    fn the_visitor_names_what_it_expects_and_takes_owned_strings() {
        assert_eq!(Expecting.to_string(), "JSON without repeated keys");
        // serde_json hands a slice's strings over borrowed; an owned one is kept as is.
        let v = StrictVisitor.visit_string::<serde_json::Error>("owned".to_owned());
        assert_eq!(v.unwrap(), json!("owned"));
    }

    #[test]
    fn values_parse_like_serde_json() {
        let text = r#"{"a":[1,-2,3.5,"s",true,false,null,{"b":{}}],"c":18446744073709551615}"#;
        assert_eq!(
            parse(text.as_bytes()).unwrap(),
            serde_json::from_str::<Value>(text).unwrap()
        );
        assert_eq!(parse(b" 3 ").unwrap(), json!(3));
    }

    #[test]
    fn a_repeated_key_is_refused_at_any_depth() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(br#"{"x":[{"a":1,"b":{"c":1,"c":1}}]}"#).is_err());
        // Escapes that spell the same key are the same key.
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(br#"{"a":1,"A":2}"#).is_ok());
    }

    #[test]
    fn trailing_bytes_and_bad_utf8_are_refused() {
        assert!(parse(b"{} {}").is_err());
        assert!(parse(b"\"\xff\"").is_err());
        assert!(parse(b"").is_err());
    }
}
