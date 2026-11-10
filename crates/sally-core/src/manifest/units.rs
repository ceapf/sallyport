//! Human-readable unit types used in manifests: byte sizes (`8GiB`), durations (`2h`), and
//! GPU layer counts (`auto` or an integer).
//!
//! Each type has exactly one canonical text form, so a parsed manifest serializes back to text
//! that parses to an identical value (RT-MAN-01 round-trip).
#![deny(clippy::indexing_slicing)]

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest digit run accepted in a unit string; `u64::MAX` has 20 digits.
const MAX_DIGITS: usize = 20;

/// Splits `"123GiB"` into `(123, "GiB")`. Rejects empty digit runs, leading `+`/`-`, and
/// overlong numbers before doing any arithmetic.
fn split_number(s: &str) -> Option<(u64, &str)> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > MAX_DIGITS {
        return None;
    }
    let (num, unit) = (s.get(..digits)?, s.get(digits..)?);
    Some((num.parse().ok()?, unit))
}

/// A size in bytes, written as `<n><unit>` with unit `B`, `KiB`, `MiB`, `GiB`, or `TiB`.
///
/// Decimal units (`KB`, `GB`) are refused to avoid a silent 7% discrepancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

const BYTE_UNITS: [(&str, u64); 5] = [
    ("TiB", 1 << 40),
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
    ("B", 1),
];

impl ByteSize {
    /// One kibibyte.
    pub const KIB: u64 = 1 << 10;
    /// One mebibyte.
    pub const MIB: u64 = 1 << 20;
    /// One gibibyte.
    pub const GIB: u64 = 1 << 30;

    /// A size of exactly `bytes` bytes.
    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// The size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Parses the canonical text form, e.g. `"8GiB"`. Returns `None` on any malformed input or
    /// overflow.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (n, unit) = split_number(s)?;
        let (_, mult) = BYTE_UNITS.iter().find(|(u, _)| *u == unit)?;
        n.checked_mul(*mult).map(Self)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Largest unit that divides exactly; zero prints as "0B".
        for (unit, mult) in BYTE_UNITS {
            if self.0 != 0 && self.0.is_multiple_of(mult) {
                return write!(f, "{}{unit}", self.0 / mult);
            }
        }
        write!(f, "{}B", self.0)
    }
}

/// A wall-clock duration with whole-second resolution, written as `<n>s`, `<n>m`, or `<n>h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u64);

const TIME_UNITS: [(&str, u64); 3] = [("h", 3600), ("m", 60), ("s", 1)];

impl Duration {
    /// A duration of `secs` seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// The duration in seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Parses the canonical text form, e.g. `"90s"` or `"2h"`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (n, unit) = split_number(s)?;
        let (_, mult) = TIME_UNITS.iter().find(|(u, _)| *u == unit)?;
        n.checked_mul(*mult).map(Self)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (unit, mult) in TIME_UNITS {
            if self.0 != 0 && self.0.is_multiple_of(mult) {
                return write!(f, "{}{unit}", self.0 / mult);
            }
        }
        write!(f, "{}s", self.0)
    }
}

/// A CPU quota stored as exact millicores, written as a YAML number (`2`, `0.5`, `1.25`).
///
/// Integer storage makes the manifest `Eq` and the round-trip exact; NaN and infinities cannot
/// be represented. At most three decimal places are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cpus(u32);

impl Cpus {
    /// `n` thousandths of a CPU.
    #[must_use]
    pub const fn from_millis(n: u32) -> Self {
        Self(n)
    }

    /// Thousandths of a CPU.
    #[must_use]
    pub const fn millis(self) -> u32 {
        self.0
    }

    fn from_f64(v: f64) -> Option<Self> {
        let scaled = v * 1000.0;
        let rounded = scaled.round();
        if !scaled.is_finite() || scaled < 0.0 || rounded > f64::from(u32::MAX) {
            return None;
        }
        if (scaled - rounded).abs() > 1e-6 {
            return None; // more than three decimals
        }
        // In range and integral (checked above), so the cast is exact.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(Self(rounded as u32))
    }
}

impl fmt::Display for Cpus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (whole, frac) = (self.0 / 1000, self.0 % 1000);
        if frac == 0 {
            write!(f, "{whole}")
        } else {
            let digits = format!("{frac:03}");
            write!(f, "{whole}.{}", digits.trim_end_matches('0'))
        }
    }
}

/// How many model layers to offload to the GPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpuLayers {
    /// Let the fit estimator decide.
    #[default]
    Auto,
    /// Offload exactly this many layers (clamped by the fit estimator).
    Layers(u32),
}

// ---- serde: unit strings ----------------------------------------------------------------------

struct UnitVisitor<T> {
    expecting: &'static str,
    parse: fn(&str) -> Option<T>,
}

impl<T> Visitor<'_> for UnitVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<T, E> {
        (self.parse)(v).ok_or_else(|| E::invalid_value(de::Unexpected::Str(v), &self))
    }
}

const BYTES_EXPECTING: &str = "a size like \"512MiB\" (units: B, KiB, MiB, GiB, TiB)";
const DURATION_EXPECTING: &str = "a duration like \"90s\", \"5m\", or \"2h\"";

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(UnitVisitor {
            expecting: BYTES_EXPECTING,
            parse: Self::parse,
        })
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(UnitVisitor {
            expecting: DURATION_EXPECTING,
            parse: Self::parse,
        })
    }
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

// ---- serde: cpus ------------------------------------------------------------------------------

struct CpusVisitor;

impl Visitor<'_> for CpusVisitor {
    type Value = Cpus;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a finite non-negative number with at most 3 decimals")
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Cpus, E> {
        Cpus::from_f64(v).ok_or_else(|| E::invalid_value(de::Unexpected::Float(v), &self))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Cpus, E> {
        u32::try_from(v)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .map(Cpus)
            .ok_or_else(|| E::invalid_value(de::Unexpected::Unsigned(v), &self))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Cpus, E> {
        u64::try_from(v)
            .map_err(|_| E::invalid_value(de::Unexpected::Signed(v), &self))
            .and_then(|u| self.visit_u64(u))
    }
}

impl<'de> Deserialize<'de> for Cpus {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(CpusVisitor)
    }
}

impl Serialize for Cpus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0.is_multiple_of(1000) {
            s.serialize_u32(self.0 / 1000)
        } else {
            s.serialize_f64(f64::from(self.0) / 1000.0)
        }
    }
}

// ---- serde: gpu_layers ------------------------------------------------------------------------

struct GpuLayersVisitor;

impl Visitor<'_> for GpuLayersVisitor {
    type Value = GpuLayers;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"auto\" or a non-negative integer")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<GpuLayers, E> {
        if v == "auto" {
            Ok(GpuLayers::Auto)
        } else {
            Err(E::invalid_value(de::Unexpected::Str(v), &self))
        }
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<GpuLayers, E> {
        u32::try_from(v)
            .map(GpuLayers::Layers)
            .map_err(|_| E::invalid_value(de::Unexpected::Unsigned(v), &self))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<GpuLayers, E> {
        u32::try_from(v)
            .map(GpuLayers::Layers)
            .map_err(|_| E::invalid_value(de::Unexpected::Signed(v), &self))
    }
}

impl<'de> Deserialize<'de> for GpuLayers {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(GpuLayersVisitor)
    }
}

impl Serialize for GpuLayers {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Auto => s.serialize_str("auto"),
            Self::Layers(n) => s.serialize_u32(*n),
        }
    }
}

// ---- JSON Schema ------------------------------------------------------------------------------

impl JsonSchema for ByteSize {
    fn schema_name() -> Cow<'static, str> {
        "ByteSize".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[0-9]{1,20}(B|KiB|MiB|GiB|TiB)$",
            "description": BYTES_EXPECTING,
        })
    }
}

impl JsonSchema for Duration {
    fn schema_name() -> Cow<'static, str> {
        "Duration".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[0-9]{1,20}(s|m|h)$",
            "description": DURATION_EXPECTING,
        })
    }
}

impl JsonSchema for Cpus {
    fn schema_name() -> Cow<'static, str> {
        "Cpus".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "number", "minimum": 0, "multipleOf": 0.001 })
    }
}

impl JsonSchema for GpuLayers {
    fn schema_name() -> Cow<'static, str> {
        "GpuLayers".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "oneOf": [
                { "const": "auto" },
                { "type": "integer", "minimum": 0, "maximum": u32::MAX },
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_size_parses_binary_units() {
        assert_eq!(ByteSize::parse("8GiB"), Some(ByteSize(8 << 30)));
        assert_eq!(ByteSize::parse("512MiB"), Some(ByteSize(512 << 20)));
        assert_eq!(ByteSize::parse("7B"), Some(ByteSize(7)));
        assert_eq!(ByteSize::parse("0B"), Some(ByteSize(0)));
    }

    #[test]
    fn byte_size_rejects_malformed() {
        for bad in [
            "", "GiB", "8", "8GB", "8 GiB", "-1GiB", "+1GiB", "8gib", "1.5GiB", "8GiBx",
        ] {
            assert_eq!(ByteSize::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn byte_size_rejects_overflow() {
        assert_eq!(ByteSize::parse("18446744073709551615TiB"), None);
        assert_eq!(ByteSize::parse("999999999999999999999B"), None);
    }

    #[test]
    fn byte_size_display_is_canonical() {
        assert_eq!(ByteSize(8 << 30).to_string(), "8GiB");
        assert_eq!(ByteSize(1536 << 20).to_string(), "1536MiB");
        assert_eq!(ByteSize(1025).to_string(), "1025B");
        assert_eq!(ByteSize(0).to_string(), "0B");
        assert_eq!(ByteSize(u64::MAX).to_string(), format!("{}B", u64::MAX));
    }

    #[test]
    fn duration_parses_and_displays() {
        assert_eq!(Duration::parse("2h"), Some(Duration(7200)));
        assert_eq!(Duration::parse("90s"), Some(Duration(90)));
        assert_eq!(
            Duration::parse("90s").map(|d| d.to_string()),
            Some("90s".into())
        );
        assert_eq!(
            Duration::parse("120m").map(|d| d.to_string()),
            Some("2h".into())
        );
        for bad in ["", "2", "2d", "1h30m", "h", "-5m"] {
            assert_eq!(Duration::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn cpus_from_numbers() {
        assert_eq!(Cpus::from_f64(0.5), Some(Cpus(500)));
        assert_eq!(Cpus::from_f64(1.25), Some(Cpus(1250)));
        assert_eq!(Cpus::from_f64(0.1), Some(Cpus(100)));
        for bad in [f64::NAN, f64::INFINITY, -1.0, 0.0001, 1e12] {
            assert_eq!(Cpus::from_f64(bad), None, "{bad}");
        }
        assert_eq!(Cpus(2000).to_string(), "2");
        assert_eq!(Cpus(1250).to_string(), "1.25");
        assert_eq!(Cpus(1).to_string(), "0.001");
    }

    #[test]
    fn parse_of_display_is_identity() {
        for n in [
            0,
            1,
            999,
            1000,
            1023,
            1024,
            1025,
            3600,
            7200,
            1 << 20,
            1 << 40,
            u64::MAX,
        ] {
            let b = ByteSize(n);
            assert_eq!(ByteSize::parse(&b.to_string()), Some(b), "{n}");
            let d = Duration(n);
            assert_eq!(Duration::parse(&d.to_string()), Some(d), "{n}");
        }
        assert_eq!(ByteSize(1024).to_string(), "1KiB");
        assert_eq!(Duration(0).to_string(), "0s");
    }

    #[test]
    fn display_round_trips() {
        for s in ["1B", "3KiB", "5MiB", "7GiB", "2TiB", "1025B"] {
            let v = ByteSize::parse(s);
            assert_eq!(v.map(|v| v.to_string()).as_deref(), Some(s));
        }
    }
}
