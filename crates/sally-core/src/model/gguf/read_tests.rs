#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

fn reader(bytes: &[u8], budget: u64) -> Reader<&[u8]> {
    Reader::new(bytes, budget, bytes.len() as u64)
}

#[test]
fn reads_little_endian_scalars_and_counts_position() {
    let bytes = [
        1, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 8, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut r = reader(&bytes, 64);
    assert_eq!(r.u8().unwrap(), 1);
    assert_eq!(r.u16().unwrap(), 0x1234);
    assert_eq!(r.u32().unwrap(), 0x1234_5678);
    assert_eq!(r.u64().unwrap(), 8);
    assert_eq!(r.position(), 15);
}

#[test]
fn a_short_source_is_truncated() {
    // The file claims more bytes than the source yields.
    let mut r = Reader::new(&[1u8, 2, 3][..], 64, 64);
    assert_eq!(r.u32(), Err(ReadError::Truncated));
}

#[test]
fn past_the_file_length_is_truncated_without_reading() {
    let mut r = Reader::new(&[0u8; 16][..], 64, 6);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32(), Err(ReadError::Truncated));
    assert_eq!(r.position(), 4);
    assert_eq!(r.u16().unwrap(), 0);
}

#[test]
fn reading_past_the_budget_is_over_budget_even_when_bytes_remain() {
    let mut r = reader(&[0; 16], 7);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32(), Err(ReadError::OverBudget));
    // The refused read consumed nothing.
    assert_eq!(r.position(), 4);
}

#[test]
fn the_budget_comes_before_the_file_length() {
    let mut r = Reader::new(&[0u8; 4][..], 8, 4);
    assert_eq!(r.u64(), Err(ReadError::Truncated));
    assert_eq!(r.bytes(9), Err(ReadError::OverBudget));
}

#[test]
fn the_budget_and_the_file_length_are_inclusive() {
    let mut r = reader(&[0; 8], 8);
    assert_eq!(r.u64().unwrap(), 0);
    assert_eq!(r.u8(), Err(ReadError::OverBudget));
    let mut r = Reader::new(&[0u8; 8][..], 9, 8);
    assert_eq!(r.u64().unwrap(), 0);
    assert_eq!(r.u8(), Err(ReadError::Truncated));
}

#[test]
fn bytes_returns_exactly_the_requested_run() {
    let mut r = reader(b"abcdef", 64);
    assert_eq!(r.bytes(4).unwrap(), b"abcd");
    assert_eq!(r.position(), 4);
    assert_eq!(r.bytes(3), Err(ReadError::Truncated));
}

#[test]
fn bytes_from_a_short_source_is_truncated() {
    let mut r = Reader::new(&b"ab"[..], 64, 64);
    assert_eq!(r.bytes(3), Err(ReadError::Truncated));
}

#[test]
fn bytes_checks_the_budget_before_allocating() {
    // A huge length is refused by the budget, never by an allocation failure.
    let mut r = Reader::new(&b"ab"[..], 64, u64::MAX);
    assert_eq!(r.bytes(u64::MAX), Err(ReadError::OverBudget));
    assert_eq!(r.position(), 0);
}

#[test]
fn skip_consumes_without_keeping() {
    let mut r = reader(&[9; 40], 64);
    r.skip(33).unwrap();
    assert_eq!(r.position(), 33);
    assert_eq!(r.skip(8), Err(ReadError::Truncated));
    let mut r = reader(&[9; 40], 32);
    assert_eq!(r.skip(33), Err(ReadError::OverBudget));
    let mut r = Reader::new(&[9u8; 4][..], 64, 64);
    assert_eq!(r.skip(5), Err(ReadError::Truncated));
}

#[test]
fn signed_and_float_reads_use_the_same_bytes() {
    let mut bytes = vec![0xff, 0xfe, 0xff, 0x00, 0x00, 0x80, 0x3f];
    bytes.extend_from_slice(&(-3i32).to_le_bytes());
    bytes.extend_from_slice(&(-4i64).to_le_bytes());
    bytes.extend_from_slice(&2.5f64.to_le_bytes());
    let mut r = reader(&bytes, 64);
    assert_eq!(r.i8().unwrap(), -1);
    assert_eq!(r.i16().unwrap(), -2);
    assert_eq!(r.f32().unwrap(), 1.0);
    assert_eq!(r.i32().unwrap(), -3);
    assert_eq!(r.i64().unwrap(), -4);
    assert_eq!(r.f64().unwrap(), 2.5);
}

struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk"))
    }
}

#[test]
fn an_io_error_is_reported_as_io() {
    let mut r = Reader::new(Failing, 64, 64);
    assert_eq!(r.u8(), Err(ReadError::Io(std::io::ErrorKind::Other)));
}

/// Fails once with `Interrupted`, then reads.
struct Interrupting(bool, &'static [u8]);

impl Read for Interrupting {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.0 {
            self.0 = false;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.1.read(buf)
    }
}

#[test]
fn interrupted_reads_are_retried() {
    let mut r = Reader::new(Interrupting(true, &[7, 0]), 64, 2);
    assert_eq!(r.u16().unwrap(), 7);
    let mut r = Reader::new(Interrupting(true, b"xy"), 64, 2);
    assert_eq!(r.bytes(2).unwrap(), b"xy");
    let mut r = Reader::new(Interrupting(true, b"xy"), 64, 2);
    r.skip(2).unwrap();
}
