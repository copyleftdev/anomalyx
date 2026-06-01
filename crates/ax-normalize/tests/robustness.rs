//! Parser robustness ("fuzz-style") harness.
//!
//! Parsers ingest untrusted bytes, so a panic, hang, or unbounded allocation is
//! a real defect — not just a wrong answer. These property tests throw arbitrary,
//! truncated, and magic-prefixed-garbage byte streams at the registry and at
//! every individual parser, asserting only that each call *returns* (Ok or a
//! clean `AxError`) and never unwinds. Deterministic (proptest seeds); runs in
//! the normal test gate, no nightly/libFuzzer needed.

use anomalyx_normalize::ParserRegistry;
use proptest::prelude::*;

/// Leading bytes that push content-sniffing binary parsers past their magic
/// check into the real decode path — where header/length handling lives and
/// where a malformed file is most likely to trip a panic.
const MAGICS: &[&[u8]] = &[
    b"SQLite format 3\x00", // sqlite
    b"PAR1",                // parquet
    b"ARROW1\x00\x00",      // arrow IPC
    b"ElfFile\x00",         // evtx
    b"Obj\x01",             // avro
    b"ORC",                 // orc
    b"PK\x03\x04",          // xlsx/ods (zip)
    b"\xd4\xc3\xb2\xa1",    // pcap (LE)
    b"\xa1\xb2\xc3\xd4",    // pcap (BE)
    b"\x0a\x0d\x0d\x0a",    // pcapng
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// Auto-detection over arbitrary bytes (and an arbitrary file extension)
    /// must always return — never panic, never hang.
    #[test]
    fn normalize_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ext in "[a-z0-9]{0,6}",
    ) {
        let src = format!("fuzz.{ext}");
        let _ = anomalyx_normalize::normalize(&src, &bytes);
    }

    /// Normalization is deterministic: the same bytes parse to byte-identical
    /// output (or the same error) every time — the reproducibility contract,
    /// exercised over fuzz inputs.
    #[test]
    fn normalize_is_deterministic(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ext in "[a-z0-9]{0,6}",
    ) {
        let src = format!("fuzz.{ext}");
        match (
            anomalyx_normalize::normalize(&src, &bytes),
            anomalyx_normalize::normalize(&src, &bytes),
        ) {
            (Ok(a), Ok(b)) => prop_assert_eq!(
                serde_json::to_string(&a).unwrap(),
                serde_json::to_string(&b).unwrap()
            ),
            (Err(a), Err(b)) => prop_assert_eq!(a.to_string(), b.to_string()),
            _ => prop_assert!(false, "normalize result varied between identical runs"),
        }
    }

    /// Every registered parser must survive arbitrary bytes fed straight to it
    /// (bypassing sniff), with no panic.
    #[test]
    fn every_parser_survives_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let reg = ParserRegistry::default();
        for id in reg.ids() {
            let _ = reg.normalize_with(id, "fuzz.dat", &bytes);
        }
    }

    /// Magic-prefixed garbage: a valid signature followed by random bytes drives
    /// binary parsers into their decode path on malformed input. Fed to every
    /// parser and to auto-detection; none may panic.
    #[test]
    fn parsers_survive_magic_prefixed_garbage(
        which in 0usize..MAGICS.len(),
        tail in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut bytes = MAGICS[which].to_vec();
        bytes.extend_from_slice(&tail);
        let reg = ParserRegistry::default();
        for id in reg.ids() {
            let _ = reg.normalize_with(id, "fuzz.dat", &bytes);
        }
        let _ = anomalyx_normalize::normalize("fuzz.bin", &bytes);
    }

    /// Truncation: any prefix of a UTF-8 text stream must parse-or-error cleanly
    /// under every text dialect (catches slicing/boundary panics on partial input).
    #[test]
    fn truncated_text_never_panics(
        full in "(\\{\"[a-z]{1,4}\":[0-9]{1,4}\\}\n){1,8}|([a-z]{1,5},){1,5}[a-z]{1,5}\n([0-9]{1,4},){1,5}[0-9]{1,4}\n",
        cut in 0usize..256,
    ) {
        let bytes = full.as_bytes();
        let end = cut.min(bytes.len());
        let reg = ParserRegistry::default();
        for id in reg.ids() {
            let _ = reg.normalize_with(id, "fuzz.dat", &bytes[..end]);
        }
    }
}
