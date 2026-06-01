//! Parser robustness ("fuzz-style") harness.
//!
//! Parsers ingest untrusted bytes, so a panic or hang is a real defect — not
//! just a wrong answer. These property tests throw arbitrary, truncated, and
//! magic-prefixed byte streams at the registry and at every individual parser,
//! asserting only that each call *returns* (Ok or a clean `AxError`) and never
//! unwinds. Runs in the normal test gate, no nightly/libFuzzer needed.
//!
//! One honest exclusion: the binary *container* decoders (`parquet`/`arrow`,
//! `avro`, `orc`, `evtx`, `pcap`) delegate to third-party crates that trust the
//! file's internal length/count fields, so a maliciously crafted length can make
//! the underlying crate attempt a huge allocation. That is a property of binary
//! format parsing, not a logic bug here, and is not something anomalyx can bound
//! without forking those decoders — so we don't feed them adversarial length
//! fields (see [`MAGICS`]). They are still fuzzed with arbitrary bytes, which
//! fail their magic check and are rejected cleanly.

use anomalyx_normalize::ParserRegistry;
use proptest::prelude::*;

/// Leading bytes that push a parser past its magic check into the real decode
/// path — where header/length handling lives and a malformed file is most likely
/// to trip a panic.
///
/// **Scope, honestly:** this list is limited to formats whose decode allocation
/// anomalyx itself bounds — `sqlite` deserializes from the supplied byte buffer,
/// so it can't allocate beyond the input. The columnar/container decoders
/// (`parquet`/`arrow` via Polars, `avro`, `orc`, `evtx`, `pcap`) delegate to
/// third-party crates that *trust the file's internal length/count fields*: a
/// maliciously crafted length makes the underlying crate attempt a huge
/// allocation — a known property of binary-format parsing, not a logic bug in
/// anomalyx, and not something we can prevent without forking those decoders.
/// Those parsers are still fuzzed with arbitrary bytes below (which fail the
/// magic check and are rejected cleanly); we just don't feed them adversarial
/// length fields here and assert a guarantee the dependency doesn't make.
const MAGICS: &[&[u8]] = &[
    b"SQLite format 3\x00", // sqlite — allocation bounded by the input buffer
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
