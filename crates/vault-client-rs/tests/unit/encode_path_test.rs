use proptest::prelude::*;
use vault_client_rs::encode_path;

proptest! {
    #[test]
    fn prop_encode_path_never_contains_raw_special_chars(s in "\\PC{0,128}") {
        let encoded = encode_path(&s);
        // The output should never contain unescaped ?, #, or raw spaces
        for (i, ch) in encoded.char_indices() {
            match ch {
                '?' | '#' | ' ' | '[' | ']' => {
                    panic!("encode_path({s:?}) produced unescaped '{ch}' at index {i}: {encoded:?}");
                }
                _ => {}
            }
        }
    }

    #[test]
    fn prop_encode_path_percent_is_always_followed_by_hex(s in "\\PC{0,64}") {
        let encoded = encode_path(&s);
        let bytes = encoded.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'%' {
                // Must be followed by exactly two hex digits
                prop_assert!(i + 2 < bytes.len(),
                    "trailing percent in encode_path({:?}): {:?}", s, encoded);
                prop_assert!(bytes[i + 1].is_ascii_hexdigit(),
                    "non-hex after percent in encode_path({:?}): {:?}", s, encoded);
                prop_assert!(bytes[i + 2].is_ascii_hexdigit(),
                    "non-hex after percent in encode_path({:?}): {:?}", s, encoded);
            }
        }
    }

    #[test]
    fn prop_encode_path_preserves_slashes(s in "[a-z]{1,10}/[a-z]{1,10}/[a-z]{1,10}") {
        let encoded = encode_path(&s);
        prop_assert_eq!(&encoded, &s, "slashes should be preserved for path segments");
    }

    #[test]
    fn prop_encode_path_ascii_alnum_preserved(s in "[a-zA-Z0-9]{1,64}") {
        let encoded = encode_path(&s);
        prop_assert_eq!(&encoded, &s, "pure ASCII alphanumeric should pass through unchanged");
    }
}

#[test]
fn encode_path_empty_string() {
    assert_eq!(encode_path(""), "");
}

#[test]
fn encode_path_question_mark() {
    assert_eq!(encode_path("a?b"), "a%3Fb");
}

#[test]
fn encode_path_hash() {
    assert_eq!(encode_path("a#b"), "a%23b");
}

#[test]
fn encode_path_percent() {
    assert_eq!(encode_path("100%"), "100%25");
}

#[test]
fn encode_path_multibyte_utf8() {
    // "café" = 63 61 66 c3 a9 — the é (U+00E9) is two bytes: 0xC3, 0xA9
    let encoded = encode_path("café");
    assert_eq!(encoded, "caf%C3%A9");
}
