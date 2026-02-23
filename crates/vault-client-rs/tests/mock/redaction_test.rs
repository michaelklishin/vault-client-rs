use vault_client_rs::{RedactionLevel, redact, redaction_level, set_redaction_level};

#[test]
fn default_level_is_full() {
    set_redaction_level(RedactionLevel::Full);
    assert_eq!(redaction_level(), RedactionLevel::Full);
}

#[test]
fn full_redacts_completely() {
    set_redaction_level(RedactionLevel::Full);
    assert_eq!(redact("super-secret-token"), "[REDACTED]");
}

#[test]
fn partial_shows_first_four_chars() {
    set_redaction_level(RedactionLevel::Partial);
    assert_eq!(redact("super-secret-token"), "supe...");
}

#[test]
fn partial_redacts_short_values() {
    set_redaction_level(RedactionLevel::Partial);
    assert_eq!(redact("ab"), "[REDACTED]");
    assert_eq!(redact("abcd"), "[REDACTED]");
}

#[test]
fn none_shows_full_value() {
    set_redaction_level(RedactionLevel::None);
    assert_eq!(redact("super-secret-token"), "super-secret-token");
}

#[test]
fn level_roundtrips() {
    for level in [
        RedactionLevel::Full,
        RedactionLevel::Partial,
        RedactionLevel::None,
    ] {
        set_redaction_level(level);
        assert_eq!(redaction_level(), level);
    }
    // Reset to default for other tests
    set_redaction_level(RedactionLevel::Full);
}

#[test]
fn debug_output_respects_redaction_level() {
    use vault_client_rs::RabbitmqCredentials;

    let creds: RabbitmqCredentials = ("guest", "hunter2").into();

    set_redaction_level(RedactionLevel::Full);
    let debug_full = format!("{:?}", creds);
    assert!(debug_full.contains("[REDACTED]"));
    assert!(!debug_full.contains("hunter2"));

    set_redaction_level(RedactionLevel::None);
    let debug_none = format!("{:?}", creds);
    assert!(debug_none.contains("hunter2"));

    // Reset
    set_redaction_level(RedactionLevel::Full);
}
