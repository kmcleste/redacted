/*!
Integration tests for engine-core — mirrors the Python test suite
to ensure behavioural equivalence.
*/

use engine_core::Engine;

fn engine() -> Engine {
    Engine::with_default_policy()
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

mod validators {
    use engine_core::validators::*;

    #[test]
    fn ssn_valid() {
        assert!(validate_ssn("575-82-8889"));
        assert!(validate_ssn("001-01-0001"));
        assert!(validate_ssn("456-78-9012"));
    }

    #[test]
    fn ssn_invalid_area() {
        assert!(!validate_ssn("000-12-3456"));
        assert!(!validate_ssn("666-12-3456"));
        assert!(!validate_ssn("900-12-3456"));
    }

    #[test]
    fn ssn_invalid_group_serial() {
        assert!(!validate_ssn("123-00-1234"));
        assert!(!validate_ssn("123-45-0000"));
    }

    #[test]
    fn ssn_known_invalid() {
        assert!(!validate_ssn("078-05-1120"));
        assert!(!validate_ssn("123-45-6789"));
    }

    #[test]
    fn credit_card_valid_visa() {
        // 4532015112830366 passes Luhn and is not a test card.
        assert!(validate_credit_card("4532015112830366"));
    }

    #[test]
    fn credit_card_valid_mc() {
        assert!(validate_credit_card("5425233430109903"));
    }

    #[test]
    fn credit_card_valid_amex() {
        assert!(validate_credit_card("370000000000002"));
    }

    #[test]
    fn credit_card_test_card_rejected() {
        assert!(!validate_credit_card("4111111111111111"));
        assert!(!validate_credit_card("5500005555555559"));
    }

    #[test]
    fn credit_card_fails_luhn_rejected() {
        assert!(!validate_credit_card("4532015112830360"));
    }

    #[test]
    fn aba_routing_valid() {
        assert!(validate_aba_routing("021000021"));
        assert!(validate_aba_routing("011000138"));
    }

    #[test]
    fn aba_routing_all_zeros_rejected() {
        assert!(!validate_aba_routing("000000000"));
    }

    #[test]
    fn aba_routing_wrong_length_rejected() {
        assert!(!validate_aba_routing("12345678"));
    }

    #[test]
    fn email_real_domain_valid() {
        assert!(validate_email("user@company.com"));
    }

    #[test]
    fn email_doc_domains_rejected() {
        assert!(!validate_email("user@example.com"));
        assert!(!validate_email("user@example.org"));
        assert!(!validate_email("user@test.com"));
        assert!(!validate_email("user@localhost"));
    }

    #[test]
    fn ip_public_valid() {
        assert!(validate_ip_address("8.8.8.8"));
        assert!(validate_ip_address("1.1.1.1"));
    }

    #[test]
    fn ip_reserved_rejected() {
        assert!(!validate_ip_address("192.0.2.1"));
        assert!(!validate_ip_address("198.51.100.1"));
        assert!(!validate_ip_address("127.0.0.1"));
    }

    #[test]
    fn phone_fiction_rejected() {
        assert!(!validate_phone("555-0100"));
        assert!(!validate_phone("5550199"));
    }

    #[test]
    fn vin_valid() {
        assert!(validate_vin("1HGBH41JXMN109186"));
    }

    #[test]
    fn vin_invalid_length() {
        assert!(!validate_vin("1HGBH41JXMN10918"));
        assert!(!validate_vin("1HGBH41JXMN1091860"));
    }

    #[test]
    fn vin_contains_ioq_rejected() {
        assert!(!validate_vin("1HGBH41JOMN109186"));
    }

    #[test]
    fn npi_valid() {
        assert!(validate_npi("1234567893"));
    }

    #[test]
    fn npi_wrong_check_digit() {
        assert!(!validate_npi("1234567890"));
    }
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

mod detectors {
    use engine_core::{detectors::ensemble::DetectionEnsemble, EntityType, PolicyBundle};

    fn ensemble() -> DetectionEnsemble {
        DetectionEnsemble::new(PolicyBundle::default())
    }

    #[test]
    fn ssn_formatted_detected() {
        let spans = ensemble().detect("SSN: 575-82-8889");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Ssn));
    }

    #[test]
    fn bare_ssn_without_context_not_detected() {
        let spans = ensemble().detect("The number is 575828889.");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Ssn));
    }

    #[test]
    fn bare_ssn_with_context_detected() {
        let spans = ensemble().detect("taxpayer id 575828889 on file");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Ssn));
    }

    #[test]
    fn valid_visa_detected() {
        let spans = ensemble().detect("card: 4532015112830366");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn test_card_not_detected() {
        let spans = ensemble().detect("card 4111111111111111");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::CreditCard));
    }

    #[test]
    fn email_detected() {
        let spans = ensemble().detect("contact user@acme.com for info");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Email));
    }

    #[test]
    fn example_email_not_detected() {
        let spans = ensemble().detect("see user@example.com");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Email));
    }

    #[test]
    fn aws_key_detected() {
        let spans = ensemble().detect("key=AKIAIOSFODNN7EXAMPLE");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::AwsKey));
    }

    #[test]
    fn github_token_detected() {
        let token = format!("ghp_{}", "A".repeat(36));
        let text = format!("token: {token}");
        let spans = ensemble().detect(&text);
        assert!(spans.iter().any(|s| s.entity_type == EntityType::GithubToken));
    }

    #[test]
    fn pem_block_detected() {
        let spans = ensemble().detect("-----BEGIN PRIVATE KEY-----\nabc123");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::PemBlock));
    }

    #[test]
    fn connection_string_detected() {
        let spans = ensemble().detect("db = postgres://user:pass@host:5432/db");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::ConnectionString));
    }

    #[test]
    fn no_false_positive_on_clean_text() {
        let spans = ensemble().detect("The quick brown fox jumps over the lazy dog.");
        assert!(spans.is_empty());
    }

    #[test]
    fn overlapping_spans_resolved() {
        let text = "ssn 575-82-8889 and card 4532015112830366";
        let spans = ensemble().detect(text);
        for (i, a) in spans.iter().enumerate() {
            for (j, b) in spans.iter().enumerate() {
                if i != j {
                    assert!(a.end <= b.start || b.end <= a.start, "overlapping spans: {a:?} {b:?}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Masker
// ---------------------------------------------------------------------------

mod masker {
    use engine_core::{
        entities::{DetectedSpan, EntityType},
        masker::Masker,
    };

    fn span(text: &str, start: usize, end: usize, et: EntityType) -> DetectedSpan {
        DetectedSpan::new(start, end, et, &text[start..end], 1.0)
    }

    #[test]
    fn single_span_masked() {
        let text = "SSN: 575-82-8889";
        let spans = vec![span(text, 5, 16, EntityType::Ssn)];
        let (masked, mapping) = Masker.mask(text, &spans);
        assert_eq!(masked, "SSN: [SSN_1]");
        assert_eq!(mapping["[SSN_1]"], "575-82-8889");
    }

    #[test]
    fn consistent_placeholder_for_same_value() {
        let text = "SSN 575-82-8889 and again 575-82-8889";
        let span1 = span(text, 4, 15, EntityType::Ssn);
        let span2 = span(text, 26, 37, EntityType::Ssn);
        let (masked, mapping) = Masker.mask(text, &[span1, span2]);
        assert_eq!(masked.matches("[SSN_1]").count(), 2);
        assert_eq!(mapping.len(), 1);
    }

    #[test]
    fn counter_per_entity_type() {
        let text = "a@b.com and c@d.com";
        let span1 = span(text, 0, 7, EntityType::Email);
        let span2 = span(text, 12, 19, EntityType::Email);
        let (_, mapping) = Masker.mask(text, &[span1, span2]);
        assert!(mapping.contains_key("[EMAIL_1]"));
        assert!(mapping.contains_key("[EMAIL_2]"));
    }

    #[test]
    fn no_spans_returns_unchanged() {
        let text = "Nothing sensitive.";
        let (masked, mapping) = Masker.mask(text, &[]);
        assert_eq!(masked, text);
        assert!(mapping.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Batch rehydrator
// ---------------------------------------------------------------------------

mod rehydrator {
    use engine_core::rehydrator::BatchRehydrator;
    use std::collections::HashMap;

    #[test]
    fn simple_rehydration() {
        let map = HashMap::from([("[PHONE_1]".to_string(), "(415) 555-1234".to_string())]);
        let (result, hits, misses) = BatchRehydrator.rehydrate("Call [PHONE_1] for support.", &map);
        assert_eq!(result, "Call (415) 555-1234 for support.");
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);
    }

    #[test]
    fn unknown_placeholder_passed_through() {
        let (result, hits, misses) =
            BatchRehydrator.rehydrate("Value is [UNKNOWN_99].", &HashMap::new());
        assert_eq!(result, "Value is [UNKNOWN_99].");
        assert_eq!(hits, 0);
        assert_eq!(misses, 1);
    }

    #[test]
    fn repeated_placeholder() {
        let map = HashMap::from([("[EMAIL_1]".to_string(), "a@b.com".to_string())]);
        let (result, hits, misses) =
            BatchRehydrator.rehydrate("[EMAIL_1] sent to [EMAIL_1]", &map);
        assert_eq!(result, "a@b.com sent to a@b.com");
        assert_eq!(hits, 2);
        assert_eq!(misses, 0);
    }
}

// ---------------------------------------------------------------------------
// Streaming rehydrator
// ---------------------------------------------------------------------------

mod streaming {
    use engine_core::StreamingRehydrator;
    use std::collections::HashMap;

    fn map() -> HashMap<String, String> {
        HashMap::from([
            ("[SSN_1]".to_string(), "575-82-8889".to_string()),
            ("[EMAIL_1]".to_string(), "user@corp.com".to_string()),
        ])
    }

    fn stream(chunks: &[&str], m: HashMap<String, String>) -> String {
        let mut r = StreamingRehydrator::new(m);
        let mut out: Vec<String> = chunks.iter().map(|c| r.feed(c)).collect();
        out.push(r.flush());
        out.concat()
    }

    #[test]
    fn whole_placeholder_in_one_chunk() {
        assert_eq!(stream(&["SSN is [SSN_1] ok"], map()), "SSN is 575-82-8889 ok");
    }

    #[test]
    fn placeholder_split_across_chunks() {
        assert_eq!(stream(&["before [SS", "N_", "1] after"], map()), "before 575-82-8889 after");
    }

    #[test]
    fn one_char_at_a_time() {
        let full = "x[SSN_1]y";
        let chunks: Vec<&str> = full.split("").filter(|s| !s.is_empty()).collect();
        assert_eq!(stream(&chunks, map()), "x575-82-8889y");
    }

    #[test]
    fn multiple_placeholders_split() {
        assert_eq!(
            stream(&["[SSN", "_1] and [EMAIL", "_1]"], map()),
            "575-82-8889 and user@corp.com"
        );
    }

    #[test]
    fn unknown_placeholder_passes_through() {
        assert_eq!(stream(&["value [UNKNOWN_99] here"], map()), "value [UNKNOWN_99] here");
    }

    #[test]
    fn open_bracket_at_end_flushed() {
        let mut r = StreamingRehydrator::new(map());
        let out = r.feed("text [");
        let flush = r.flush();
        assert_eq!(format!("{out}{flush}"), "text [");
    }

    #[test]
    fn long_non_placeholder_does_not_buffer_forever() {
        let noise = format!("[{}rest", "A".repeat(200));
        let result = stream(&[&noise], map());
        assert!(result.contains("rest"));
    }

    #[test]
    fn empty_stream() {
        assert_eq!(stream(&[], map()), "");
    }
}

// ---------------------------------------------------------------------------
// Engine round-trip (pipeline)
// ---------------------------------------------------------------------------

mod pipeline {
    use super::engine;

    #[test]
    fn round_trip_ssn() {
        let e = engine();
        let text = "SSN: 575-82-8889";
        let masked = e.mask(text, None, None);
        assert!(!masked.text.contains("575-82-8889"));
        assert!(masked.text.contains("[SSN_1]"));

        let rh = e.rehydrate(&masked.text, &masked.correlation_id, None);
        assert_eq!(rh.text, text);
        assert_eq!(rh.rehydrated_count, 1);
    }

    #[test]
    fn round_trip_email() {
        let e = engine();
        let text = "Contact admin@corp.io for help";
        let masked = e.mask(text, None, None);
        assert!(!masked.text.contains("admin@corp.io"));

        let rh = e.rehydrate(&masked.text, &masked.correlation_id, None);
        assert_eq!(rh.text, text);
    }

    #[test]
    fn no_pii_text_unchanged() {
        let e = engine();
        let text = "Nothing sensitive here.";
        let result = e.mask(text, None, None);
        assert_eq!(result.text, text);
        assert!(!result.was_masked());
    }

    #[test]
    fn streaming_round_trip() {
        let e = engine();
        let text = "SSN: 575-82-8889 and email: user@corp.com";
        let masked = e.mask(text, None, None);

        let mid = masked.text.len() / 2;
        let c1 = &masked.text[..mid];
        let c2 = &masked.text[mid..];

        let mut r = e.streaming_rehydrator(&masked.correlation_id, None);
        let output = format!("{}{}{}", r.feed(c1), r.feed(c2), r.flush());
        assert_eq!(output, text);
    }

    #[test]
    fn vault_missing_returns_unchanged() {
        let e = engine();
        let rh = e.rehydrate("[SSN_1]", "nonexistent-cid", None);
        assert_eq!(rh.text, "[SSN_1]");
        assert_eq!(rh.rehydrated_count, 0);
    }

    #[test]
    fn delete_vault_entry() {
        let e = engine();
        let masked = e.mask("SSN: 575-82-8889", None, None);
        assert!(e.delete_vault_entry(&masked.correlation_id));
        let rh = e.rehydrate(&masked.text, &masked.correlation_id, None);
        assert_eq!(rh.rehydrated_count, 0);
    }

    #[test]
    fn entity_counts_reported() {
        let e = engine();
        let text = "Cards: 4532015112830366 and 5425233430109903, SSN 575-82-8889";
        let result = e.mask(text, None, None);
        assert!(*result.entity_counts.get(&engine_core::EntityType::CreditCard).unwrap_or(&0) >= 2);
        assert!(*result.entity_counts.get(&engine_core::EntityType::Ssn).unwrap_or(&0) >= 1);
    }
}
