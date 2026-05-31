/*!
Masker: replaces detected spans with typed positional placeholders (D3).

Format: `[ENTITY_TYPE_N]`  — consistent within a request (same original value
→ same placeholder), typed counters per entity type.

Operates right-to-left to preserve byte offsets of earlier spans.
*/

use std::collections::HashMap;

use crate::entities::{DetectedSpan, EntityType};

pub struct Masker;

impl Masker {
    pub fn mask(&self, text: &str, spans: &[DetectedSpan]) -> (String, HashMap<String, String>) {
        if spans.is_empty() {
            return (text.to_string(), HashMap::new());
        }

        // Forward pass: assign placeholders in first-seen order.
        let mut counters: HashMap<EntityType, usize> = HashMap::new();
        let mut value_to_placeholder: HashMap<String, String> = HashMap::new();
        let mut placeholder_to_value: HashMap<String, String> = HashMap::new();

        let mut sorted_fwd: Vec<&DetectedSpan> = spans.iter().collect();
        sorted_fwd.sort_by_key(|s| s.start);

        for span in &sorted_fwd {
            if !value_to_placeholder.contains_key(&span.original_value) {
                let counter = counters.entry(span.entity_type).or_insert(0);
                *counter += 1;
                let placeholder = format!("[{}_{}]", span.entity_type.as_str(), counter);
                value_to_placeholder.insert(span.original_value.clone(), placeholder.clone());
                placeholder_to_value.insert(placeholder, span.original_value.clone());
            }
        }

        // Backward pass: replace spans right-to-left.
        let mut sorted_bwd = sorted_fwd;
        sorted_bwd.sort_by_key(|s| std::cmp::Reverse(s.start));

        let mut chars: Vec<u8> = text.as_bytes().to_vec();
        for span in sorted_bwd {
            let placeholder = value_to_placeholder[&span.original_value].as_bytes();
            chars.splice(span.start..span.end, placeholder.iter().copied());
        }

        let masked = String::from_utf8(chars).expect("masked text is valid UTF-8");
        (masked, placeholder_to_value)
    }
}
