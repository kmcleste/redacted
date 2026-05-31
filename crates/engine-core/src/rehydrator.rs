/*!
Batch rehydrator: replaces placeholders back to original values in a complete string.

For streaming (chunk-by-chunk) use `StreamingRehydrator` in `streaming.rs`.
*/

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

// Matches any typed positional placeholder: [ENTITY_TYPE_N]
static PLACEHOLDER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[[A-Z_]+_\d+\]").unwrap());

pub struct BatchRehydrator;

impl BatchRehydrator {
    /// Replace all known placeholders in `text`.
    ///
    /// Returns the rehydrated text and the count of substitutions made.
    pub fn rehydrate(&self, text: &str, map: &HashMap<String, String>) -> (String, usize) {
        if map.is_empty() || text.is_empty() {
            return (text.to_string(), 0);
        }

        let mut count = 0usize;
        let result = PLACEHOLDER_RE.replace_all(text, |caps: &regex::Captures<'_>| {
            let ph = caps.get(0).unwrap().as_str();
            if let Some(original) = map.get(ph) {
                count += 1;
                original.clone()
            } else {
                ph.to_string()
            }
        });

        (result.into_owned(), count)
    }
}
