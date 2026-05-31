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
    /// Returns `(rehydrated_text, hits, misses)` where `hits` is the number of
    /// successful substitutions and `misses` is placeholders present in the text
    /// but absent from the vault map (D17 metric: engine_rehydrate_mismatches_total).
    pub fn rehydrate(&self, text: &str, map: &HashMap<String, String>) -> (String, usize, usize) {
        if text.is_empty() {
            return (text.to_string(), 0, 0);
        }
        if map.is_empty() {
            let misses = PLACEHOLDER_RE.find_iter(text).count();
            return (text.to_string(), 0, misses);
        }

        let mut hits = 0usize;
        let mut misses = 0usize;
        let result = PLACEHOLDER_RE.replace_all(text, |caps: &regex::Captures<'_>| {
            let ph = caps.get(0).unwrap().as_str();
            if let Some(original) = map.get(ph) {
                hits += 1;
                original.clone()
            } else {
                misses += 1;
                ph.to_string()
            }
        });

        (result.into_owned(), hits, misses)
    }
}
