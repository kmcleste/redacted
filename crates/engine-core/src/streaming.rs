/*!
Streaming rehydrator — the hard problem (PRD §3, §5).

A placeholder like `[SSN_1]` may be split across SSE/WebSocket frames:
`[SS` → `N_` → `1]`. Per-chunk regex replacement corrupts it.

Solution: a bounded-lookahead state machine.

States:
  - Normal    — scan for `[`; everything before it is safe to emit.
  - InBracket — buffer bytes after `[` until:
    a) `]` found → lookup in map: hit → emit original, miss → emit buffer.
    b) buffer exceeds `max_placeholder_len` → emit first byte, retry.

The buffer is always bounded: max `max_placeholder_len + 1` bytes.
No heap growth from adversarial input.

Thread-safety: one `StreamingRehydrator` per stream session; not `Sync`.
*/

use std::collections::HashMap;

/// Hard upper bound on placeholder length: `[CONNECTION_STRING_999]` = 23 chars.
/// 64 gives ample headroom without risking unbounded buffering.
const HARD_MAX: usize = 64;

pub struct StreamingRehydrator {
    map: HashMap<String, String>,
    max_len: usize,
    buffer: String,
    in_bracket: bool,
}

impl StreamingRehydrator {
    pub fn new(map: HashMap<String, String>) -> Self {
        let max_len = map
            .keys()
            .map(|k| k.len())
            .max()
            .unwrap_or(HARD_MAX)
            .min(HARD_MAX);
        Self {
            map,
            max_len,
            buffer: String::with_capacity(max_len + 1),
            in_bracket: false,
        }
    }

    /// Consume a chunk; return whatever output can be safely emitted now.
    pub fn feed(&mut self, chunk: &str) -> String {
        self.buffer.push_str(chunk);
        self.drain()
    }

    /// End of stream: flush all buffered content as-is.
    /// Must be called exactly once at stream end.
    pub fn flush(&mut self) -> String {
        let remaining = std::mem::take(&mut self.buffer);
        self.in_bracket = false;
        remaining
    }

    fn drain(&mut self) -> String {
        let mut output = String::with_capacity(self.buffer.len());

        loop {
            if !self.in_bracket {
                match self.buffer.find('[') {
                    None => {
                        // No placeholder start — safe to emit everything.
                        output.push_str(&self.buffer);
                        self.buffer.clear();
                        break;
                    }
                    Some(pos) => {
                        // Emit everything before `[`.
                        output.push_str(&self.buffer[..pos]);
                        self.buffer.drain(..pos);
                        self.in_bracket = true;
                    }
                }
            } else {
                match self.buffer.find(']') {
                    Some(close) => {
                        let candidate = &self.buffer[..close + 1];
                        if let Some(original) = self.map.get(candidate) {
                            output.push_str(original);
                        } else {
                            output.push_str(candidate);
                        }
                        self.buffer.drain(..close + 1);
                        self.in_bracket = self.buffer.starts_with('[');
                    }
                    None if self.buffer.len() > self.max_len => {
                        // Too long to be a valid placeholder — emit first char and retry.
                        let first = self.buffer.chars().next().unwrap();
                        output.push(first);
                        let char_len = first.len_utf8();
                        self.buffer.drain(..char_len);
                        self.in_bracket = self.buffer.starts_with('[');
                    }
                    None => {
                        // Need more data.
                        break;
                    }
                }
            }
        }

        output
    }
}

impl std::fmt::Debug for StreamingRehydrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingRehydrator")
            .field("placeholders", &self.map.len())
            .field("buffered_bytes", &self.buffer.len())
            .field("in_bracket", &self.in_bracket)
            .finish()
    }
}
