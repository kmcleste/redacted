/*!
Reversible-map vault — the crown jewel (D1, D12).

All values are encrypted at rest with ChaCha20-Poly1305. The key is generated
once per Vault instance and lives only in process memory.

Each ciphertext blob is prefixed with a 12-byte random nonce.
The vault is `Send + Sync` via `Mutex`-protected state.
*/

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

use crate::error::{EngineError, Result};

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------

fn encrypt(cipher: &ChaCha20Poly1305, plaintext: &[u8]) -> Vec<u8> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(&nonce, plaintext).expect("ChaCha20 encryption failed"));
    out
}

fn decrypt(cipher: &ChaCha20Poly1305, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(EngineError::VaultCrypto("ciphertext too short".into()));
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| EngineError::VaultCrypto("decryption failed".into()))
}

// ---------------------------------------------------------------------------
// VaultEntry
// ---------------------------------------------------------------------------

struct VaultEntry {
    /// {placeholder → encrypted(original)}
    map: HashMap<String, Vec<u8>>,
    expires_at: Instant,
}

impl VaultEntry {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    fn extend_ttl(&mut self, additional: Duration) {
        let candidate = Instant::now() + additional;
        if candidate > self.expires_at {
            self.expires_at = candidate;
        }
    }

    fn get_map(&self, cipher: &ChaCha20Poly1305) -> Result<HashMap<String, String>> {
        self.map
            .iter()
            .map(|(k, ct)| {
                let plaintext = decrypt(cipher, ct)?;
                let value = String::from_utf8(plaintext)
                    .map_err(|e| EngineError::VaultCrypto(e.to_string()))?;
                Ok((k.clone(), value))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
pub const CONVERSATION_TTL: Duration = Duration::from_secs(3600);

struct VaultInner {
    cipher: ChaCha20Poly1305,
    entries: HashMap<String, VaultEntry>,
}

pub struct Vault {
    inner: Mutex<VaultInner>,
}

impl Vault {
    pub fn new() -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        Self {
            inner: Mutex::new(VaultInner {
                cipher: ChaCha20Poly1305::new(&key),
                entries: HashMap::new(),
            }),
        }
    }

    /// Store or merge a placeholder map for the given correlation ID.
    pub fn store(&self, correlation_id: &str, placeholder_map: HashMap<String, String>, ttl: Duration) {
        let mut inner = self.inner.lock().expect("vault mutex poisoned");

        // Encrypt all values *before* mutably borrowing `entries` — avoids
        // the borrow-checker conflict between &cipher and &mut entries.
        let encrypted: Vec<(String, Vec<u8>)> = placeholder_map
            .into_iter()
            .map(|(k, v)| (k, encrypt(&inner.cipher, v.as_bytes())))
            .collect();

        if let Some(entry) = inner.entries.get_mut(correlation_id) {
            if !entry.is_expired() {
                entry.extend_ttl(ttl);
                for (k, ct) in encrypted {
                    entry.map.insert(k, ct);
                }
                return;
            }
        }

        // Not found or expired — create a fresh entry.
        let map: HashMap<String, Vec<u8>> = encrypted.into_iter().collect();
        inner.entries.insert(
            correlation_id.to_string(),
            VaultEntry { map, expires_at: Instant::now() + ttl },
        );
    }

    /// Retrieve the decrypted placeholder map.
    pub fn get(&self, correlation_id: &str) -> Result<HashMap<String, String>> {
        let inner = self.inner.lock().expect("vault mutex poisoned");
        match inner.entries.get(correlation_id) {
            None => Err(EngineError::VaultNotFound(correlation_id.to_string())),
            Some(entry) if entry.is_expired() => {
                Err(EngineError::VaultExpired(correlation_id.to_string()))
            }
            Some(entry) => entry.get_map(&inner.cipher),
        }
    }

    /// Purge a vault entry (right-to-erasure, D12). Returns true if an entry was deleted.
    pub fn delete(&self, correlation_id: &str) -> bool {
        let mut inner = self.inner.lock().expect("vault mutex poisoned");
        inner.entries.remove(correlation_id).is_some()
    }

    /// Remove all expired entries. Call periodically from a maintenance task.
    pub fn purge_expired(&self) -> usize {
        let mut inner = self.inner.lock().expect("vault mutex poisoned");
        let before = inner.entries.len();
        inner.entries.retain(|_, e| !e.is_expired());
        before - inner.entries.len()
    }

    pub fn len(&self) -> usize {
        let inner = self.inner.lock().expect("vault mutex poisoned");
        inner.entries.values().filter(|e| !e.is_expired()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, correlation_id: &str) -> bool {
        let inner = self.inner.lock().expect("vault mutex poisoned");
        inner.entries.get(correlation_id).map_or(false, |e| !e.is_expired())
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("live_entries", &self.len()).finish()
    }
}
