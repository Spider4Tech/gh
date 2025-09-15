use dashmap::DashMap;
use once_cell::sync::Lazy;
use zeroize::Zeroize;

/// Length of cryptographic keys in bytes
pub const KEY_LENGTH: usize = 2512;

/// Length of salt values in bytes
pub const SALT_LEN: usize = 32;

/// Current version identifier for the encryption algorithm
pub const VERSION: u8 = 9;

/// Algorithm identifier for the encryption scheme
pub const ALG_ID: u8 = 173;

/// Chunk size for Blake3 keystream generation in bytes
pub const BLAKE3_KEYSTREAM_CHUNK: usize = 65536;

/// Optimal chunk size for parallel processing in bytes
pub const OPTIMAL_CHUNK_SIZE: usize = 65536;

/// Number of encryption rounds to perform
pub const ROUND: usize = 4;

/// Cipher cache containing precomputed lookup tables and transformation data
/// 
/// This structure stores optimized lookup tables for fast encryption and decryption
/// operations, including forward and inverse substitution boxes, character mappings,
/// and key-derived transformation data.
#[derive(Debug, Clone)]
pub struct CipherCache {
    /// Forward substitution lookup tables
    pub rows: Vec<[u8; 256]>,
    /// Index mapping for efficient table lookups
    pub index_map: Vec<usize>,
    /// Inverse substitution lookup tables
    pub inverse_rows: Vec<[u8; 256]>,
    /// Position mapping for character lookups
    pub char_positions: [usize; 256],
    /// Character transformation table
    pub characters: [u8; 256],
    /// Key1-derived character indices
    pub key1_chars: Vec<u8>,
    /// Key2-derived character indices
    pub key2_chars: Vec<u8>,
}

/// Cache key for identifying unique cipher cache entries
/// 
/// This structure serves as a unique identifier for cached cipher data,
/// ensuring that the same encryption parameters reuse cached computations
/// for improved performance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Runtime salt value
    pub run_salt: [u8; 32],
    /// Round-specific seed value
    pub round_seed: [u8; 8],
    /// Length of data being processed
    pub data_len: usize,
}

/// Global thread-safe cache store for cipher computations
/// 
/// This lazy-initialized concurrent hash map stores precomputed cipher caches
/// to avoid redundant expensive calculations across multiple operations.
pub static CIPHER_CACHE_STORE: Lazy<DashMap<CacheKey, CipherCache>> = Lazy::new(|| {
    // Inline storage for small maps reduces allocations; tune shards internally
    DashMap::with_capacity(16)
});

impl Zeroize for CipherCache {
    /// Securely zeros all sensitive data in the cipher cache
    /// 
    /// This implementation ensures that cryptographic material stored in the cache
    /// is properly cleared from memory when no longer needed, preventing potential
    /// information leakage.
    fn zeroize(&mut self) {
        for row in &mut self.rows {
            row.zeroize();
        }
        for inv_row in &mut self.inverse_rows {
            inv_row.zeroize();
        }
        self.char_positions.zeroize();
        self.characters.zeroize();
        self.index_map.zeroize();
        self.key1_chars.zeroize();
        self.key2_chars.zeroize();
    }
}

impl Drop for CipherCache {
    /// Automatically zeros sensitive data when the cache is dropped
    /// 
    /// This implementation provides defense-in-depth by ensuring that sensitive
    /// cryptographic material is cleared from memory even if explicit zeroization
    /// is not called.
    fn drop(&mut self) {
        self.zeroize();
    }
}