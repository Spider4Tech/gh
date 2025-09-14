use crate::crypto::fill_random;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Escapes zero bytes in input data for safe transmission
/// 
/// Replaces each zero byte (0x00) with a two-byte escape sequence (0x00, 0xFF)
/// to prevent zero bytes from being interpreted as string terminators or
/// causing issues in protocols that treat zero as special.
/// 
/// # Arguments
/// 
/// * `input` - Vector of bytes to escape
/// 
/// # Returns
/// 
/// Vector with zero bytes escaped as two-byte sequences
/// 
/// # Note
/// 
/// This escaping is reversible using the corresponding unescape function.
pub fn escape_zero_bytes(input: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        if b == 0 {
            out.push(0u8);
            out.push(0xFFu8);
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}

/// Unescapes zero bytes and removes padding markers
/// 
/// Reverses the zero-byte escaping process and removes padding markers
/// (represented as 0x00, 0x00 sequences) that were inserted during
/// the padding process.
/// 
/// # Arguments
/// 
/// * `v` - Vector of escaped bytes to process
/// 
/// # Returns
/// 
/// Vector with original zero bytes restored and padding removed
/// 
/// # Processing Rules
/// 
/// - (0x00, 0x00) sequences are removed as padding markers
/// - (0x00, 0xFF) sequences are converted back to single 0x00 bytes
/// - All other bytes pass through unchanged
pub fn unescape_and_remove_stars(v: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0usize;
    while i < v.len() {
        if v[i] == 0 {
            if i + 1 < v.len() {
                let nxt = v[i + 1];
                if nxt == 0 {
                    i += 2;
                    continue;
                } else if nxt == 0xFF {
                    out.push(0u8);
                    i += 2;
                    continue;
                } else {
                    out.push(v[i]);
                    i += 1;
                    continue;
                }
            } else {
                i += 1;
                continue;
            }
        } else {
            out.push(v[i]);
            i += 1;
        }
    }
    out
}

/// Inserts random padding markers into escaped data
/// 
/// Adds cryptographically secure random padding to data by inserting
/// padding markers (0x00, 0x00 sequences) at pseudorandom positions.
/// The number and positions of padding markers are derived from the key
/// to ensure deterministic removal during decryption.
/// 
/// # Arguments
/// 
/// * `word` - Input data to pad (will be escaped first)
/// * `key` - Key material for deriving padding parameters
/// 
/// # Returns
/// 
/// Vector with random padding markers inserted
/// 
/// # Security
/// 
/// - Uses HKDF for secure key derivation from input key
/// - Employs cryptographically secure random nonce
/// - Padding amount is randomized within bounds (1/3 to 2x original length)
/// - All sensitive intermediate values are securely cleared from memory
/// 
/// # Process
/// 
/// 1. Escapes zero bytes in input data
/// 2. Derives padding parameters from key and fresh random nonce
/// 3. Calculates number of padding markers to insert
/// 4. Determines positions for padding insertion
/// 5. Inserts padding markers at calculated positions
pub fn insert_random_stars_escaped_secure(word: Vec<u8>, key: &[u8]) -> Vec<u8> {
    if word.is_empty() {
        return word;
    }

    // 1. Escape zero bytes (unchanged, already optimized)
    let escaped = escape_zero_bytes(word);
    let lene = escaped.clone().len();
    if escaped.is_empty() {
        return escaped;
    }

    // 2. Generate padding parameters in one go
    let mut padding_params = [0u8; 48]; // 16 (nonce) + 32 (padding_key)
    fill_random(&mut padding_params);
    let (fresh_nonce, _padding_key) = padding_params.split_at_mut(16);

    // Derive padding key (unchanged for security)
    let mut ikm = Vec::with_capacity(key.len() + 16);
    ikm.extend_from_slice(key);
    ikm.extend_from_slice(fresh_nonce);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut derived_padding_key = [0u8; 32];
    hk.expand(b"padding_secure_v2", &mut derived_padding_key)
        .expect("hkdf padding");
    ikm.zeroize();

    // 3. Calculate number of stars (simplified logic)
    let min_stars = escaped.len() / 3;
    let max_stars = (escaped.len() * 2).min(escaped.len() + 65536); // Cap to prevent excessive padding
    let stars_seed = u64::from_le_bytes(derived_padding_key[0..8].try_into().unwrap());
    let num_stars = min_stars + (stars_seed as usize % (max_stars - min_stars + 1));

    // 4. Generate positions in bulk (optimized)
    let mut positions = vec![0usize; num_stars];
    let mut t = 0;
    while t < num_stars {
        let pos_seed = u64::from_le_bytes(derived_padding_key[(t % 4)..][..8].try_into().unwrap())
            .wrapping_add(t as u64)
            .wrapping_add(stars_seed);
        positions[t] = (pos_seed as usize) % (escaped.len() + 1);
        t += 1;
    }
    positions.sort_unstable();

    // 5. Pre-allocate result buffer
    let mut result = Vec::with_capacity(escaped.len() + num_stars * 2);

    // 6. Insert stars and data in a single pass (optimized)
    let mut escaped_idx = 0;
    let mut pos_idx = 0;
    let mut current_pos = 0;
    let mut escaped_iter = escaped.into_iter();
    let star_pair = [0u8; 2]; // Pre-allocated star pair

    while escaped_idx < lene || pos_idx < num_stars {
        // Insert stars if needed
        while pos_idx < num_stars && positions[pos_idx] == current_pos {
            result.extend_from_slice(&star_pair);
            pos_idx += 1;
        }

        // Insert escaped data if available
        if let Some(byte) = escaped_iter.next() {
            result.push(byte);
            escaped_idx += 1;
        }

        current_pos += 1;
    }

    // Insert remaining stars
    while pos_idx < num_stars {
        result.extend_from_slice(&star_pair);
        pos_idx += 1;
    }

    // Zeroize sensitive data
    derived_padding_key.zeroize();
    padding_params.zeroize();

    result
}


