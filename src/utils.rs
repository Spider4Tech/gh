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
    let escaped = escape_zero_bytes(word);

    let mut fresh_nonce = [0u8; 16];
    fill_random(&mut fresh_nonce);

    let mut ikm = Vec::with_capacity(key.len() + fresh_nonce.len());
    ikm.extend_from_slice(key);
    ikm.extend_from_slice(&fresh_nonce);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut padding_key = [0u8; 32];
    hk.expand(b"padding_secure_v2", &mut padding_key).expect("hkdf padding");

    ikm.zeroize();
    fresh_nonce.zeroize();

    let min = (escaped.len() / 3) as u64;
    let max = (escaped.len() * 2) as u64;
    let range = if max > min { max - min + 1 } else { 1 };
    let stars_seed = u64::from_le_bytes([
        padding_key[0], padding_key[1], padding_key[2], padding_key[3],
        padding_key[4], padding_key[5], padding_key[6], padding_key[7],
    ]);
    let num_stars = (min + (stars_seed % range)) as usize;

    let mut positions: Vec<usize> = Vec::with_capacity(num_stars);
    let mut t = 0usize;
    while t < num_stars {
        let pos_seed = u64::from_le_bytes([
            padding_key[(t * 8) % 32], padding_key[(t * 8 + 1) % 32],
            padding_key[(t * 8 + 2) % 32], padding_key[(t * 8 + 3) % 32],
            padding_key[(t * 8 + 4) % 32], padding_key[(t * 8 + 5) % 32],
            padding_key[(t * 8 + 6) % 32], padding_key[(t * 8 + 7) % 32],
        ]) ^ (t as u64);
        let pos = (pos_seed as usize) % (escaped.len() + 1);
        positions.push(pos);
        t += 1;
    }
    positions.sort_unstable();

    let output_len = escaped.len() + (num_stars * 2);
    let mut result = Vec::with_capacity(output_len);
    let mut escaped_idx = 0;
    let mut pos_idx = 0;
    let mut current_pos = 0;

    while escaped_idx < escaped.len() || pos_idx < positions.len() {
        while pos_idx < positions.len() && positions[pos_idx] == current_pos {
            result.push(0u8);
            result.push(0u8);
            pos_idx += 1;
        }

        if escaped_idx < escaped.len() {
            result.push(escaped[escaped_idx]);
            escaped_idx += 1;
        }

        current_pos += 1;
    }

    while pos_idx < positions.len() {
        result.push(0u8);
        result.push(0u8);
        pos_idx += 1;
    }

    padding_key.zeroize();
    result
}