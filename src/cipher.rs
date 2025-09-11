use crate::crypto::*;
use crate::types::*;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
use std::error::Error;
use std::time::Instant;
use zeroize::Zeroize;

/// Performs constant-time lookup in a 256-byte table
/// 
/// This function provides timing attack resistance by ensuring that the execution
/// time is independent of the index value. All 256 table positions are accessed
/// in every call, preventing information leakage through timing channels.
/// 
/// # Arguments
/// 
/// * `table` - The 256-byte lookup table
/// * `index` - The index to look up (0-255)
/// 
/// # Returns
/// 
/// The value at the specified index in the table
/// 
/// # Security
/// 
/// This implementation prevents timing side-channel attacks by processing
/// the table in fixed-size chunks and using bitwise masks rather than
/// conditional branching.
#[inline]
pub fn constant_time_lookup_256(table: &[u8; 256], index: u8) -> u8 {
    let mut result = 0u8;
    let idx = index as usize;

    let mut i = 0usize;
    while i < 256 {
        let mask0 = if i == idx { 0xFF } else { 0x00 };
        let mask1 = if i + 1 == idx { 0xFF } else { 0x00 };
        let mask2 = if i + 2 == idx { 0xFF } else { 0x00 };
        let mask3 = if i + 3 == idx { 0xFF } else { 0x00 };

        result |= table[i] & mask0;
        if i + 1 < 256 { result |= table[i + 1] & mask1; }
        if i + 2 < 256 { result |= table[i + 2] & mask2; }
        if i + 3 < 256 { result |= table[i + 3] & mask3; }

        i += 4;
    }
    result
}

/// Performs constant-time lookup in a position array
/// 
/// Finds the position value for a given character value in constant time,
/// providing protection against timing side-channel attacks.
/// 
/// # Arguments
/// 
/// * `positions` - Array of 256 position values
/// * `value` - The value to find the position for (0-255)
/// 
/// # Returns
/// 
/// The position corresponding to the input value
/// 
/// # Security
/// 
/// Uses constant-time execution to prevent timing attacks by accessing
/// all array elements regardless of the target value.
#[inline] 
pub fn constant_time_position_lookup(positions: &[usize; 256], value: u8) -> usize {
    let mut result = 0usize;
    let val = value as usize;

    let mut i = 0usize;
    while i < 256 {
        let mask0 = if i == val { usize::MAX } else { 0 };
        let mask1 = if i + 1 == val { usize::MAX } else { 0 };
        let mask2 = if i + 2 == val { usize::MAX } else { 0 };
        let mask3 = if i + 3 == val { usize::MAX } else { 0 };

        result |= positions[i] & mask0;
        if i + 1 < 256 { result |= positions[i + 1] & mask1; }
        if i + 2 < 256 { result |= positions[i + 2] & mask2; }
        if i + 3 < 256 { result |= positions[i + 3] & mask3; }

        i += 4;
    }
    result
}

/// Performs constant-time character lookup by index
/// 
/// Retrieves a character from the character array using constant-time execution
/// to prevent timing side-channel attacks that could reveal the lookup index.
/// 
/// # Arguments
/// 
/// * `characters` - Array of 256 character values
/// * `index` - The index to look up (0-255)
/// 
/// # Returns
/// 
/// The character at the specified index
/// 
/// # Security
/// 
/// Processes the entire character array in chunks to ensure constant execution
/// time regardless of the target index value.
#[inline]
pub fn constant_time_character_lookup(characters: &[u8; 256], index: usize) -> u8 {
    let mut result = 0u8;

    let mut i = 0usize;
    while i < 256 {
        let mask0 = if i == index { 0xFF } else { 0x00 };
        let mask1 = if i + 1 == index { 0xFF } else { 0x00 };
        let mask2 = if i + 2 == index { 0xFF } else { 0x00 };
        let mask3 = if i + 3 == index { 0xFF } else { 0x00 };

        result |= characters[i] & mask0;
        if i + 1 < 256 { result |= characters[i + 1] & mask1; }
        if i + 2 < 256 { result |= characters[i + 2] & mask2; }
        if i + 3 < 256 { result |= characters[i + 3] & mask3; }

        i += 4;
    }
    result
}

/// Builds an inverse lookup table from a forward substitution table
/// 
/// Creates the mathematical inverse of a 256-byte substitution table,
/// allowing for bidirectional transformations during encryption and decryption.
/// 
/// # Arguments
/// 
/// * `forward_row` - The forward substitution table (256 bytes)
/// 
/// # Returns
/// 
/// The inverse substitution table where inverse[forward[i]] = i for all i
/// 
/// # Note
/// 
/// The input table must be a valid permutation (each value 0-255 appears exactly once)
/// for the inverse to be mathematically correct.
pub fn build_inverse_lookup(forward_row: &[u8; 256]) -> [u8; 256] {
    let mut inverse = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inverse[forward_row[i] as usize] = i as u8;
        i += 1;
    }
    inverse
}

/// Generates a substitution row for the cipher matrix
/// 
/// Creates a unique 256-byte substitution table for a specific position
/// in the cipher matrix, derived from salt, seed, and coordinate parameters.
/// 
/// # Arguments
/// 
/// * `salt` - Salt value for key derivation
/// * `seed` - Seed value for this generation
/// * `table_2d` - 2D table coordinate
/// * `row` - Row coordinate within the table
/// 
/// # Returns
/// 
/// A 256-byte substitution table unique to the given parameters
/// 
/// # Security
/// 
/// The transformation key is securely cleared from memory after use.
pub fn generate_row_direct(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> [u8; 256] {
    let mut ikm = [0u8; 24];
    ikm[0..8].copy_from_slice(&seed.to_le_bytes());
    ikm[8..16].copy_from_slice(&(table_2d as u64).to_le_bytes());
    ikm[16..24].copy_from_slice(&(row as u64).to_le_bytes());
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), &ikm);
    let mut transform_key = [0u8; 32];
    hk.expand(b"sbox_key_v1", &mut transform_key)
        .expect("hkdf sbox key");
    let sbox = perm256_from_key(&transform_key);
    transform_key.zeroize();
    sbox
}

/// Applies bit rotation to data using a rotation key in parallel
/// 
/// Performs left bit rotation on each byte of the input buffer, with the
/// rotation amount determined by the corresponding rotation key bytes.
/// Processing is done in parallel chunks for improved performance.
/// 
/// # Arguments
/// 
/// * `buf` - Data buffer to rotate (consumed and returned)
/// * `rot_key` - Key determining rotation amounts for each byte
/// 
/// # Returns
/// 
/// The input buffer with bit rotations applied
/// 
/// # Performance
/// 
/// Uses parallel processing with Rayon for improved throughput on multi-core systems.
pub fn shift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    buf.par_chunks_mut(OPTIMAL_CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * OPTIMAL_CHUNK_SIZE;
            let mut i = 0usize;
            while i < chunk.len() {
                let idx = base_idx + i;
                let amount = (rot_key[idx % rot_key.len()] & 0x07) as u32;
                chunk[i] = chunk[i].rotate_left(amount);
                i += 1;
            }
        });
    buf
}

/// Reverses bit rotation applied by shift_bits_with_rot_key_par
/// 
/// Performs right bit rotation to undo the left rotations applied during
/// encryption. Uses the same rotation key to ensure perfect reversal.
/// Processing is done in parallel chunks for optimal performance.
/// 
/// # Arguments
/// 
/// * `buf` - Data buffer to unrotate (consumed and returned)
/// * `rot_key` - Key determining rotation amounts (same as used for shifting)
/// 
/// # Returns
/// 
/// The input buffer with bit rotations reversed
/// 
/// # Performance
/// 
/// Uses parallel processing with Rayon for improved throughput on multi-core systems.
pub fn unshift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    buf.par_chunks_mut(OPTIMAL_CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * OPTIMAL_CHUNK_SIZE;
            let mut i = 0usize;
            while i < chunk.len() {
                let idx = base_idx + i;
                let amount = (rot_key[idx % rot_key.len()] & 0x07) as u32;
                chunk[i] = chunk[i].rotate_right(amount);
                i += 1;
            }
        });
    buf
}

/// Builds coordinate pairs for cipher table generation
/// 
/// Creates a list of unique coordinate pairs derived from key character data,
/// used to determine which substitution tables to generate for the cipher cache.
/// 
/// # Arguments
/// 
/// * `key1_chars` - Character indices from the first key
/// * `key2_chars` - Character indices from the second key
/// * `len` - Length of data being processed
/// 
/// # Returns
/// 
/// A sorted, deduplicated vector of coordinate pairs for table generation
/// 
/// # Performance
/// 
/// The result is sorted and deduplicated to minimize cache size and
/// eliminate redundant table generation.
#[inline]
pub fn build_pairs(key1_chars: &[usize], key2_chars: &[usize], len: usize) -> Vec<(u16, u16)> {
    let mut v = Vec::with_capacity(len.min(65536));
    let mut i = 0usize;
    while i < len {
        let table_2d = (key1_chars[i % key1_chars.len()] & 0xFF) as u16;
        let row = (key2_chars[i % key2_chars.len()] & 0xFF) as u16;
        v.push((table_2d, row));
        i += 1;
    }
    v.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    v.dedup();
    v
}

/// Builds local cipher row cache with parallel generation
/// 
/// Generates substitution tables for the specified coordinate pairs in parallel,
/// along with an index mapping for fast lookup during encryption/decryption operations.
/// 
/// # Arguments
/// 
/// * `salt` - Salt value for row generation
/// * `seed` - Seed value for randomization
/// * `pairs` - Coordinate pairs specifying which tables to generate
/// 
/// # Returns
/// 
/// A tuple containing:
/// - Vector of generated substitution rows
/// - Index mapping for efficient table lookup
/// 
/// # Performance
/// 
/// Uses parallel processing with Rayon to generate multiple tables simultaneously.
#[inline]
pub fn build_row_cache_local(
    salt: &[u8],
    seed: u64,
    pairs: &[(u16, u16)],
) -> (Vec<[u8; 256]>, Vec<usize>) {
    let mut rows: Vec<[u8; 256]> = vec![[0u8; 256]; pairs.len()];
    rows.par_iter_mut()
        .zip(pairs.par_iter().cloned())
        .for_each(|(slot, (i, j))| {
            *slot = generate_row_direct(salt, seed, i as usize, j as usize);
        });
    let mut map = vec![usize::MAX; 256 * 256];
    let mut idx = 0usize;
    while idx < pairs.len() {
        let (i, j) = pairs[idx];
        map[((i as usize) << 8) | (j as usize)] = idx;
        idx += 1;
    }
    (rows, map)
}

/// Builds or retrieves a cipher cache for encryption/decryption operations
/// 
/// Creates a comprehensive cache containing substitution tables, character mappings,
/// and index structures needed for high-performance cipher operations. Uses global
/// caching to avoid regenerating identical caches.
/// 
/// # Arguments
/// 
/// * `key1` - First secret key for cipher generation
/// * `key2` - Second secret key for cipher generation
/// * `run_salt` - Runtime salt for this encryption session
/// * `round_seed` - Seed specific to the current encryption round
/// * `data_len` - Length of data to be processed
/// 
/// # Returns
/// 
/// A complete cipher cache ready for encryption/decryption operations
/// 
/// # Performance
/// 
/// Uses global caching and parallel processing to minimize computation time.
/// Cache hits avoid expensive regeneration of substitution tables.
pub fn build_cipher_cache(
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    run_salt: &[u8],
    round_seed: &[u8; 8],
    data_len: usize,
) -> CipherCache {
    let mut cache_key = CacheKey {
        run_salt: [0u8; 32],
        round_seed: *round_seed,
        data_len,
    };
    cache_key.run_salt.copy_from_slice(run_salt);

    if let Some(cached) = CIPHER_CACHE_STORE.get(&cache_key) {
        println!("  - Using cached cipher cache");
        return cached.clone();
    }

    let start_total = Instant::now();
    println!("  - Building new cipher cache");

    let characters = build_characters(run_salt, round_seed);
    let mut char_positions = [0usize; 256];
    let mut i = 0usize;
    while i < 256 {
        char_positions[characters[i] as usize] = i;
        i += 1;
    }

    let k1_ref = key1.expose_secret();
    let k2_ref = key2.expose_secret();
    let (key1_chars, key2_chars) = rayon::join(
        || {
            k1_ref
                .par_iter()
                .map(|&c| (c as usize) & 0xFF)
                .collect::<Vec<_>>()
        },
        || {
            k2_ref
                .par_iter()
                .map(|&c| (c as usize) & 0xFF)
                .collect::<Vec<_>>()
        },
    );

    let pairs = build_pairs(&key1_chars, &key2_chars, data_len);

    let (rows, index_map) = build_row_cache_local(run_salt, u64::from_le_bytes(*round_seed), &pairs);

    let inverse_rows: Vec<[u8; 256]> = rows
        .par_iter()
        .map(build_inverse_lookup)
        .collect();

    let cache = CipherCache {
        rows,
        index_map,
        inverse_rows,
        char_positions,
        characters,
        key1_chars,
        key2_chars,
    };

    if CIPHER_CACHE_STORE.len() < 16 {
        CIPHER_CACHE_STORE.insert(cache_key, cache.clone());
    }

    println!("  - Cache building total: {:?}", start_total.elapsed());
    cache
}

/// Core encryption function with optimized performance
/// 
/// Encrypts plaintext using the cipher cache, XOR keystream, and substitution tables.
/// Processes data in chunks with parallel execution for optimal performance.
/// 
/// # Arguments
/// 
/// * `plain_text` - Data to encrypt
/// * `cache` - Pre-built cipher cache containing substitution tables
/// * `xor_key` - Key for keystream generation
/// * `run_salt` - Runtime salt for keystream derivation
/// 
/// # Returns
/// 
/// Encrypted ciphertext as a vector of bytes
/// 
/// # Performance
/// 
/// Uses parallel processing with Rayon and chunked keystream generation
/// for maximum throughput on multi-core systems.
pub fn encrypt_core_optimized(
    plain_text: Vec<u8>,
    cache: &CipherCache,
    xor_key: &[u8],
    run_salt: &[u8],
) -> Vec<u8> {
    if plain_text.is_empty() {
        return Vec::new();
    }

    let mut cipher_text = vec![0u8; plain_text.len()];

    let mut offset: usize = 0;
    let mut chunk_index: u64 = 0;

    while offset < plain_text.len() {
        let remaining = plain_text.len() - offset;
        let this = std::cmp::min(remaining, BLAKE3_KEYSTREAM_CHUNK);

        let mut keystream = vec![0u8; this];
        blake3_stream_for_chunk(xor_key, Some(run_salt), b"xor_stream_v1", chunk_index, &mut keystream);

        {
            let src = &plain_text[offset..offset + this];
            let dst = &mut cipher_text[offset..offset + this];

            dst.par_iter_mut()
                .zip(src.par_iter())
                .zip(keystream.par_iter())
                .enumerate()
                .for_each(|(i, ((d, &s), &k))| {
                    let pos = offset + i;
                    let table_2d = cache.key1_chars[pos % cache.key1_chars.len()] & 0xFF;
                    let row = cache.key2_chars[pos % cache.key2_chars.len()] & 0xFF;
                    let map_index = (table_2d << 8) | row;

                    if let Some(&row_idx) = cache.index_map.get(map_index) {
                        if row_idx != usize::MAX {
                            let transformed = constant_time_lookup_256(&cache.rows[row_idx], s);
                            *d = transformed ^ k;
                        } else {
                            *d = s ^ k;
                        }
                    } else {
                        *d = s ^ k;
                    }
                });
        }

        keystream.zeroize();
        offset += this;
        chunk_index = chunk_index.wrapping_add(1);
    }

    cipher_text
}

/// Core decryption function with optimized performance
/// 
/// Decrypts ciphertext using the cipher cache, XOR keystream, and inverse substitution tables.
/// Mirrors the encryption process in reverse for perfect data recovery.
/// 
/// # Arguments
/// 
/// * `cipher_text` - Data to decrypt
/// * `cache` - Pre-built cipher cache containing inverse substitution tables
/// * `xor_key` - Key for keystream generation (same as used for encryption)
/// * `run_salt` - Runtime salt for keystream derivation (same as used for encryption)
/// 
/// # Returns
/// 
/// Decrypted plaintext as a vector of bytes
/// 
/// # Performance
/// 
/// Uses parallel processing with Rayon and chunked keystream generation
/// for maximum throughput on multi-core systems.
pub fn decrypt_core_optimized(
    cipher_text: Vec<u8>,
    cache: &CipherCache,
    xor_key: &[u8],
    run_salt: &[u8],
) -> Vec<u8> {
    if cipher_text.is_empty() {
        return Vec::new();
    }

    let mut plain_text = vec![0u8; cipher_text.len()];

    let mut offset: usize = 0;
    let mut chunk_index: u64 = 0;

    while offset < cipher_text.len() {
        let remaining = cipher_text.len() - offset;
        let this = std::cmp::min(remaining, BLAKE3_KEYSTREAM_CHUNK);

        let mut keystream = vec![0u8; this];
        blake3_stream_for_chunk(xor_key, Some(run_salt), b"xor_stream_v1", chunk_index, &mut keystream);

        {
            let src = &cipher_text[offset..offset + this];
            let dst = &mut plain_text[offset..offset + this];

            dst.par_iter_mut()
                .zip(src.par_iter())
                .zip(keystream.par_iter())
                .enumerate()
                .for_each(|(i, ((d, &s), &k))| {
                    let pos = offset + i;
                    let table_2d = cache.key1_chars[pos % cache.key1_chars.len()] & 0xFF;
                    let row = cache.key2_chars[pos % cache.key2_chars.len()] & 0xFF;
                    let map_index = (table_2d << 8) | row;

                    let xor_result = s ^ k;

                    if let Some(&row_idx) = cache.index_map.get(map_index) {
                        if row_idx != usize::MAX {
                            *d = constant_time_lookup_256(&cache.inverse_rows[row_idx], xor_result);
                        } else {
                            *d = xor_result;
                        }
                    } else {
                        *d = xor_result;
                    }
                });
        }

        keystream.zeroize();
        offset += this;
        chunk_index = chunk_index.wrapping_add(1);
    }

    plain_text
}

pub fn encrypt3_final(
    data: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    round_keys: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut run_salt = [0u8; SALT_LEN];
    fill_random(&mut run_salt);

    let mut body = data;

    let rounds = std::cmp::min(ROUND, round_keys.len());
    println!("Encrypting {} rounds", rounds);

    let mut r = 0usize;
    while r < rounds {
        println!("  Round {}", r + 1);
        let round_seed = derive_round_seed(&run_salt, r as u32);
        
        let (xor_key, rot_key) = derive_subkeys_with_salt_and_seed(key1, key2, &run_salt, &round_seed);

        let cache = build_cipher_cache(key1, key2, &run_salt, &round_seed, body.len());

        let start_enc = Instant::now();
        body = encrypt_core_optimized(body, &cache, &xor_key, &run_salt);
        println!("    Core encryption: {:?}", start_enc.elapsed());

        let start_shift = Instant::now();
        body = shift_bits_with_rot_key_par(body, &rot_key);
        println!("    Bit shift: {:?}", start_shift.elapsed());

        r += 1;
    }

    let hmac_key = derive_hmac_key_final(key1, key2, &run_salt);

    let mut header = Vec::with_capacity(SALT_LEN + 2);
    header.extend_from_slice(&run_salt);
    header.push(VERSION);
    header.push(ALG_ID);

    let hmac_tag = compute_hmac(&hmac_key, &header, &body);

    let mut output = Vec::with_capacity(header.len() + body.len() + hmac_tag.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&body);
    output.extend_from_slice(&hmac_tag);

    Ok(output)
}

pub fn decrypt3_final(
    encrypted_data: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    round_keys: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if encrypted_data.len() < SALT_LEN + 2 + 32 {
        return Err("Data too short".into());
    }

    let mut run_salt = [0u8; SALT_LEN];
    run_salt.copy_from_slice(&encrypted_data[0..SALT_LEN]);
    
    let version = encrypted_data[SALT_LEN];
    let alg_id = encrypted_data[SALT_LEN + 1];

    if version != VERSION || alg_id != ALG_ID {
        return Err("Invalid version or algorithm ID".into());
    }

    let split_point = encrypted_data.len() - 32;
    let header = &encrypted_data[0..SALT_LEN + 2];
    let body = &encrypted_data[SALT_LEN + 2..split_point];
    let hmac_tag = &encrypted_data[split_point..];

    let hmac_key = derive_hmac_key_final(key1, key2, &run_salt);
    if !verify_hmac(&hmac_key, header, body, hmac_tag) {
        return Err("HMAC verification failed".into());
    }

    let mut plaintext = body.to_vec();

    let rounds = std::cmp::min(ROUND, round_keys.len());
    println!("Decrypting {} rounds", rounds);

    let mut r = (rounds as i32) - 1;
    while r >= 0 {
        println!("  Round {}", r + 1);
        let round_seed = derive_round_seed(&run_salt, r as u32);
        
        let (xor_key, rot_key) = derive_subkeys_with_salt_and_seed(key1, key2, &run_salt, &round_seed);

        let start_unshift = Instant::now();
        plaintext = unshift_bits_with_rot_key_par(plaintext, &rot_key);
        println!("    Bit unshift: {:?}", start_unshift.elapsed());

        let cache = build_cipher_cache(key1, key2, &run_salt, &round_seed, plaintext.len());

        let start_dec = Instant::now();
        plaintext = decrypt_core_optimized(plaintext, &cache, &xor_key, &run_salt);
        println!("    Core decryption: {:?}", start_dec.elapsed());

        r -= 1;
    }

    Ok(plaintext)
}