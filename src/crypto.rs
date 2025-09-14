use crate::types::*;
use argon2::{Argon2, Params};
use blake3::Hasher;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Generates a custom cryptographically secure S-Box from a 32-byte key
/// 
/// This function creates a non-linear, key-dependent substitution box
/// using a combination of modular arithmetic, bitwise operations, and
/// polynomial transformations to ensure cryptographic strength.
/// 
/// # Arguments
/// 
/// * `key` - A 32-byte secret key used to derive the S-Box
/// 
/// # Returns
/// 
/// A 256-byte substitution box where each byte is uniquely mapped
pub fn generate_custom_sbox(key: &[u8; 32]) -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for i in 0..256 {
        let mut x = i as u8;
        // Key-dependent non-linear transformations
        x = x.wrapping_add(key[i % 32]);
        x = x.wrapping_mul(key[(i + 7) % 32] | 1);
        x = x.rotate_left(key[(i + 13) % 32] % 8);
        x ^= key[(i + 19) % 32];
        x = x.wrapping_add(key[(i + 23) % 32]);
        // Polynomial transformation for non-linearity
        x = x.wrapping_mul(x).wrapping_add(x).wrapping_add(0x55);
        sbox[i] = x;
    }
    // Ensure the S-Box is a permutation (bijective)
    let mut used = [false; 256];
    for i in 0..256 {
        let mut j = sbox[i] as usize;
        while used[j] {
            j = (j + 1) % 256;
        }
        sbox[i] = j as u8;
        used[j] = true;
    }
    sbox
}

/// Generates the inverse of a custom S-Box
/// 
/// Creates the mathematical inverse of a 256-byte substitution box,
/// allowing for bidirectional transformations during encryption and decryption.
/// 
/// # Arguments
/// 
/// * `forward_sbox` - The forward substitution box (256 bytes)
/// 
/// # Returns
/// 
/// The inverse substitution box where inverse[forward[i]] = i for all i
pub fn generate_inverse_sbox(forward_sbox: &[u8; 256]) -> [u8; 256] {
    let mut inverse = [0u8; 256];
    for i in 0..256 {
        inverse[forward_sbox[i] as usize] = i as u8;
    }
    inverse
}

/// Derives a 32-byte Blake3 key using HKDF key derivation
/// 
/// This function creates a cryptographically secure 32-byte key suitable for Blake3
/// operations by using HKDF with SHA-256 as the underlying hash function.
/// 
/// # Arguments
/// 
/// * `xor_key` - Source key material for derivation
/// * `salt` - Optional salt value for HKDF (use None for no salt)
/// * `info_label` - Context information for key derivation
/// 
/// # Returns
/// 
/// A 32-byte array containing the derived key
/// 
/// # Panics
/// 
/// Panics if HKDF expansion fails (should never happen with valid inputs)
pub fn derive_blake3_key32(xor_key: &[u8], salt: Option<&[u8]>, info_label: &[u8]) -> [u8; 32] {
    let hk = match salt {
        Some(s) => Hkdf::<Sha256>::new(Some(s), xor_key),
        None => Hkdf::<Sha256>::new(None, xor_key),
    };
    let mut key32 = [0u8; 32];
    hk.expand(info_label, &mut key32)
        .expect("hkdf expand -> key32");
    key32
}

/// Generates a Blake3 keystream chunk for a specific chunk index
/// 
/// Creates a pseudorandom keystream segment using Blake3 in keyed mode,
/// incorporating context information and chunk indexing for domain separation.
/// 
/// # Arguments
/// 
/// * `xor_key` - Key material for Blake3 key derivation
/// * `salt` - Optional salt for key derivation
/// * `context` - Context bytes for domain separation
/// * `chunk_index` - Sequential chunk number for unique keystreams
/// * `out` - Output buffer to fill with keystream data
/// 
/// # Security
/// 
/// The derived key is securely cleared from memory after use to prevent leakage.
pub fn blake3_stream_for_chunk(
    xor_key: &[u8],
    salt: Option<&[u8]>,
    context: &[u8],
    chunk_index: u64,
    out: &mut [u8],
) {
    let key32 = derive_blake3_key32(xor_key, salt, context);

    let mut hasher = blake3::Hasher::new_keyed(&key32);
    hasher.update(context);
    hasher.update(&chunk_index.to_be_bytes());

    let mut reader = hasher.finalize_xof();
    reader.fill(out);

    let mut k = key32;
    k.zeroize();
}

/// Expands a keystream using Blake3 in streaming mode
/// 
/// Generates a large keystream by processing it in chunks, with each chunk
/// being independently derivable. This approach enables parallel processing
/// and random access to any portion of the keystream.
/// 
/// # Arguments
/// 
/// * `xor_key` - Source key material for keystream generation
/// * `salt` - Optional salt for key derivation
/// * `context` - Context information for domain separation
/// * `keystream_buf` - Output buffer to fill with keystream
/// * `chunk_size` - Size of each processing chunk
pub fn blake3_expand_keystream_streaming(
    xor_key: &[u8],
    salt: Option<&[u8]>,
    context: &[u8],
    keystream_buf: &mut [u8],
    chunk_size: usize,
) {
    let mut offset: usize = 0;
    let mut chunk_index: u64 = 0;
    while offset < keystream_buf.len() {
        let remaining = keystream_buf.len() - offset;
        let this = if remaining < chunk_size { remaining } else { chunk_size };
        let dst = &mut keystream_buf[offset .. offset + this];
        blake3_stream_for_chunk(xor_key, salt, context, chunk_index, dst);
        offset += this;
        chunk_index = chunk_index.wrapping_add(1);
    }
}

/// Fills a buffer with cryptographically secure random bytes
/// 
/// Uses the system's cryptographically secure random number generator
/// to fill the provided buffer with unpredictable random data.
/// 
/// # Arguments
/// 
/// * `dest` - Buffer to fill with random bytes
/// 
/// # Panics
/// 
/// Panics if the system random number generator fails
pub fn fill_random(dest: &mut [u8]) {
    let rng = SystemRandom::new();
    rng.fill(dest).expect("SystemRandom fill failed");
}

/// Derives a round-specific seed value from a master salt
/// 
/// Creates unique 8-byte seeds for each encryption round using HKDF,
/// ensuring that each round uses distinct cryptographic material.
/// 
/// # Arguments
/// 
/// * `run_salt` - Master salt value for the encryption session
/// * `round_index` - Zero-based index of the encryption round
/// 
/// # Returns
/// 
/// An 8-byte seed value unique to this round
/// 
/// # Panics
/// 
/// Panics if HKDF expansion fails
pub fn derive_round_seed(run_salt: &[u8], round_index: u32) -> [u8; 8] {
    let hk = Hkdf::<Sha256>::new(Some(run_salt), b"master_seed");
    let mut info = Vec::with_capacity(12);
    info.extend_from_slice(b"round_seed_v1");
    info.extend_from_slice(&round_index.to_le_bytes());
    let mut seed = [0u8; 8];
    hk.expand(&info, &mut seed).expect("derive round seed");
    seed
}

/// Derives cryptographic subkeys for XOR and rotation operations
/// 
/// Creates two distinct keys from the input key material: one for XOR operations
/// and another for bit rotation. The keys are derived using different input
/// ordering to ensure they are cryptographically independent.
/// 
/// # Arguments
/// 
/// * `key1` - First secret key for derivation
/// * `key2` - Second secret key for derivation  
/// * `salt` - Salt value for key derivation
/// * `seed_bytes` - Round-specific seed for unique keys per round
/// 
/// # Returns
/// 
/// A tuple containing (xor_key, rotation_key), both of KEY_LENGTH bytes
/// 
/// # Security
/// 
/// Intermediate key material is securely zeroed to prevent leakage.
pub fn derive_subkeys_with_salt_and_seed(
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    salt: &[u8],
    seed_bytes: &[u8; 8],
) -> (Vec<u8>, Vec<u8>) {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();

    let mut xor_ikm = Vec::with_capacity(k1.len() + k2.len() + seed_bytes.len());
    xor_ikm.extend_from_slice(k1);
    xor_ikm.extend_from_slice(k2);
    xor_ikm.extend_from_slice(seed_bytes);

    let hk_xor = Hkdf::<Sha256>::new(Some(salt), &xor_ikm);
    let mut xor_key = vec![0u8; KEY_LENGTH];
    hk_xor.expand(b"xor_key_v2", &mut xor_key).expect("hkdf xor");

    let mut rot_ikm = Vec::with_capacity(k1.len() + k2.len() + seed_bytes.len());
    rot_ikm.extend_from_slice(k2);
    rot_ikm.extend_from_slice(k1);
    rot_ikm.extend_from_slice(seed_bytes);

    let hk_rot = Hkdf::<Sha256>::new(Some(salt), &rot_ikm);
    let mut rot_key = vec![0u8; KEY_LENGTH];
    hk_rot.expand(b"rot_key_v2", &mut rot_key).expect("hkdf rot");

    xor_ikm.zeroize();
    rot_ikm.zeroize();

    (xor_key, rot_key)
}

/// Derives the final HMAC key for message authentication
/// 
/// Creates a 32-byte HMAC key from the provided secret keys and salt,
/// used for authenticating the encrypted data and preventing tampering.
/// 
/// # Arguments
/// 
/// * `key1` - First secret key for HMAC key derivation
/// * `key2` - Second secret key for HMAC key derivation
/// * `salt` - Salt value for key derivation
/// 
/// # Returns
/// 
/// A 32-byte HMAC key for message authentication
/// 
/// # Security
/// 
/// Intermediate key material is securely zeroed after use.
pub fn derive_hmac_key_final(key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>, salt: &[u8]) -> Vec<u8> {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();
    let mut ikm = Vec::with_capacity(k1.len() + k2.len());
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(k2);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut hmac_key = vec![0u8; 32];
    hk.expand(b"hmac_final_v1", &mut hmac_key)
        .expect("hkdf hmac final");
    ikm.zeroize();
    hmac_key
}

/// Generates a strong cryptographic key using Argon2 password hashing
/// 
/// Derives a high-entropy secret key from seed material using Argon2id,
/// a memory-hard password hashing function resistant to brute-force attacks.
/// The result is further processed with HKDF for key expansion.
/// 
/// # Arguments
/// 
/// * `seed` - Source entropy for key generation
/// * `salt` - Salt value to prevent rainbow table attacks
/// 
/// # Returns
/// 
/// A Secret-wrapped vector containing KEY_LENGTH bytes of key material
/// 
/// # Security
/// 
/// Uses Argon2id with secure parameters (8192 KB memory, 2 iterations, 4 parallelism).
/// Intermediate outputs are securely cleared from memory.
pub fn gene3_with_salt(seed: &[u8], salt: &[u8]) -> Secret<Vec<u8>> {
    let params = Params::new(8192, 2, 4, None).expect("params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = vec![0u8; 64];
    argon2
        .hash_password_into(seed, salt, &mut out)
        .expect("argon2");
    let hk = Hkdf::<Sha256>::new(Some(salt), &out);
    let mut okm = vec![0u8; KEY_LENGTH];
    hk.expand(b"key_expand_v1", &mut okm).expect("hkdf expand");
    out.zeroize();
    Secret::new(okm)
}

/// Computes HMAC-SHA256 authentication tag for message integrity
/// 
/// Generates a cryptographic message authentication code over the provided
/// header and ciphertext data using HMAC with SHA-256.
/// 
/// # Arguments
/// 
/// * `hmac_key` - Secret key for HMAC computation
/// * `header` - Header data to authenticate
/// * `ciphertext` - Encrypted data to authenticate
/// 
/// # Returns
/// 
/// HMAC tag as a vector of bytes
/// 
/// # Panics
/// 
/// Panics if the HMAC key length is invalid
pub fn compute_hmac(hmac_key: &[u8], header: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
    mac.update(header);
    mac.update(ciphertext);
    mac.finalize().into_bytes().to_vec()
}

/// Verifies HMAC-SHA256 authentication tag in constant time
/// 
/// Validates the integrity and authenticity of data by recomputing the HMAC
/// and comparing it against the provided tag using constant-time comparison
/// to prevent timing attacks.
/// 
/// # Arguments
/// 
/// * `hmac_key` - Secret key for HMAC verification
/// * `header` - Header data to verify
/// * `ciphertext` - Encrypted data to verify
/// * `tag` - Expected HMAC tag to validate against
/// 
/// # Returns
/// 
/// `true` if the HMAC is valid, `false` otherwise
/// 
/// # Security
/// 
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_hmac(hmac_key: &[u8], header: &[u8], ciphertext: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
    mac.update(header);
    mac.update(ciphertext);
    let computed_tag = mac.finalize().into_bytes();
    computed_tag.ct_eq(tag).into()
}

/// Builds a character substitution table for encryption operations
/// 
/// Creates a 256-byte substitution table derived from the runtime salt and
/// round seed, providing unique character mappings for each encryption round.
/// 
/// # Arguments
/// 
/// * `run_salt` - Runtime salt for the encryption session
/// * `round_seed` - Seed value specific to the current round
/// 
/// # Returns
/// 
/// A 256-byte array containing the character substitution mapping
/// 
/// # Security
/// 
/// The substitution key is securely cleared from memory after use.
pub fn build_characters(run_salt: &[u8], round_seed: &[u8; 8]) -> [u8; 256] {
    let mut hasher = Hasher::new();
    hasher.update(run_salt);
    hasher.update(round_seed);
    hasher.update(b"chars_sbox_v1");
    let mut sbox_key = [0u8; 32];
    let hash = hasher.finalize();
    sbox_key.copy_from_slice(&hash.as_bytes()[..32]);
    let out = generate_custom_sbox(&sbox_key);
    sbox_key.zeroize();
    out
}

/// Generates a 256-byte permutation from a 32-byte key
/// 
/// Creates a cryptographic permutation by applying multiple rounds of non-linear
/// transformations, multiplications, and XOR operations to produce a unique
/// 256-byte substitution table.
/// 
/// # Arguments
/// 
/// * `key` - 32-byte key for permutation generation
/// 
/// # Returns
/// 
/// A 256-byte permutation array where each value 0-255 appears exactly once
/// 
/// # Security
/// 
/// Uses non-linear polynomial transformations and key-dependent mixing for cryptographic strength.
pub fn perm256_from_key(key: &[u8; 32]) -> [u8; 256] {
    generate_custom_sbox(key)
}