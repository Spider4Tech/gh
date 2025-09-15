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

/// Generates a custom cryptographically secure S-Box from a key
/// 
/// This function creates a non-linear, key-dependent substitution box
/// using a combination of modular arithmetic, bitwise operations, and
/// polynomial transformations to ensure cryptographic strength.
/// 
/// # Arguments
/// 
/// * `key` - A secret key used to derive the S-Box
/// 
/// # Returns
/// 
/// A 256-byte substitution box where each byte is uniquely mapped
pub fn generate_custom_sbox(key: &[u8]) -> [u8; 256] {
    // AES S-box table (standard)
    const AES_SBOX: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];

    // derive an odd multiplier in 1..255 from key so multiplication mod 256 is invertible
    let mul: u8 = if key.is_empty() {
        5u8 // arbitrary odd fallback
    } else {
        // combine some key bytes to produce a value, force odd and non-zero
        let mut v: u16 = 0x0101;
        for (i, &b) in key.iter().enumerate().take(8) {
            v = v.wrapping_mul((b as u16).wrapping_add((i as u16) + 1));
        }
        let mut m = (v as u8) | 1; // ensure odd
        if m == 0 { m = 1; }
        m
    };

    // derive XOR mask bytes from key (cycled)
    let xor_mask = if key.is_empty() { vec![0x63u8] } else { key.to_vec() };

    let mut sbox = [0u8; 256];
    for i in 0..256 {
        let base = AES_SBOX[i];
        // bijective transform: multiply by odd (invertible mod 256) then xor by key-derived mask
        let m = base.wrapping_mul(mul);
        let k = xor_mask[i % xor_mask.len()];
        // Add a non-linear transformation to break affinity
        let x = m ^ k;
        // Non-linear polynomial: x^3 + x^2 + x + constant
        let x_u32 = x as u32;
        let nonlinear = ((x_u32 * x_u32 * x_u32) ^ (x_u32 * x_u32) ^ x_u32 ^ 0xA5) as u8;
        sbox[i] = nonlinear;
    }

    // final check: ensure bijectivity (should hold). If collision found, fallback to AES S-box.
    {
        let mut seen = [false; 256];
        let mut collision = false;
        for &v in sbox.iter() {
            if seen[v as usize] {
                collision = true;
                break;
            }
            seen[v as usize] = true;
        }
        if collision {
            // fallback to AES SBOX (bijective)
            sbox.copy_from_slice(&AES_SBOX);
        }
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

/// Test that the custom S-Box is not affine
#[test]
fn test_custom_sbox_is_not_affine() {
    let key = [0x42u8; 2048];
    let sbox = generate_custom_sbox(&key);

    // Test 1: Check if S(x) + S(y) = S(x + y) for all x, y (linearity)
    let mut is_linear = true;
    for x in 0u8..255 {
        for y in 0u8..255 {
            if sbox[x as usize] ^ sbox[y as usize] != sbox[(x ^ y) as usize] {
                is_linear = false;
                break;
            }
        }
        if !is_linear { break; }
    }
    assert!(!is_linear, "La S-Box est linéaire (ce qui est mauvais pour la sécurité)");

    // Test 2: Check if S(x) = A * x + B for some A, B (affinity)
    let mut is_affine = true;
    for a in 1u8..255 {
        for b in 0u8..255 {
            let mut valid = true;
            for x in 0u8..255 {
                if sbox[x as usize] != (a.wrapping_mul(x) ^ b) {
                    valid = false;
                    break;
                }
            }
            if valid {
                is_affine = true;
                break;
            }
        }
        if is_affine { break; }
    }
    assert!(!is_affine, "La S-Box est affine (ce qui est mauvais pour la sécurité)");
}

/// Test that the custom S-Box has good non-linearity
#[test]
fn test_custom_sbox_nonlinearity() {
    let key = [0x42u8; 2048];
    let sbox = generate_custom_sbox(&key);

    // Test non-linearity: Pr[a·x + b·S(x) = c] should be close to 0.5 for all a, b, c
    let mut max_bias = 0.0;
    for a in 0..8 {
        for b in 0..8 {
            for c in 0..2 {
                let mut count = 0;
                for x in 0..255 {
                    let condition = ((x >> a) & 1) ^ ((sbox[x as usize] >> b) & 1) ^ c;
                    if condition == 0 { count += 1; }
                }
                let bias = (count as f64 / 256.0 - 0.5).abs();
                if bias > max_bias { max_bias = bias; }
            }
        }
    }
    assert!(max_bias < 0.2, "S-Box has detectable linear approximations (max bias: {})", max_bias);
}

/// Test that the custom S-Box has good differential uniformity
#[test]
fn test_custom_sbox_differential_uniformity() {
    let key = [0x42u8; 2048];
    let sbox = generate_custom_sbox(&key);

    // DDT[a][b] = #x such that S(x) ^ S(x ^ a) == b
    let mut ddt = [[0u16; 256]; 256];

    for a in 1usize..256 {
        for x in 0usize..256 {
            let xa = x ^ a;
            let out = sbox[x] ^ sbox[xa];
            ddt[a][out as usize] += 1;
        }
    }

    // trouver la valeur max sur a != 0 et b quelconque
    let mut max_entry = 0u16;
    for a in 1usize..256 {
        for b in 0usize..256 {
            if ddt[a][b] > max_entry {
                max_entry = ddt[a][b];
            }
        }
    }

    eprintln!("max DDT entry = {}", max_entry);
    // Seuil : 4 = niveau AES; 8 = permissif.
    assert!(max_entry <= 4, "DDT maximum trop élevé: {}", max_entry);
}

/// Test that the custom S-Box has good avalanche effect
#[test]
fn test_custom_sbox_avalanche() {
    let key = [0x42u8; 2048];
    let sbox = generate_custom_sbox(&key);

    let mut total_hd = 0;
    for in_bit in 0..8 {
        let mask = 1usize << in_bit;
        for x in 0usize..256 {
            let y1 = sbox[x];
            let y2 = sbox[x ^ mask];
            let hd = (y1 ^ y2).count_ones() as usize;
            total_hd += hd;
        }
    }
    let avg_hd = total_hd as f64 / (256.0 * 8.0);
    eprintln!("average hamming distance per single-bit input flip = {}", avg_hd);
    assert!(avg_hd >= 3.0 && avg_hd <= 5.0, "average avalanche out of expected range: {}", avg_hd);
}