# Horizon Cryptographic Library

**A high-performance, secure, and parallelized cryptographic library for Rust, optimized for modern hardware and resistant to side-channel attacks.**

[![Crates.io](https://img.shields.io/crates/v/horizon.svg)](https://crates.io/crates/horizon)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://github.com/Spider4Tech/gh/actions/workflows/rust.yml/badge.svg)](https://github.com/Spider4Tech/gh/actions/workflows/rust.yml)
[![Clippy](https://github.com/Spider4Tech/gh/actions/workflows/clippy.yml/badge.svg)](https://github.com/Spider4Tech/gh/actions/workflows/clippy.yml)

---

## **Overview**

**Horizon** is a Rust cryptographic library designed for **high-performance, secure data encryption and decryption**, with a focus on **parallelism, constant-time operations, and resistance to timing attacks**. It is ideal for applications requiring **strong cryptographic guarantees** while maintaining **optimal performance** on modern multi-core hardware.

### **Key Features**
| Feature                     | Description                                                                                     |
|-----------------------------|-------------------------------------------------------------------------------------------------|
| **Custom S-Box Generation** | Key-dependent, bijective substitution boxes using GF(256) arithmetic and BLAKE3-based derivation. |
| **Parallel Processing**     | Uses `rayon` for multi-core optimization, chunked data processing, and cache-efficient operations. |
| **Constant-Time Operations**| All lookups and transformations are constant-time to prevent side-channel attacks.           |
| **HMAC-SHA256**             | Ensures message integrity and authenticity.                                                 |
| **BLAKE3 Keystream**        | Fast, cryptographically secure keystream generation.                                         |
| **Secure Memory Handling**  | Zeroization of sensitive data to prevent memory leaks.                                       |
| **Optimized Caching**       | Global, thread-safe cache for substitution tables and round parameters.                        |
| **Linear Cryptanalysis**     | Built-in tests to ensure S-box resistance to linear cryptanalysis (max bias < 0.10).           |

---

## **Installation**

Add `horizon` to your `Cargo.toml`:

```toml
[dependencies]
horizon = "0.9.5"
```

Or via `cargo add`:

```sh
cargo add horizon
```

---

## **Usage**

### **Basic Encryption/Decryption**

```rust
use horizon::{encrypt3_final, decrypt3_final, gene3_with_salt, fill_random};
use secrecy::ExposeSecret;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a cryptographically secure salt
    let mut salt = [0u8; 32];
    fill_random(&mut salt);

    // 2. Derive master keys using Argon2id and HKDF
    let seed = b"my_secure_seed";
    let key1 = gene3_with_salt(seed, &salt);
    let key2 = gene3_with_salt(key1.expose_secret(), &salt);

    // 3. Generate round keys (5 rounds in this example)
    let mut round_keys = Vec::new();
    for _ in 0..5 {
        let mut rnum = [0u8; 8];
        fill_random(&mut rnum);
        round_keys.push(rnum.to_vec());
    }

    // 4. Encrypt sensitive data
    let original_data = b"Sensitive data".to_vec();
    let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys)?;

    // 5. Decrypt and verify
    let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys)?;
    assert_eq!(original_data, decrypted);

    Ok(())
}
```

---

## **Architecture**

### **1. Key Derivation**
- **Algorithm**: Argon2id (memory-hard, 8192 KB, 2 iterations, 4 parallelism).
- **Expansion**: HKDF for key material expansion.
- **Salt**: Unique per session, 32-byte cryptographically secure random value.

### **2. Custom S-Box Generation**
- **Base**: AES S-box as a foundation.
- **Transformation**:
  - **GF(256) Multiplication**: Uses the irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (AES standard).
  - **XOR Mask**: Key-dependent mask for additional diffusion.
  - **Bijectivity Guarantee**: Regenerates if collisions are detected (max 100 attempts).
- **Derivation**: BLAKE3-based, with attempt counter as a nonce to ensure uniqueness.

### **3. Substitution Tables**
- **Per-Round Tables**: 256-byte substitution and inverse tables generated for each round.
- **Cache**: Global, thread-safe cache (16 entries max) to avoid recomputation.
- **Lookup**: Constant-time using bitwise operations.

### **4. Core Encryption Process**
1. **Round Seed Derivation**: Unique 8-byte seed per round using HKDF.
2. **Subkey Derivation**: XOR and rotation keys derived from master keys and round seed.
3. **Cipher Cache Construction**: Substitution tables and character mappings for the round.
4. **Parallel Chunk Processing**:
   - Data split into 65536-byte chunks.
   - Each chunk processed in parallel with:
     - Substitution via S-box.
     - XOR with keystream (BLAKE3-derived).
     - Bit rotation for diffusion.
5. **HMAC-SHA256**: Applied to ciphertext for integrity.

### **5. Decryption Process**
- Mirrors encryption, using inverse substitution tables and verified HMAC.

---

## **Security Considerations**

### **Threat Model**
- **Confidentiality**: Resistant to known-plaintext, chosen-plaintext, and timing attacks.
- **Integrity**: HMAC-SHA256 prevents tampering.
- **Side Channels**: Constant-time operations mitigate timing and cache attacks.

### **Mitigations**
| Threat               | Mitigation                                                                 |
|----------------------|----------------------------------------------------------------------------|
| Timing Attacks       | Constant-time lookups, fixed-size operations.                           |
| Memory Leaks         | Zeroization of keys and sensitive data (`zeroize` crate).                |
| Key Reuse            | Unique salts and seeds per session.                                       |
| Linear Cryptanalysis | S-box tested for max bias < 0.10.                                         |
| Cache Attacks        | Thread-local caching, limited global cache size.                        |

---

## **Performance**

### **Optimizations**
- **Parallelism**: `rayon` for multi-core processing.
- **Chunking**: 65536-byte chunks for cache efficiency.
- **Caching**: Reuses substitution tables across rounds.
- **BLAKE3**: Fast keystream generation (~1GB/s on modern CPUs).

### **Benchmark Results (Intel i9-13900K, 32GB RAM)**
| Operation       | Throughput  | Latency (1MB) | Memory Usage |
|-----------------|--------------|---------------|--------------|
| Encryption      | ~120MB/s     | ~8ms          | ~20MB        |
| Decryption      | ~110MB/s     | ~9ms          | ~20MB        |
| Key Derivation  | ~1000 ops/s  | ~1ms          | ~8MB         |

---

## **Testing**

### **Test Coverage**
- **Unit Tests**: Key derivation, S-box bijectivity, encryption/decryption cycles.
- **Integration Tests**: End-to-end workflows with random data.
- **Property Tests**: Fuzz testing for edge cases.
- **Security Tests**: Linear cryptanalysis, timing attack resistance.

### **Run Tests**
```sh
cargo test --release
```

### **Example Test Output**
```sh
running 42 tests
test cipher::test_encrypt_decrypt_roundtrip ... ok
test crypto::test_sbox_bijectivity ... ok
test lib::test_linear_cryptanalysis ... ok
test types::test_cache_consistency ... ok
...
test result: ok. 42 passed; 0 failed
```

---

## **API Reference**

### **Core Functions**

#### **`encrypt3_final`**
```rust
pub fn encrypt3_final(
    plaintext: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    round_keys: &[Vec<u8>],
) -> Result<Vec<u8>, CipherError>
```
- **Inputs**:
  - `plaintext`: Data to encrypt.
  - `key1`, `key2`: Master keys (derived via `gene3_with_salt`).
  - `round_keys`: Round-specific keys (8-byte seeds).
- **Output**: `header || ciphertext || hmac`.
- **Errors**: Invalid key lengths, HMAC failure.

#### **`decrypt3_final`**
```rust
pub fn decrypt3_final(
    ciphertext: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    round_keys: &[Vec<u8>],
) -> Result<Vec<u8>, CipherError>
```
- **Inputs**: Ciphertext (with header/HMAC).
- **Output**: Original plaintext.
- **Errors**: HMAC mismatch, decryption failure.

#### **`gene3_with_salt`**
```rust
pub fn gene3_with_salt(seed: &[u8], salt: &[u8; 32]) -> Secret<Vec<u8>>
```
- **Inputs**: Seed (e.g., password) and salt.
- **Output**: 32-byte derived key (Argon2id + HKDF).

---

## **Advanced Usage**

### **Customizing Rounds**
```rust
let rounds = 10; // Default: 5
let mut round_keys = Vec::with_capacity(rounds);
for _ in 0..rounds {
    let mut seed = [0u8; 8];
    fill_random(&mut seed);
    round_keys.push(seed.to_vec());
}
```

### **Benchmarking**
```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_encrypt(c: &mut Criterion) {
    let mut salt = [0u8; 32];
    fill_random(&mut salt);
    let key1 = gene3_with_salt(b"seed", &salt);
    let key2 = gene3_with_salt(key1.expose_secret(), &salt);
    let round_keys = vec![vec![0u8; 8]; 5];
    let data = vec![0u8; 1_000_000]; // 1MB

    c.bench_function("encrypt_1mb", |b| {
        b.iter(|| encrypt3_final(data.clone(), &key1, &key2, &round_keys).unwrap())
    });
}

criterion_group!(benches, benchmark_encrypt);
criterion_main!(benches);
```

---

## **Contributing**

### **Guidelines**
- **Code Style**: `rustfmt` and `clippy` must pass.
- **Testing**: All changes require tests.
- **Documentation**: Update `README.md` and docstrings for new features.
- **Security**: Open an issue for security-related changes before implementing.

### **How to Contribute**
1. Fork the repository.
2. Create a feature branch (`git checkout -b feat/your-feature`).
3. Commit changes (`git commit -am 'Add your feature'`).
4. Push to the branch (`git push origin feat/your-feature`).
5. Open a Pull Request.

---

## **License**

This project is licensed under the **MIT License** – see [LICENSE](LICENSE) for details.

---

## **Acknowledgments**

- **Argon2**: Password Hashing Competition winner.
- **BLAKE3**: Fast, secure cryptographic hash function.
- **Rayon**: Data parallelism for Rust.
- **RustCrypto**: Community-driven cryptographic primitives.
- **Zeroize**: Secure memory handling.

---

## **Changelog**

### **v0.9.5 (2025-09-15)**
- **Added**:
  - GF(256) multiplication for S-box generation.
  - BLAKE3-based parameter derivation for S-box uniqueness.
  - Linear cryptanalysis test with stricter bias threshold (0.10).
  - 65536-byte chunking for parallel processing.
- **Changed**:
  - S-box generation now guarantees bijectivity via regeneration.
  - Cipher cache uses `Vec<u8>` instead of `Vec<usize>` for efficiency.
  - BLAKE3 keystream chunk size increased to 65536 bytes.
- **Fixed**:
  - Potential panic in parallel iterators with empty keys.
  - Bounds checking for substitution table lookups.
