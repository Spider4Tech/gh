# Horizon Cryptographic Library

**A high-performance, secure cryptographic library for Rust.**

[![Crates.io](https://img.shields.io/crates/v/horizon.svg)](https://crates.io/crates/horizon)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://github.com/Spider4Tech/gh/actions/workflows/rust.yml/badge.svg)](https://github.com/Spider4Tech/gh/actions/workflows/rust.yml)
[![Clippy](https://github.com/Spider4Tech/gh/actions/workflows/clippy.yml/badge.svg)](https://github.com/Spider4Tech/gh/actions/workflows/clippy.yml)

## Overview

**Horizon** is a Rust cryptographic library designed for high-performance, secure data encryption and decryption. It provides a robust framework for handling sensitive data, featuring:

- **Argon2id** for secure key derivation
- **BLAKE3** for fast, secure keystream generation
- **HMAC-SHA256** for message authentication
- **Parallel processing** with Rayon for optimal performance
- **Constant-time operations** to prevent timing attacks
- **Secure memory handling** with zeroization

Horizon is ideal for applications requiring strong cryptographic guarantees while maintaining high performance.

## Features

| Feature               | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Key Derivation**    | Uses Argon2id for secure, memory-hard key derivation                          |
| **Keystream**         | BLAKE3 for fast, cryptographically secure keystream generation                |
| **Authentication**    | HMAC-SHA256 for message integrity and authenticity                          |
| **Parallelism**       | Rayon for parallel processing of large datasets                             |
| **Timing Resistance** | Constant-time operations to prevent side-channel attacks                    |
| **Memory Safety**     | Zeroization of sensitive data to prevent memory leaks                      |
| **Caching**           | Global cache for substitution tables to optimize repeated operations         |

## Installation

Add `horizon` to your `Cargo.toml`:

```toml
[dependencies]
horizon = "0.9.4"
```

Or via `cargo add`:
```sh
cargo add horizon
```

## Usage

### Basic Encryption/Decryption

```rust
use horizon::{encrypt3_final, decrypt3_final, gene3_with_salt, fill_random};
use secrecy::ExposeSecret;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random salt
    let mut salt = [0u8; 32];
    fill_random(&mut salt);

    // Derive encryption keys
    let seed = b"my_secure_seed";
    let key1 = gene3_with_salt(seed, &salt);
    let key2 = gene3_with_salt(key1.expose_secret(), &salt);

    // Generate round keys
    let mut round_keys = Vec::new();
    for _ in 0..5 {
        let mut rnum = [0u8; 8];
        fill_random(&mut rnum);
        round_keys.push(rnum.to_vec());
    }

    // Encrypt data
    let original_data = b"Sensitive data".to_vec();
    let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys)?;

    // Decrypt data
    let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys)?;

    assert_eq!(original_data, decrypted);
    Ok(())
}
```

## Architecture

### Key Components

1. **Key Derivation**
   - Uses **Argon2id** with secure parameters (8192 KB memory, 2 iterations, 4 parallelism)
   - Output is further processed with **HKDF** for key expansion

2. **Substitution Tables**
   - 256-byte substitution tables generated per round
   - Tables are derived from salt, seed, and coordinate parameters
   - Inverse tables are precomputed for decryption

3. **Cipher Cache**
   - Global thread-safe cache for substitution tables
   - Avoids recomputing identical tables across operations
   - Limited to 16 entries to balance memory usage

4. **Bit Rotation**
   - Each byte is rotated left/right based on rotation key
   - Parallelized for performance

5. **HMAC Authentication**
   - Ensures message integrity and authenticity
   - Uses SHA-256 for strong cryptographic guarantees

### Round Processing

Horizon uses a multi-round encryption process:

1. **Round Seed Derivation**: Unique 8-byte seed for each round using HKDF
2. **Subkey Derivation**: XOR and rotation keys derived from master keys and round seed
3. **Cipher Cache Construction**: Substitution tables generated for the round
4. **Core Encryption**: Data processed through substitution, XOR, and rotation
5. **Bit Shifting**: Additional diffusion through bit rotation

Each round uses:
- A unique round seed
- Fresh substitution tables
- Independent XOR and rotation keys

### Security Considerations

- **Timing Attacks**: All lookups use constant-time implementations
- **Memory Leaks**: Sensitive data is zeroized after use
- **Key Reuse**: Each encryption session uses unique salts and seeds
- **Integrity**: HMAC protects against tampering
- **Parallel Safety**: Rayon ensures thread-safe parallel operations

## Performance

Horizon is optimized for both security and performance:

- **Parallel Processing**: Uses Rayon for multi-core optimization
- **Chunked Operations**: Processes data in 4KB chunks for memory efficiency
- **Caching**: Reuses computed tables to avoid redundant calculations
- **Benchmark Results**:
  - Encryption: ~50MB/s on modern CPUs
  - Decryption: ~45MB/s on modern CPUs
  - Memory Usage: ~10MB for cache (configurable)

## Testing

Horizon includes comprehensive tests covering:

- Key generation and derivation
- Encryption/decryption cycles
- Integrity verification
- Timing attack resistance
- Large data handling
- Edge cases (empty input, etc.)
- Known attack vectors (bit flipping, salt reuse)

Run tests with:
```sh
cargo test
```

## Contributing

Contributions are welcome! Please open an **Issue** or **Pull Request** for:

- Bug reports
- Feature requests
- Performance improvements
- Documentation enhancements

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

## Acknowledgments

- **Argon2**: Password hashing competition winner
- **BLAKE3**: Fast, secure cryptographic hash
- **Rayon**: Data parallelism for Rust
- **Rust Crypto**: Community-driven cryptographic primitives