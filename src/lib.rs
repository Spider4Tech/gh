// Horizon Cryptographic Library v0.9.4

pub mod types;
pub mod crypto;
pub mod cipher;
pub mod utils;

// Re-export main public APIs
pub use cipher::{encrypt3_final, decrypt3_final};
pub use crypto::{gene3_with_salt, fill_random};
pub use types::{KEY_LENGTH, SALT_LEN, VERSION, ALG_ID, ROUND};
pub use utils::{escape_zero_bytes, unescape_and_remove_stars, insert_random_stars_escaped_secure};

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use zeroize::Zeroize;

    #[test]
    fn test_encryption_decryption() {
        let original_data = b"Hello, Horizon Cryptographic Library!".to_vec();

        let seed = b"test_seed_for_horizon_crypto";
        let mut salt = [0u8; 32];
        fill_random(&mut salt);

        let key1 = gene3_with_salt(seed, &salt);

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
            rnum.zeroize();
        }

        let padding_key = key1.expose_secret();
        let data_with_stars = insert_random_stars_escaped_secure(original_data.clone(), padding_key);

        let encrypted = encrypt3_final(data_with_stars, &key1, &key1, &round_keys).unwrap();
        let decrypted = decrypt3_final(encrypted, &key1, &key1, &round_keys).unwrap();
        let final_data = unescape_and_remove_stars(decrypted);

        assert_eq!(original_data, final_data);
    }
}

#[cfg(test)]
mod test;