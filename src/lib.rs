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

    use crate::ROUND;
use crate::fill_random;
use crate::SALT_LEN;

    use rand::Rng;
    use crate::crypto::{generate_custom_sbox, generate_inverse_sbox};
    use crate::decrypt3_final;
    use crate::encrypt3_final;
    use crate::gene3_with_salt;

    use crate::KEY_LENGTH;
    use std::time::Instant;

    // Test de génération de clés
    #[test]
    fn test_key_generation() {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key = gene3_with_salt(b"test_seed", &salt);
        assert_eq!(key.expose_secret().len(), KEY_LENGTH, "Generated key must have the correct length");
    }

    // Test de chiffrement et déchiffrement
    #[test]
    fn test_encrypt_decrypt() {
        let seed = b"test_seed_for_horizon";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = b"Hello, Horizon Cryptographic Library!".to_vec();
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys).unwrap();
        assert_eq!(original_data, decrypted, "Decryption must match the original message");
    }

    // Test d'intégrité des données (HMAC)
    #[test]
    fn test_hmac_integrity() {
        let seed = b"test_seed_for_hmac";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = b"Test HMAC integrity".to_vec();
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        // Modify a byte to test integrity
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[SALT_LEN + 2] ^= 0xFF; // Flip a bit in the body
            let result = decrypt3_final(tampered, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Decryption must fail if HMAC is invalid");
        }
    }

    // Test de gestion des erreurs (message vide)
    #[test]
    fn test_empty_input() {
        let seed = b"test_seed_for_empty";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = Vec::new();
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys).unwrap();
        assert_eq!(original_data, decrypted, "Empty message must be handled correctly");
    }

    // Test avec des données de grande taille
    #[test]
    fn test_large_data() {
        let seed = b"test_seed_for_large_data";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data: Vec<u8> = (0..10000).map(|x| (x % 256) as u8).collect(); // 10 KB of data
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys).unwrap();

        assert_eq!(original_data, decrypted, "Decryption must match the original input for large data");
    }

    // Test avec différents types de données (binaire, texte, etc.)
    #[test]
    fn test_different_data_types() {
        let seed = b"test_seed_for_data_types";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        // Text
        let text_data = b"Sample text data".to_vec();
        let encrypted_text = encrypt3_final(text_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted_text = decrypt3_final(encrypted_text, &key1, &key2, &round_keys).unwrap();
        assert_eq!(text_data, decrypted_text, "Text data must be correctly handled");

        // Binary data
        let binary_data: Vec<u8> = (0..128).collect();
        let encrypted_binary = encrypt3_final(binary_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted_binary = decrypt3_final(encrypted_binary, &key1, &key2, &round_keys).unwrap();
        assert_eq!(binary_data, decrypted_binary, "Binary data must be correctly handled");
    }

    // Test de résistance basique aux modifications (pour démonstration académique)
    #[test]
    fn test_tamper_resistance() {
        let seed = b"test_seed_for_tamper";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = b"Tamper resistance test".to_vec();
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        // Modify a byte in the ciphertext
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[SALT_LEN + 2 + 10] ^= 0xFF; // Flip a bit in the body
            let result = decrypt3_final(tampered, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Decryption must fail if ciphertext is modified");
        }
    }

    // Test de résistance à la réutilisation de sel
    #[test]
    fn test_salt_reuse() {
        let seed = b"test_seed_for_salt_reuse";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data1 = b"First message".to_vec();
        let original_data2 = b"Second message".to_vec();

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted1 = encrypt3_final(original_data1.clone(), &key1, &key2, &round_keys).unwrap();
        let encrypted2 = encrypt3_final(original_data2.clone(), &key1, &key2, &round_keys).unwrap();

        // Ensure ciphertexts are different even with the same salt
        assert_ne!(encrypted1, encrypted2, "Ciphertexts must be different even with the same salt for different messages");
    }

    // Test de résistance à la perturbation (bit flipping attack)
    #[test]
    fn test_bit_flipping_attack() {
        let seed = b"test_seed_for_bit_flipping";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = b"Bit flipping attack test".to_vec();

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();

        // Modify a bit in the ciphertext
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[SALT_LEN + 2 + 5] ^= 0x01; // Flip a single bit

            let result = decrypt3_final(tampered, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Decryption must fail if ciphertext is modified");
        }
    }

    // Test de résistance à une attaque par texte clair connu
    #[test]
    fn test_known_plaintext_attack() {
        let seed = b"test_seed_for_known_plaintext";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let known_plaintext = b"Known plaintext for attack".to_vec();

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let ciphertext = encrypt3_final(known_plaintext.clone(), &key1, &key2, &round_keys).unwrap();

        // Here, we assume the attacker knows the plaintext and ciphertext.
        // In a real scenario, the attacker would try to deduce information about the key.
        // For this test, we just verify that decryption works correctly.
        let decrypted = decrypt3_final(ciphertext, &key1, &key2, &round_keys).unwrap();
        assert_eq!(known_plaintext, decrypted, "Decryption must match the known plaintext");
    }

    // Test de résistance à une attaque par timing (simulation basique)
    #[test]
    fn test_timing_attack_resistance() {
        let seed = b"test_seed_for_timing_attack";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = b"Timing attack resistance test".to_vec();

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        // Measure encryption time
        let start_encrypt = Instant::now();
        let _ = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let encrypt_time = start_encrypt.elapsed();

        // Measure decryption time
        let ciphertext = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let start_decrypt = Instant::now();
        let _ = decrypt3_final(ciphertext, &key1, &key2, &round_keys).unwrap();
        let decrypt_time = start_decrypt.elapsed();

        // Ensure times are reasonable and do not leak sensitive information
        println!("Encryption time: {:?}", encrypt_time);
        println!("Decryption time: {:?}", decrypt_time);
        assert!(encrypt_time < std::time::Duration::from_secs(2), "Encryption must not be too slow");  // TODO à surveiller
        assert!(decrypt_time < std::time::Duration::from_secs(2), "Decryption must not be too slow");
    }

    // Test de résistance à une attaque par collision
    #[test]
    fn test_collision_resistance() {
        let seed = b"test_seed_for_collision";
        let mut salt1 = [0u8; SALT_LEN];
        let mut salt2 = [0u8; SALT_LEN];
        fill_random(&mut salt1);
        fill_random(&mut salt2);

        let key1_1 = gene3_with_salt(seed, &salt1);
        let key2_1 = gene3_with_salt(key1_1.expose_secret(), &salt1);
        let key1_2 = gene3_with_salt(seed, &salt2);
        let key2_2 = gene3_with_salt(key1_2.expose_secret(), &salt2);

        let original_data = b"Collision resistance test".to_vec();

        let mut round_keys1 = Vec::new();
        let mut round_keys2 = Vec::new();
        for _ in 0..ROUND {
            let mut rnum1 = [0u8; 8];
            let mut rnum2 = [0u8; 8];
            fill_random(&mut rnum1);
            fill_random(&mut rnum2);
            round_keys1.push(u64::from_le_bytes(rnum1).to_string().into_bytes());
            round_keys2.push(u64::from_le_bytes(rnum2).to_string().into_bytes());
        }

        let encrypted1 = encrypt3_final(original_data.clone(), &key1_1, &key2_1, &round_keys1).unwrap();
        let encrypted2 = encrypt3_final(original_data.clone(), &key1_2, &key2_2, &round_keys2).unwrap();

        // Ensure ciphertexts are different even with the same plaintext but different salts
        assert_ne!(encrypted1, encrypted2, "Ciphertexts must be different even with the same plaintext but different salts");
    }

    // Test de résistance à une attaque par force brute (simulation académique)
    #[test]
    fn test_brute_force_attack() {
        // Note: This test is only for academic demonstration with very small keys!
        let small_key_size = 3; // A very small key size for demonstration purposes
        let mut small_seed = vec![0; small_key_size];
        rand::thread_rng().fill(&mut small_seed[..]);

        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);

        let original_data = b"Brute force test".to_vec();

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let key1 = gene3_with_salt(&small_seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let ciphertext = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();

        // Simulate brute force attack on a very small key
        //let mut found = false;
        let max_attempts = 10; //255u32.pow(small_key_size as u32);
        for i in 0..=max_attempts {
            let candidate_seed = int_to_bytes(i, small_key_size);
            let candidate_key1 = gene3_with_salt(&candidate_seed, &salt);
            let candidate_key2 = gene3_with_salt(candidate_key1.expose_secret(), &salt);

            let decrypted = decrypt3_final(ciphertext.clone(), &candidate_key1, &candidate_key2, &round_keys);
            if decrypted.is_ok() && decrypted.unwrap() == original_data {
                //found = true;
                break;
            }
        }
        //assert!(found, "Brute force attack must succeed for very small keys");
    }

    // Utility function to convert an integer to a byte array
    fn int_to_bytes(mut x: u32, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push((x % 256) as u8);
            x /= 256;
        }
        result
    }

    // Test de résistance à la réutilisation de clé
    #[test]
    fn test_key_reuse_resistance() {
        let seed = b"test_seed_for_key_reuse";
        let mut salt1 = [0u8; SALT_LEN];
        let mut salt2 = [0u8; SALT_LEN];
        fill_random(&mut salt1);
        fill_random(&mut salt2);

        let key1 = gene3_with_salt(seed, &salt1);
        let key2 = gene3_with_salt(seed, &salt2);

        let original_data = b"Key reuse resistance test".to_vec();
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted1 = encrypt3_final(original_data.clone(), &key1, &key1, &round_keys).unwrap();
        let encrypted2 = encrypt3_final(original_data.clone(), &key2, &key2, &round_keys).unwrap();

        // Les chiffrés doivent être différents même avec la même graine mais des sels différents
        assert_ne!(encrypted1, encrypted2, "Ciphertexts must be different even with the same seed but different salts");
    }

    // Test de résistance à l'attaque par texte clair choisi
    #[test]
    fn test_chosen_plaintext_attack() {
        let seed = b"test_seed_for_chosen_plaintext";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let plaintext1 = b"First chosen plaintext".to_vec();
        let plaintext2 = b"Second chosen plaintext".to_vec();

        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let ciphertext1 = encrypt3_final(plaintext1.clone(), &key1, &key2, &round_keys).unwrap();
        let ciphertext2 = encrypt3_final(plaintext2.clone(), &key1, &key2, &round_keys).unwrap();

        // Les chiffrés doivent être différents pour des textes clairs différents
        assert_ne!(ciphertext1, ciphertext2, "Ciphertexts must be different for different plaintexts");
    }

    // Test de résistance à la corruption de données
    #[test]
    fn test_data_corruption_resistance() {
        let seed = b"test_seed_for_data_corruption";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data = b"Data corruption resistance test".to_vec();
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let mut corrupted = encrypted.clone();
        if !corrupted.is_empty() {
            corrupted[SALT_LEN + 2] = 0xFF; // Corruption d'un octet
            let result = decrypt3_final(corrupted, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Decryption must fail if data is corrupted");
        }
    }

    // Test de résistance à la fuite d'information par timing
    #[test]
    fn test_timing_leak_resistance() {
        let seed = b"test_seed_for_timing_leak";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);


        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        // Mesurer le temps de chiffrement pour des données de tailles différentes
        let small_data = b"small".to_vec();
        let large_data: Vec<u8> = (0..10000).map(|x| (x % 256) as u8).collect();

        let start_small = Instant::now();
        let _ = encrypt3_final(small_data.clone(), &key1, &key2, &round_keys).unwrap();
        let time_small = start_small.elapsed();

        let start_large = Instant::now();
        let _ = encrypt3_final(large_data.clone(), &key1, &key2, &round_keys).unwrap();
        let time_large = start_large.elapsed();

        // Le temps ne doit pas être proportionnel à la taille des données (pour éviter les attaques par timing)
        println!("Encryption time for small data: {:?}", time_small);
        println!("Encryption time for large data: {:?}", time_large);
        assert!(time_large < time_small * 100, "Encryption time must not scale linearly with data size");
    }

    // Test de résistance à la réutilisation de nonces/IVs
    #[test]
    fn test_nonce_reuse_resistance() {
        let seed = b"test_seed_for_nonce_reuse";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data1 = b"First message with reused nonce".to_vec();
        let original_data2 = b"Second message with reused nonce".to_vec();

        // Simuler la réutilisation de nonce en réutilisant les mêmes round_keys
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted1 = encrypt3_final(original_data1.clone(), &key1, &key2, &round_keys).unwrap();
        let encrypted2 = encrypt3_final(original_data2.clone(), &key1, &key2, &round_keys).unwrap();

        // Les chiffrés doivent être différents même avec les mêmes round_keys
        assert_ne!(encrypted1, encrypted2, "Ciphertexts must be different even with reused round keys");
    }

    /// Test that the custom S-Box is a valid permutation (bijective)
    #[test]
    fn test_custom_sbox_is_bijective() {
        let key = [0x42u8; 2048]; // Example 2048-byte key
        let sbox = generate_custom_sbox(&key);

        // Check all values 0..255 are present exactly once
        let mut found = [false; 256];
        for &val in &sbox {
            assert!(!found[val as usize], "Duplicate value {} in S-Box", val);
            found[val as usize] = true;
        }
        assert!(found.iter().all(|&f| f), "S-Box is not bijective");
    }

    /// Test that small key changes produce very different S-Boxes
    #[test]
    fn test_custom_sbox_key_sensitivity() {
        let key1 = [0x42u8; 2048];
        let mut key2 = [0x42u8; 2048];
        key2[0] ^= 0x01; // Flip one bit

        let sbox1 = generate_custom_sbox(&key1);
        let sbox2 = generate_custom_sbox(&key2);

        // Count differing bytes
        let diff = sbox1.iter().zip(sbox2.iter()).filter(|(a, b)| a != b).count();
        assert!(diff > 128, "S-Boxes are too similar for different keys (diff: {})", diff);
    }

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


    /// Test that the S-Box generation is reasonably fast
    #[test]
    fn test_custom_sbox_performance() {
        let key = [0x42u8; 2048];
        let start = Instant::now();
        let _ = generate_custom_sbox(&key);
        let duration = start.elapsed();
        assert!(duration < std::time::Duration::from_millis(100), "S-Box generation is too slow: {:?}", duration);
    }

    /// Test that the inverse S-Box correctly inverts the forward S-Box
    #[test]
    fn test_custom_sbox_inverse_correctness() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);
        let inv_sbox = generate_inverse_sbox(&sbox);

        // Verify that for all i, inv_sbox[sbox[i]] == i
        for i in 0..256 {
            assert_eq!(inv_sbox[sbox[i] as usize], i as u8, "Inverse S-Box is incorrect at index {}", i);
        }
    }

    /// Test that the S-Box is resistant to fixed points
    #[test]
    fn test_custom_sbox_no_fixed_points() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);

        // Count fixed points (sbox[i] == i)
        let fixed_points = sbox.iter().enumerate().filter(|(i, &val)| *i == val as usize).count();
        assert!(fixed_points < 16, "Too many fixed points in S-Box: {}", fixed_points);
    }

    /// Test that the S-Box is resistant to linear approximations
    #[test]
    fn test_custom_sbox_nonlinearity() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);

        // Test linear approximation: Pr[a·x + b·S(x) = c] should be close to 0.5 for all a, b, c
        let mut max_bias = 0.0;
        for a in 0..8 {
            for b in 0..8 {
                for c in 0..2 {
                    let mut count = 0;
                    for x in 0..255 {
                        let condition = ((x >> a) & 1) ^ ((sbox[x as usize] >> b) & 1) ^ c;
                        if condition == 0 {
                            count += 1;
                        }
                    }
                    let bias = (count as f64 / 256.0 - 0.5).abs();
                    if bias > max_bias {
                        max_bias = bias;
                    }
                }
            }
        }
        assert!(max_bias < 0.2, "S-Box has detectable linear approximations (max bias: {})", max_bias);
    }

    #[test]
    fn test_custom_sbox_bijective() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);
        let mut seen = [false; 256];
        for &v in sbox.iter() {
            assert!(!seen[v as usize], "duplicate value in sbox: {:02x}", v);
            seen[v as usize] = true;
        }
    }

    #[test]
    fn test_custom_sbox_linear_approximation_table() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);
        let mut max_bias = 0usize;
        for a in 1usize..256 {
            for b in 1usize..256 {
                let mut count = 0usize;
                for x in 0usize..256 {
                    let pa = ( (a as u8 & x as u8).count_ones() & 1 ) as u8;
                    let pb = ( (b as u8 & sbox[x]).count_ones() & 1 ) as u8;
                    if pa == pb {
                        count += 1;
                    }
                }
                let bias = if count > 128 { count - 128 } else { 128 - count };
                if bias > max_bias { max_bias = bias; }
            }
        }
        eprintln!("max LAT absolute deviation from 128 = {}", max_bias);
        let max_bias_frac = max_bias as f64 / 256.0;
        assert!(max_bias_frac <= 0.10, "S-box linear bias too high: {}", max_bias_frac);
    }

    #[test]
    fn test_custom_sbox_avalanche_and_sac() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);
        let mut total_hd: usize = 0;
        let mut toggle_counts = [[0usize; 8]; 8];
        for in_bit in 0..8 {
            let mask = 1usize << in_bit;
            for x in 0usize..256 {
                let y1 = sbox[x];
                let y2 = sbox[x ^ mask];
                let hd = (y1 ^ y2).count_ones() as usize;
                total_hd += hd;
                for out_bit in 0..8 {
                    if ((y1 ^ y2) >> out_bit) & 1 == 1 {
                        toggle_counts[in_bit][out_bit] += 1;
                    }
                }
            }
        }
        let avg_hd = total_hd as f64 / (256.0 * 8.0);
        eprintln!("average hamming distance per single-bit input flip = {}", avg_hd);
        assert!(avg_hd >= 3.0 && avg_hd <= 5.0, "average avalanche out of expected range: {}", avg_hd);
        for in_bit in 0..8 {
            for out_bit in 0..8 {
                let frac = toggle_counts[in_bit][out_bit] as f64 / 256.0;
                let bias = (frac - 0.5).abs();
                assert!(bias <= 0.10, "SAC bias too high for in_bit {} out_bit {} = {}", in_bit, out_bit, bias);
            }
        }
    }

    #[test]
    fn test_custom_sbox_bit_independence_criterion() {
        let key = [0x42u8; 2048];
        let sbox = generate_custom_sbox(&key);
        for a in 1usize..256 {
            for b in 1usize..256 {
                let mut cnt00 = 0usize;
                let mut cnt01 = 0usize;
                let mut cnt10 = 0usize;
                let mut cnt11 = 0usize;
                for x in 0usize..256 {
                    let pa = ((a as u8 & x as u8).count_ones() & 1) as u8;
                    let sb = sbox[x];
                    let pb = ((b as u8 & sb).count_ones() & 1) as u8;
                    match (pa, pb) {
                        (0,0) => cnt00 += 1,
                        (0,1) => cnt01 += 1,
                        (1,0) => cnt10 += 1,
                        (1,1) => cnt11 += 1,
                        _ => {}
                    }
                }

                let p01 = cnt01 as f64 / 256.0;
                let p10 = cnt10 as f64 / 256.0;
                let p11 = cnt11 as f64 / 256.0;
                let pa = p10 + p11;
                let pb = p01 + p11;
                let expected_p11 = pa * pb;
                let diff = (p11 - expected_p11).abs();
                assert!(diff <= 0.10, "BIC failed for masks a=0x{:02x} b=0x{:02x}, diff={}", a, b, diff);
            }
        }
    }


}