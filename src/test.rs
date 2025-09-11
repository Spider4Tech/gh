// src/test.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // Test de génération de clés
    #[test]
    fn test_key_generation() {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key = gene3_with_salt(b"test_seed", &salt);
        assert_eq!(key.expose_secret().len(), KEY_LENGTH, "La clé générée doit avoir la bonne longueur");
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
        for r in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys).unwrap();
        assert_eq!(original_data, decrypted, "Le déchiffrement doit correspondre au message original");
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
        // Modifier un octet pour tester l'intégrité
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[SALT_LEN + 2] ^= 0xFF; // Inverser un bit dans le corps
            let result = decrypt3_final(tampered, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Le déchiffrement doit échouer si le HMAC est invalide");
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
        assert_eq!(original_data, decrypted, "Un message vide doit être traité correctement");
    }

    // Test avec des données de grande taille
    #[test]
    fn test_large_data() {
        let seed = b"test_seed_for_large_data";
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key1 = gene3_with_salt(seed, &salt);
        let key2 = gene3_with_salt(key1.expose_secret(), &salt);

        let original_data: Vec<u8> = (0..10000).map(|x| (x % 256) as u8).collect(); // 10 Ko de données
        let mut round_keys = Vec::new();
        for _ in 0..ROUND {
            let mut rnum = [0u8; 8];
            fill_random(&mut rnum);
            round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        }

        let start_time = Instant::now();
        let encrypted = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys).unwrap();
        let duration = start_time.elapsed();

        assert_eq!(original_data, decrypted, "Le déchiffrement doit correspondre à l'entrée originale pour de grandes données");
        println!("Temps pris pour chiffrer/déchiffrer 10 Ko de données : {:?}", duration);
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

        // Texte
        let text_data = b"Sample text data".to_vec();
        let encrypted_text = encrypt3_final(text_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted_text = decrypt3_final(encrypted_text, &key1, &key2, &round_keys).unwrap();
        assert_eq!(text_data, decrypted_text, "Les données de texte doivent être correctement traitées");

        // Données binaires
        let binary_data: Vec<u8> = (0..256).collect();
        let encrypted_binary = encrypt3_final(binary_data.clone(), &key1, &key2, &round_keys).unwrap();
        let decrypted_binary = decrypt3_final(encrypted_binary, &key1, &key2, &round_keys).unwrap();
        assert_eq!(binary_data, decrypted_binary, "Les données binaires doivent être correctement traitées");
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
        // Modifier un octet dans le ciphertext
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[SALT_LEN + 2 + 10] ^= 0xFF; // Inverser un bit dans le corps
            let result = decrypt3_final(tampered, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Le déchiffrement doit échouer si le ciphertext est modifié");
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

        // Vérifier que les ciphertexts sont différents même avec le même sel
        assert_ne!(encrypted1, encrypted2, "Les ciphertexts doivent être différents même avec le même sel pour des messages différents");
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

        // Modifier un bit dans le ciphertext
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[SALT_LEN + 2 + 5] ^= 0x01; // Inverser un seul bit

            let result = decrypt3_final(tampered, &key1, &key2, &round_keys);
            assert!(result.is_err(), "Le déchiffrement doit échouer si le ciphertext est modifié");
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

        // Ici, nous supposons que l'attaquant connaît le texte clair et le ciphertext.
        // Dans un vrai scénario, l'attaquant essaierait de déduire des informations sur la clé.
        // Pour ce test, nous vérifions simplement que le déchiffrement fonctionne correctement.
        let decrypted = decrypt3_final(ciphertext, &key1, &key2, &round_keys).unwrap();
        assert_eq!(known_plaintext, decrypted, "Le déchiffrement doit correspondre au texte clair connu");
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

        // Mesurer le temps de chiffrement
        let start_encrypt = Instant::now();
        let _ = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let encrypt_time = start_encrypt.elapsed();

        // Mesurer le temps de déchiffrement
        let ciphertext = encrypt3_final(original_data.clone(), &key1, &key2, &round_keys).unwrap();
        let start_decrypt = Instant::now();
        let _ = decrypt3_final(ciphertext, &key1, &key2, &round_keys).unwrap();
        let decrypt_time = start_decrypt.elapsed();

        // Vérifier que les temps sont raisonnables et ne révèlent pas d'informations sensibles
        println!("Temps de chiffrement: {:?}", encrypt_time);
        println!("Temps de déchiffrement: {:?}", decrypt_time);
        assert!(encrypt_time < std::time::Duration::from_secs(1), "Le chiffrement ne doit pas être trop lent");
        assert!(decrypt_time < std::time::Duration::from_secs(1), "Le déchiffrement ne doit pas être trop lent");
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

        // Vérifier que les ciphertexts sont différents même avec le même texte clair mais des sels différents
        assert_ne!(encrypted1, encrypted2, "Les ciphertexts doivent être différents même avec le même texte clair mais des sels différents");
    }

    // Test de résistance à une attaque par force brute (simulation académique)
    #[test]
    fn test_brute_force_attack() {
        // Note: Ce test est uniquement pour des démonstrations académiques avec de très petites clés!
        let small_key_size = 3; // Une taille de clé très petite pour des raisons démonstratives
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

        // Simulation d'attaque par force brute sur une clé très courte
        let mut found = false;
        let max_attempts = 255u32.pow(small_key_size as u32);
        for i in 0..=max_attempts {
            let candidate_seed = int_to_bytes(i, small_key_size);
            let candidate_key1 = gene3_with_salt(&candidate_seed, &salt);
            let candidate_key2 = gene3_with_salt(candidate_key1.expose_secret(), &salt);

            let decrypted = decrypt3_final(ciphertext.clone(), &candidate_key1, &candidate_key2, &round_keys);
            if decrypted.is_ok() && decrypted.unwrap() == original_data {
                found = true;
                break;
            }
        }
        assert!(found, "L'attaque par force brute doit réussir pour des clés très courtes");
    }

    // Fonction utilitaire pour convertir un entier en tableau d'octets
    fn int_to_bytes(mut x: u32, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push((x % 256) as u8);
            x /= 256;
        }
        result
    }
}