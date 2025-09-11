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
}