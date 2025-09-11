// Horizon Cryptographic Library v0.9.4
// Main binary for testing the cryptographic functions

use horizon::{encrypt3_final, decrypt3_final, gene3_with_salt, fill_random, insert_random_stars_escaped_secure, unescape_and_remove_stars, ROUND};
use secrecy::ExposeSecret;
use std::error::Error;
use std::time::Instant;
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Horizon Cryptographic Library v0.9.4 - Performance Test");
    println!("==================================================");

    let start_all = Instant::now();

    let original_data = vec![b'A'; 1 * 512 * 512];
    println!("Original data size: {} bytes", original_data.len());

    let seed = b"horizon_test_seed_2025";
    let mut salt = [0u8; 32];
    let start_salt = Instant::now();
    fill_random(&mut salt);
    println!("Salt generation: {:?}", start_salt.elapsed());

    let start_key_gen = Instant::now();
    let key1 = gene3_with_salt(seed, &salt);
    let key2 = gene3_with_salt(key1.expose_secret(), &salt);
    println!("Key generation: {:?}", start_key_gen.elapsed());

    let start_list = Instant::now();
    let mut round_keys = Vec::new();
    let mut r = 0usize;
    while r < ROUND {
        let mut rnum = [0u8; 8];
        fill_random(&mut rnum);
        round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        rnum.zeroize();
        r += 1;
    }
    println!("Round keys generation: {:?}", start_list.elapsed());

    let start_encrypt_all = Instant::now();

    let start_secure_padding = Instant::now();
    let padding_key = key1.expose_secret();
    let data_with_stars = insert_random_stars_escaped_secure(original_data.clone(), padding_key);
    println!("Secure padding: {:?}", start_secure_padding.elapsed());

    let encrypted = encrypt3_final(data_with_stars, &key1, &key2, &round_keys)?;
    println!("Encrypted size: {} bytes", encrypted.len());
    println!("Total encryption: {:?}", start_encrypt_all.elapsed());

    let start_decrypt_all = Instant::now();
    let decrypted = decrypt3_final(encrypted, &key1, &key2, &round_keys)?;
    println!("Total decryption: {:?}", start_decrypt_all.elapsed());

    let start_strip = Instant::now();
    let final_data = unescape_and_remove_stars(decrypted);
    println!("Strip/Unescape: {:?}", start_strip.elapsed());

    if final_data != original_data {
        println!("❌ Data mismatch!");
        return Err("Data integrity check failed".into());
    } else {
        println!("✅ Encryption/Decryption successful - Data integrity verified!");
    }

    println!("Total test time: {:?}", start_all.elapsed());
    Ok(())
}