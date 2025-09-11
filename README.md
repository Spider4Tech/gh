# Horizon

**Une librairie Rust pour la gestion sécurisée et performante de données sensibles.**

[![Crates.io](https://img.shields.io/crates/v/horizon.svg)](https://crates.io/crates/horizon)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://github.com/Spider4Tech/gh/actions/workflows/rust.yml/badge.svg)](https://github.com/Spider4Tech/gh/actions/workflows/rust.yml)

---

## 📌 À propos

**Horizon** est une librairie Rust conçue pour offrir des primitives cryptographiques et des structures de données sécurisées, optimisées pour la performance et la sécurité. Elle intègre :
- **Hachage sécurisé** (Argon2, BLAKE3)
- **Gestion de clés et secrets** (HMAC, HKDF, zeroization)
- **Structures de données thread-safe** (DashMap, Rayon)
- **Optimisations avancées** (LTO, codegen-units = 1)

Idéal pour les applications nécessitant une **gestion robuste de mots de passe, de tokens, ou de données sensibles**.

---

## 🛠 Installation

Ajoutez `horizon` à votre `Cargo.toml` :

```toml
[dependencies]
horizon = "0.9.4"
```

Ou via `cargo add` :
```sh
cargo add horizon
```

---

## 🚀 Fonctionnalités

| Module               | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **Hachage**          | Argon2, BLAKE3 pour le hachage sécurisé de mots de passe.                  |
| **Clés & Secrets**   | Génération, dérivation (HKDF), et stockage sécurisé (zeroize).            |
| **MAC**              | HMAC-SHA256/512 pour l'authentification de messages.                       |
| **Concurrency**      | Structures de données thread-safe (DashMap) et parallélisation (Rayon).   |
| **Optimisations**    | Compilation optimisée pour la performance (LTO, opt-level=3).             |

---

## 📂 Exemples d'utilisation

### 1. Hachage de mot de passe avec Argon2
```rust
use horizon::password;

fn main() {
    let password = "mon_mot_de_passe_sécurisé";
    let hash = password::hash(password).expect("Échec du hachage");
    println!("Hash: {}", hash);
}
```

### 2. Génération de clé HMAC
```rust
use horizon::hmac;

fn main() {
    let key = b"ma_clé_secrète";
    let data = b"données_à_protéger";
    let mac = hmac::sign(key, data);
    println!("MAC: {:x}", mac);
}
```

### 3. Utilisation de DashMap pour le stockage thread-safe
```rust
use dashmap::DashMap;
use horizon::secrets;

fn main() {
    let map = DashMap::new();
    map.insert("clé1", secrets::zeroize_on_drop("valeur_sécurisée"));
}
```

---

## 🔧 Configuration

### Profil de Release
Le projet est optimisé pour la production via `Cargo.toml` :
```toml
[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
opt-level = 3
```

### Features
- **`alloc`** : Active l'allocation dynamique pour `secrecy`.
- **Parallélisation** : `rayon` et `dashmap` sont activés par défaut.

---

## 🧪 Tests

Exécutez les tests avec :
```sh
cargo test --release
```

Les tests couvrent :
- La robustesse des fonctions de hachage.
- L'absence de fuites mémoire (zeroization).
- La thread-safety des structures de données.

---

## 📜 Licence

Ce projet est sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus de détails.

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Ouvrez une **Issue** ou un **Pull Request** pour :
- Signaler un bug.
- Proposer une nouvelle fonctionnalité.
- Améliorer la documentation.