//! Fill a store with throwaway keys so the GUI can be looked at with content
//! in it. Never point this at a real store.
//!
//!     XDG_DATA_HOME=/tmp/demo cargo run -p rgpg-core --example seed-demo-store

use rgpg_core::Store;
use rgpg_core::keygen::{KeyGenRequest, KeyType, generate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open_default()?;

    // (user id, keep the secret key, key type)
    let people = [
        ("Ada Lovelace <ada@analytical.engine>", true, KeyType::Curve25519),
        ("Grace Hopper <grace@navy.mil>", true, KeyType::Rsa3072),
        ("Alan Turing <alan@bletchley.uk>", false, KeyType::Curve25519),
        ("Katherine Johnson <katherine@nasa.gov>", false, KeyType::Curve25519),
        ("Radia Perlman <radia@spanning.tree>", false, KeyType::Rsa3072),
        ("Barbara Liskov <barbara@substitution.org>", false, KeyType::Curve25519),
    ];

    for (user_id, keep_secret, key_type) in people {
        let mut request = KeyGenRequest::new(user_id);
        request.key_type = key_type;
        let key = generate(&request)?;
        if keep_secret {
            store.insert_secret(&key.cert)?;
        } else {
            store.insert(&key.cert)?;
        }
        println!("{} {}", key.cert.fingerprint().to_hex(), user_id);
    }

    Ok(())
}
