use anyhow::{Context, Result};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass},
    session::UserType,
    types::AuthPin,
};
use std::env;

const USER_PIN: &str = "5678";

const MESSAGE: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. \
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. \
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

fn main() -> Result<()> {
    // --- Library initialization ---
    let lib_path = env::var("PKCS11_MODULE")
        .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());

    let pkcs11 = Pkcs11::new(lib_path).context("failed to load library")?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // --- Token discovery or initialization ---

    let so_pin = AuthPin::new("abcdef654321".into()); // security officer pin

    let slot = if let Some(s) = pkcs11.get_slots_with_token()?.into_iter().next() { 
        s
    } else {
        let empty_slot = pkcs11
            .get_all_slots()?
            .into_iter()
            .next()
            .context("no slots available")?;

        pkcs11.init_token(empty_slot, &so_pin, "TestToken")?;

        {
            let so_session = pkcs11.open_rw_session(empty_slot)?;
            so_session.login(UserType::So, Some(&so_pin))?;
            so_session.init_pin(&AuthPin::new(USER_PIN.into()))?;
        }

        pkcs11
            .get_slots_with_token()?
            .into_iter()
            .next()
            .context("token not found after initialization")?
    };

    // --- Session and login ---

    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // --- RSA signature ---

    let pub_attrs = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::ModulusBits(2048.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    ];

    let priv_attrs = vec![
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];

    let (pub_key, priv_key) =
        session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_attrs, &priv_attrs)?;

    let signature = session.sign(&Mechanism::Sha256RsaPkcs, priv_key, MESSAGE)?;
    println!(
        "RSA signature ({} bytes), first 8 bytes: {:02x?}",
        signature.len(),
        &signature[..8]
    );

    session.verify(&Mechanism::Sha256RsaPkcs, pub_key, MESSAGE, &signature)?;
    println!("RSA signature verified OK");

    // --- AES-256 encryption/decryption ---

    let aes_attrs = vec![
        Attribute::Token(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::ValueLen(32.into()), // AES-256
        Attribute::KeyType(KeyType::AES),
        Attribute::Class(ObjectClass::SECRET_KEY),
    ];

    let aes_key = session.generate_key(&Mechanism::AesKeyGen, &aes_attrs)?;
    let init_vector = *b"qwertyuiop123456"; // should be random and unique for every message

    let ciphertext = session.encrypt(&Mechanism::AesCbcPad(init_vector), aes_key, MESSAGE)?;
    println!("AES-256 encrypted ({} bytes): {:02x?}", ciphertext.len(), &ciphertext[..16]);

    let decrypted = session.decrypt(&Mechanism::AesCbcPad(init_vector), aes_key, &ciphertext)?;
    println!(
        "AES-256 decrypted: \"{}\"",
        String::from_utf8(decrypted)?
    );

    Ok(())
}
