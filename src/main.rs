use aes_siv::{
    Aes256SivAead, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass},
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
    let lib_path =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());

    let pkcs11 = Pkcs11::new(lib_path).context("failed to load library")?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // --- Token discovery or initialization ---

    let so_pin = AuthPin::new("abcdef654321".into()); // security officer pin

    let slot = pkcs11.get_slots_with_token()?.into_iter().find(|&s| {
        pkcs11
            .get_token_info(s)
            .map(|info| info.token_initialized())
            .unwrap_or(false)
    });

    let slot = if let Some(s) = slot {
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

        empty_slot
    };

    // --- Session and login ---

    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // --- HMAC-SHA256 signature ---

    let gtk_attrs = vec![
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::ValueLen(32.into()),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Class(ObjectClass::SECRET_KEY),
    ];

    let gtk_key = session.generate_key(&Mechanism::GenericSecretKeyGen, &gtk_attrs)?;

    let mic = session.sign(&Mechanism::Sha256Hmac, gtk_key, MESSAGE)?;
    println!("HMAC-SHA256 MIC ({} bytes): {:02x?}", mic.len(), mic);

    session.verify(&Mechanism::Sha256Hmac, gtk_key, MESSAGE, &mic)?;
    println!("HMAC-SHA256 MIC verified OK");

    // --- AES-SIV encryption ---

    let ptk_attrs = vec![
        Attribute::Token(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Extractable(true),
        Attribute::ValueLen(64.into()),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Class(ObjectClass::SECRET_KEY),
    ];

    let ptk_key = session.generate_key(&Mechanism::GenericSecretKeyGen, &ptk_attrs)?;

    let ptk_raw = session.get_attributes(ptk_key, &[AttributeType::Value])?;
    let Attribute::Value(ptk_bytes) = &ptk_raw[0] else {
        anyhow::bail!("failed to extract PTK value");
    };

    let siv_key = aes_siv::Key::<Aes256SivAead>::from_slice(ptk_bytes);
    let cipher = Aes256SivAead::new(siv_key);

    let nonce = aes_siv::Nonce::default();
    let aad = b"type=data; version=1";

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: MESSAGE, aad })
        .map_err(|e| anyhow::anyhow!("AES-SIV encrypt failed: {e}"))?;
    println!(
        "AES-SIV ciphertext ({} bytes), first 8 bytes: {:02x?}",
        ciphertext.len(),
        &ciphertext[..8]
    );

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-SIV decrypt failed: {e}"))?;
    assert_eq!(plaintext, MESSAGE);
    println!("AES-SIV decrypted OK");

    Ok(())
}
