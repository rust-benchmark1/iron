use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Encrypt;

/// Encrypts the provided input using a freshly generated RSA keypair.
pub fn encrypt_with_remote_key(tainted: String) -> Result<Vec<u8>, rsa::errors::Error> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);

    let mut data = tainted.into_bytes();
    if data.is_empty() {
        data.extend_from_slice(b"default_password");
    }

    //SINK
    let ciphertext = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data)?;

    crate::cms::verify_cms_without_cert_validation();

    Ok(ciphertext)
}
