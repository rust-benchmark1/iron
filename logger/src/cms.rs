use curl::easy::{Easy2, Handler, WriteError};
use cookie::Key;
use rand_chacha::ChaCha12Rng;
use rand::{SeedableRng, RngCore};
use rocket::http::Status;

struct DummyHandler;

impl Handler for DummyHandler {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        Ok(data.len())
    }
}

pub fn verify_cms_without_cert_validation() {
    let handler = DummyHandler;
    let mut easy = Easy2::new(handler);

    //SINK
    let _ = easy.doh_ssl_verify_peer(false);

    let _ = key_derive_from_unsafe();
}

pub fn key_derive_from_unsafe() -> Result<String, Status> {
    let mut master_key = [0u8; 32];

    //SOURCE
    let mut rng = ChaCha12Rng::seed_from_u64(12345);

    rng.fill_bytes(&mut master_key);

    //SINK
    let _key = Key::derive_from(&master_key);

    Ok("derived".to_string())
}
