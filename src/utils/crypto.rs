use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn generate_key_iv() -> (Vec<u8>, Vec<u8>) {
    let key: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32) // key size for AES 256
        .collect();

    let iv: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16) // block size for AES
        .collect();

    (key, iv)
}

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(encrypted_data).unwrap()
}
