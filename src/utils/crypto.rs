use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

// Define type alias for AES-256 CBC mode
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn generate_key_iv() -> (Vec<u8>, Vec<u8>) {
    let key: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32) // key size for AES 256
        .map(|b| b as u8)
        .collect();

    let iv: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16) // block size for AES
        .map(|b| b as u8)
        .collect();

    (key, iv)
}

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256CbcEnc::new_from_slices(key, iv).unwrap();

    let block_size = Encryptor::<Aes256>::block_size();

    // Calculate the size of the padded buffer
    let mut buffer = Vec::with_capacity(data.len() + block_size);
    buffer.extend_from_slice(data);
    // let pos = buffer.len();

    // Apply padding
    // let pad_len = block_size - (buffer.len() % block_size);
    // buffer.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let pad_len = block_size - (data.len() % block_size);
    let mut buffer = Vec::with_capacity(data.len() + pad_len);
    buffer.extend_from_slice(data);
    buffer.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    // Encrypt
    let mut blocks = buffer.chunks_exact_mut(block_size)
        .map(GenericArray::from_mut_slice)
        .collect::<Vec<_>>();

    for block in blocks.iter_mut() {
        cipher.encrypt_block_mut(block);
    }

    buffer


    // let mut buffer = vec![0u8; data.len() + Aes256CbcEnc::block_size()];
    // buffer.extend_from_slice(data);
    // let pos = Pkcs7::pad(&mut buffer, Aes256CbcEnc::block_size()).unwrap();
    // cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, pos).unwrap();
    // buffer
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256CbcDec::new_from_slices(key, iv).unwrap();
    let mut buffer = encrypted_data.to_vec();

    let mut blocks = buffer.chunks_exact_mut(Decryptor::<Aes256>::block_size())
        .map(GenericArray::from_mut_slice)
        .collect::<Vec<_>>();

    for block in blocks.iter_mut() {
        cipher.decrypt_block_mut(block);
    }

    let pad_len = *buffer.last().unwrap() as usize;
    buffer.truncate(buffer.len() - pad_len);
    buffer
}