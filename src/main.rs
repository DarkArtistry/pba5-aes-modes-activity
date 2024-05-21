//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};

use rand::Rng;



///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
	todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;

	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.clone_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
	let mut data = Vec::new();
	for block in blocks {
		data.extend_from_slice(&block);
	}

	data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let number_pad_bytes = data[data.len() - 1] as usize;
    let mut data = data;
    if number_pad_bytes <= data.len() && number_pad_bytes > 0 {
        data.truncate(data.len() - number_pad_bytes);
    }
    data
}


/// XOR two blocks of data together.
fn xor(block1: [u8; BLOCK_SIZE], block2: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	let mut result = [0; BLOCK_SIZE];
	for i in 0..BLOCK_SIZE {
		result[i] = block1[i] ^ block2[i];
	}
	result
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
	

	let padded_data = pad(plain_text.clone());
	let group_data = group(padded_data.clone());

	let mut cipher_text = Vec::new();
	

	for block in group_data {
		let encrypted_block = aes_encrypt(block, &key);
		cipher_text.extend_from_slice(&encrypted_block);
	}

	cipher_text

}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	
	let group_data = group(cipher_text);
	

	let mut plain_text = Vec::new();
	for block in group_data {
		let decrypted_block = aes_decrypt(block, &key);
		plain_text.extend_from_slice(&decrypted_block);
	}

	un_pad(plain_text)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random initialization vector for the first block.

	let init_vector = [0; BLOCK_SIZE];
	
	let mut cipher_text = Vec::new();

	let mut prev_block = init_vector;
	let padded_data = pad(plain_text.clone());

	for block in group(padded_data.clone()) {
		let xored_block = xor(block, prev_block);
        let encrypted_block = aes_encrypt(xored_block, &key);
        cipher_text.extend_from_slice(&encrypted_block);
		prev_block = encrypted_block;
    }

	cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	
	let init_vector = [0; BLOCK_SIZE];
	
	let mut plain_text = Vec::new();

	let mut prev_block = init_vector;
	for block in group(cipher_text.clone()) {
		let decrypted_block = aes_decrypt(block, &key);
		let xored_block = xor(decrypted_block, prev_block);
		plain_text.extend_from_slice(&xored_block);
		prev_block = block;
	}

	un_pad(plain_text)
}

fn increment_counter(counter: &mut [u8; 16]) {
    for i in counter.iter_mut().rev() {
        *i += 1;
        if *i != 0 {
            break;
        }
    }
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random nonce
	
	let mut nonce = [0; 16];
	rand::thread_rng().fill(&mut nonce[0..16]);

	let mut cipher_text = Vec::new();
	
	let padded_data = pad(plain_text.clone());

	let mut v = nonce;
	for block in group(padded_data.clone()) {
		let encrypted_v = aes_encrypt(v, &key);
		let xored_block = xor(block, encrypted_v);
		cipher_text.extend_from_slice(&xored_block);
		increment_counter(&mut v);
    }

	
	cipher_text.extend_from_slice(&nonce);
	cipher_text
}

fn ctr_decrypt(mut cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    
	let nonce_vec = cipher_text[cipher_text.len() - 16..cipher_text.len()].to_vec();
	let nonce: [u8; 16] = nonce_vec.try_into().expect("Nonce length is not 16");
	let cipher_text = cipher_text[0..cipher_text.len() - 16].to_vec();
	
 
    let mut plain_text = Vec::new();

	let mut v = nonce;
    for block in group(cipher_text.clone()) {
        let encrypted_v = aes_encrypt(v, &key);
        let xored_block = xor(block, encrypted_v);
        plain_text.extend_from_slice(&xored_block);
        increment_counter(&mut v);
    }

    un_pad(plain_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad() {
		let data = vec![1, 2, 3, 4, 5, 6, 7];
		let padded_data = pad(data.clone());
		assert_eq!(padded_data.len(), 16);
		assert_eq!(padded_data[7], 9);
		assert_eq!(un_pad(padded_data), data);
	}

	#[test]
	fn test_group() {
		let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
		let padded_data = pad(data.clone());
		let grouped_data = group(padded_data.clone());
		assert_eq!(grouped_data.len(), 1);
		assert_eq!(un_group(grouped_data), padded_data);
	}

	#[test]
	fn test_xor() {
		let block1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
		let block2 = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
		let result = xor(block1, block2);

		
		assert_eq!(result, [17, 13, 13, 9, 9, 13, 13, 1, 1, 13, 13, 9, 9, 13, 13, 17]);
	}

	#[test]
	fn test_ecb() {
		let key = [1; 16];
		let plain_text = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
	
		let cipher_text = ecb_encrypt(plain_text.to_vec().clone(), key);
		
		let decrypted_text = ecb_decrypt(cipher_text.clone(), key);
		
		assert_eq!(plain_text.to_vec(), decrypted_text);


	}

	
	#[test]
	fn test_ecb_string() {
		let key = [1; 16];
		let plain_text = "Hello, World!";
	
		let cipher_text = ecb_encrypt(plain_text.as_bytes().to_vec().clone(), key);

		let decrypted_text = ecb_decrypt(cipher_text.clone(), key);
		
		assert_eq!(plain_text.as_bytes().to_vec(), decrypted_text);
	}

	#[test]
	fn test_cbc() {
		let key = [1; 16];
		let plain_text = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
	
		let cipher_text = cbc_encrypt(plain_text.to_vec().clone(), key);
		
		let decrypted_text = cbc_decrypt(cipher_text.clone(), key);
		
		assert_eq!(plain_text.to_vec(), decrypted_text);
	}

	#[test]
	fn test_ctr() {
		let key = [1; 16];
		let plain_text = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
	
		let cipher_text = ctr_encrypt(plain_text.to_vec().clone(), key);
		
		let decrypted_text = ctr_decrypt(cipher_text.clone(), key);
		
		assert_eq!(plain_text.to_vec(), decrypted_text);
	}
}


