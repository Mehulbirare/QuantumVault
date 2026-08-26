use std::fmt;
use std::sync::Once;

static CRYPTO_INIT: Once = Once::new();

#[link(name = "quantum_crypto", kind = "static")]
extern "C" {
    fn qv_crypto_init();
    fn qv_kyber_public_key_bytes() -> usize;
    fn qv_kyber_secret_key_bytes() -> usize;
    fn qv_kyber_ciphertext_bytes() -> usize;
    fn qv_kyber_shared_secret_bytes() -> usize;
    fn qv_kyber_keygen(public_key: *mut u8, secret_key: *mut u8) -> libc::c_int;
    fn qv_kyber_encaps(ciphertext: *mut u8, shared_secret: *mut u8, public_key: *const u8) -> libc::c_int;
    fn qv_kyber_decaps(shared_secret: *mut u8, ciphertext: *const u8, secret_key: *const u8) -> libc::c_int;
    fn qv_xor_cipher(input: *const u8, output: *mut u8, len: usize, key: *const u8, key_len: usize);

    fn qv_dilithium_public_key_bytes() -> usize;
    fn qv_dilithium_secret_key_bytes() -> usize;
    fn qv_dilithium_signature_bytes() -> usize;
    fn qv_dilithium_keygen(public_key: *mut u8, secret_key: *mut u8) -> libc::c_int;
    fn qv_dilithium_sign(signature: *mut u8, signature_len: *mut usize, message: *const u8, message_len: usize, secret_key: *const u8) -> libc::c_int;
    fn qv_dilithium_verify(message: *const u8, message_len: usize, signature: *const u8, signature_len: usize, public_key: *const u8) -> libc::c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InitializationFailed,
    KeygenFailed(i32),
    EncapsulationFailed(i32),
    DecapsulationFailed(i32),
    InvalidKeyLength,
    InvalidCiphertextLength,
    SignatureFailed(i32),
    VerificationFailed,
    InvalidSignatureLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InitializationFailed => write!(f, "Failed to initialize post-quantum cryptography engine"),
            CryptoError::KeygenFailed(code) => write!(f, "Kyber keypair generation failed with error code: {}", code),
            CryptoError::EncapsulationFailed(code) => write!(f, "Kyber encapsulation failed with error code: {}", code),
            CryptoError::DecapsulationFailed(code) => write!(f, "Kyber decapsulation failed with error code: {}", code),
            CryptoError::InvalidKeyLength => write!(f, "Provided key length is invalid"),
            CryptoError::InvalidCiphertextLength => write!(f, "Provided ciphertext length is invalid"),
            CryptoError::SignatureFailed(code) => write!(f, "Dilithium signing failed with error code: {}", code),
            CryptoError::VerificationFailed => write!(f, "Dilithium signature verification failed"),
            CryptoError::InvalidSignatureLength => write!(f, "Provided signature length is invalid"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Initializes the underlying post-quantum cryptography engine.
/// This is thread-safe and runs at most once.
pub fn init() {
    CRYPTO_INIT.call_once(|| unsafe {
        qv_crypto_init();
    });
}

#[derive(Clone)]
pub struct KyberKeys {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generates a new CRYSTALS-Kyber-768 keypair.
pub fn generate_keypair() -> Result<KyberKeys, CryptoError> {
    init();
    
    let pub_len = unsafe { qv_kyber_public_key_bytes() };
    let sec_len = unsafe { qv_kyber_secret_key_bytes() };
    
    if pub_len == 0 || sec_len == 0 {
        return Err(CryptoError::InitializationFailed);
    }
    
    let mut public_key = vec![0u8; pub_len];
    let mut secret_key = vec![0u8; sec_len];
    
    let result = unsafe {
        qv_kyber_keygen(public_key.as_mut_ptr(), secret_key.as_mut_ptr())
    };
    
    if result == 0 {
        Ok(KyberKeys { public_key, secret_key })
    } else {
        Err(CryptoError::KeygenFailed(result))
    }
}

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

/// Encrypts a plaintext message using CRYSTALS-Kyber-768 key encapsulation
/// and a symmetric XOR cipher keyed by the generated shared secret.
pub fn encrypt(plaintext: &[u8], public_key: &[u8]) -> Result<EncryptedData, CryptoError> {
    init();
    
    let pub_len = unsafe { qv_kyber_public_key_bytes() };
    let ct_len = unsafe { qv_kyber_ciphertext_bytes() };
    let secret_len = unsafe { qv_kyber_shared_secret_bytes() };
    
    if public_key.len() != pub_len {
        return Err(CryptoError::InvalidKeyLength);
    }
    
    let mut kem_ciphertext = vec![0u8; ct_len];
    let mut shared_secret = vec![0u8; secret_len];
    
    let encaps_res = unsafe {
        qv_kyber_encaps(kem_ciphertext.as_mut_ptr(), shared_secret.as_mut_ptr(), public_key.as_ptr())
    };
    
    if encaps_res != 0 {
        return Err(CryptoError::EncapsulationFailed(encaps_res));
    }
    
    let mut ciphertext = vec![0u8; plaintext.len()];
    unsafe {
        qv_xor_cipher(
            plaintext.as_ptr(),
            ciphertext.as_mut_ptr(),
            plaintext.len(),
            shared_secret.as_ptr(),
            shared_secret.len(),
        );
    }
    
    // Wipe shared secret in memory immediately after use
    unsafe {
        libc::memset(shared_secret.as_mut_ptr() as *mut libc::c_void, 0, secret_len);
    }
    
    Ok(EncryptedData {
        ciphertext,
        kem_ciphertext,
    })
}

/// Decrypts a ciphertext message using CRYSTALS-Kyber-768 key decapsulation
/// and a symmetric XOR cipher keyed by the recovered shared secret.
pub fn decrypt(
    ciphertext: &[u8],
    kem_ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    init();
    
    let sec_len = unsafe { qv_kyber_secret_key_bytes() };
    let ct_len = unsafe { qv_kyber_ciphertext_bytes() };
    let secret_len = unsafe { qv_kyber_shared_secret_bytes() };
    
    if secret_key.len() != sec_len {
        return Err(CryptoError::InvalidKeyLength);
    }
    if kem_ciphertext.len() != ct_len {
        return Err(CryptoError::InvalidCiphertextLength);
    }
    
    let mut shared_secret = vec![0u8; secret_len];
    
    let decaps_res = unsafe {
        qv_kyber_decaps(shared_secret.as_mut_ptr(), kem_ciphertext.as_ptr(), secret_key.as_ptr())
    };
    
    if decaps_res != 0 {
        return Err(CryptoError::DecapsulationFailed(decaps_res));
    }
    
    let mut plaintext = vec![0u8; ciphertext.len()];
    unsafe {
        qv_xor_cipher(
            ciphertext.as_ptr(),
            plaintext.as_mut_ptr(),
            ciphertext.len(),
            shared_secret.as_ptr(),
            shared_secret.len(),
        );
    }
    
    // Wipe shared secret in memory immediately after use
    unsafe {
        libc::memset(shared_secret.as_mut_ptr() as *mut libc::c_void, 0, secret_len);
    }
    
    Ok(plaintext)
}

#[derive(Clone)]
pub struct DilithiumKeys {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generates a new CRYSTALS-Dilithium-3 keypair.
pub fn generate_dilithium_keypair() -> Result<DilithiumKeys, CryptoError> {
    init();
    
    let pub_len = unsafe { qv_dilithium_public_key_bytes() };
    let sec_len = unsafe { qv_dilithium_secret_key_bytes() };
    
    if pub_len == 0 || sec_len == 0 {
        return Err(CryptoError::InitializationFailed);
    }
    
    let mut public_key = vec![0u8; pub_len];
    let mut secret_key = vec![0u8; sec_len];
    
    let result = unsafe {
        qv_dilithium_keygen(public_key.as_mut_ptr(), secret_key.as_mut_ptr())
    };
    
    if result == 0 {
        Ok(DilithiumKeys { public_key, secret_key })
    } else {
        Err(CryptoError::KeygenFailed(result))
    }
}

/// Signs a message using CRYSTALS-Dilithium-3.
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    init();
    
    let sec_len = unsafe { qv_dilithium_secret_key_bytes() };
    let sig_max_len = unsafe { qv_dilithium_signature_bytes() };
    
    if secret_key.len() != sec_len {
        return Err(CryptoError::InvalidKeyLength);
    }
    
    let mut signature = vec![0u8; sig_max_len];
    let mut signature_len = 0;
    
    let result = unsafe {
        qv_dilithium_sign(
            signature.as_mut_ptr(),
            &mut signature_len,
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
        )
    };
    
    if result == 0 {
        signature.truncate(signature_len);
        Ok(signature)
    } else {
        Err(CryptoError::SignatureFailed(result))
    }
}

/// Verifies a signature using CRYSTALS-Dilithium-3.
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
    init();
    
    let pub_len = unsafe { qv_dilithium_public_key_bytes() };
    
    if public_key.len() != pub_len {
        return Err(CryptoError::InvalidKeyLength);
    }
    
    let result = unsafe {
        qv_dilithium_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
        )
    };
    
    if result == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_and_keygen() {
        init();
        let keys = generate_keypair().expect("Keypair generation failed");
        
        let expected_pub_len = unsafe { qv_kyber_public_key_bytes() };
        let expected_sec_len = unsafe { qv_kyber_secret_key_bytes() };
        
        assert_eq!(keys.public_key.len(), expected_pub_len);
        assert_eq!(keys.secret_key.len(), expected_sec_len);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = generate_keypair().expect("Keypair generation failed");
        
        let test_cases = vec![
            b"".as_slice(),
            b"Hello Post-Quantum FFI!".as_slice(),
            b"A".repeat(1000).as_slice(),
        ];
        
        for plaintext in test_cases {
            let encrypted = encrypt(plaintext, &keys.public_key).expect("Encryption failed");
            let decrypted = decrypt(&encrypted.ciphertext, &encrypted.kem_ciphertext, &keys.secret_key)
                .expect("Decryption failed");
                
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }

    #[test]
    fn test_invalid_lengths() {
        let keys = generate_keypair().expect("Keypair generation failed");
        let msg = b"Testing length constraints";
        
        // 1. Invalid public key length
        let mut bad_pub_key = keys.public_key.clone();
        bad_pub_key.pop();
        let res = encrypt(msg, &bad_pub_key);
        assert_eq!(res.err(), Some(CryptoError::InvalidKeyLength));
        
        // Encrypt properly to get valid ciphertext and KEM ciphertext
        let encrypted = encrypt(msg, &keys.public_key).expect("Encryption failed");
        
        // 2. Invalid secret key length
        let mut bad_sec_key = keys.secret_key.clone();
        bad_sec_key.push(0);
        let res = decrypt(&encrypted.ciphertext, &encrypted.kem_ciphertext, &bad_sec_key);
        assert_eq!(res.err(), Some(CryptoError::InvalidKeyLength));
        
        // 3. Invalid KEM ciphertext length
        let mut bad_kem_ciphertext = encrypted.kem_ciphertext.clone();
        bad_kem_ciphertext.pop();
        let res = decrypt(&encrypted.ciphertext, &bad_kem_ciphertext, &keys.secret_key);
        assert_eq!(res.err(), Some(CryptoError::InvalidCiphertextLength));
    }

    #[test]
    fn test_dilithium_keygen_and_sign_verify_roundtrip() {
        let keys = generate_dilithium_keypair().expect("Dilithium keypair generation failed");
        
        let expected_pub_len = unsafe { qv_dilithium_public_key_bytes() };
        let expected_sec_len = unsafe { qv_dilithium_secret_key_bytes() };
        
        assert_eq!(keys.public_key.len(), expected_pub_len);
        assert_eq!(keys.secret_key.len(), expected_sec_len);

        let test_message = b"Verification test message for CRYSTALS-Dilithium-3!";
        let signature = sign(test_message, &keys.secret_key).expect("Dilithium signing failed");
        
        let verify_res = verify(test_message, &signature, &keys.public_key);
        assert!(verify_res.is_ok(), "Dilithium verification failed for valid message and signature");
    }

    #[test]
    fn test_dilithium_tampering() {
        let keys = generate_dilithium_keypair().expect("Dilithium keypair generation failed");
        let test_message = b"Original document message contents";
        
        let signature = sign(test_message, &keys.secret_key).expect("Dilithium signing failed");
        
        // 1. Verify that a modified message fails verification
        let mut tampered_message = test_message.to_vec();
        if !tampered_message.is_empty() {
            tampered_message[0] ^= 0xFF; // Modify one character
        }
        let verify_res = verify(&tampered_message, &signature, &keys.public_key);
        assert_eq!(verify_res.err(), Some(CryptoError::VerificationFailed));
        
        // 2. Verify that a modified signature fails verification
        let mut tampered_signature = signature.clone();
        if !tampered_signature.is_empty() {
            tampered_signature[0] ^= 0xFF; // Modify signature byte
        }
        let verify_res = verify(test_message, &tampered_signature, &keys.public_key);
        assert_eq!(verify_res.err(), Some(CryptoError::VerificationFailed));
    }
}

