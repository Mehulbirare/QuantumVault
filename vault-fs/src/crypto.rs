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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InitializationFailed,
    KeygenFailed(i32),
    EncapsulationFailed(i32),
    DecapsulationFailed(i32),
    InvalidKeyLength,
    InvalidCiphertextLength,
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
