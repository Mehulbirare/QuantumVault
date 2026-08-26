#ifndef QUANTUM_CRYPTO_H
#define QUANTUM_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Initialize the crypto engine. Safe to call multiple times.
void qv_crypto_init(void);

// Get Kyber-768 parameters
size_t qv_kyber_public_key_bytes(void);
size_t qv_kyber_secret_key_bytes(void);
size_t qv_kyber_ciphertext_bytes(void);
size_t qv_kyber_shared_secret_bytes(void);

// Key generation.
// public_key must point to a buffer of at least qv_kyber_public_key_bytes() bytes.
// secret_key must point to a buffer of at least qv_kyber_secret_key_bytes() bytes.
// Returns 0 on success, non-zero on error.
int qv_kyber_keygen(uint8_t *public_key, uint8_t *secret_key);

// Encapsulation.
// ciphertext must point to a buffer of at least qv_kyber_ciphertext_bytes() bytes.
// shared_secret must point to a buffer of at least qv_kyber_shared_secret_bytes() bytes.
// public_key must point to a valid public key buffer.
// Returns 0 on success, non-zero on error.
int qv_kyber_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);

// Decapsulation.
// shared_secret must point to a buffer of at least qv_kyber_shared_secret_bytes() bytes.
// ciphertext must point to a valid ciphertext buffer.
// secret_key must point to a valid secret key buffer.
// Returns 0 on success, non-zero on error.
int qv_kyber_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

// XOR Cipher.
// Performs input ^ key stream, writing to output.
void qv_xor_cipher(const uint8_t *input, uint8_t *output, size_t len, const uint8_t *key, size_t key_len);

// Get Dilithium-3 parameters
size_t qv_dilithium_public_key_bytes(void);
size_t qv_dilithium_secret_key_bytes(void);
size_t qv_dilithium_signature_bytes(void);

// Key generation for Dilithium-3.
// public_key must point to a buffer of at least qv_dilithium_public_key_bytes() bytes.
// secret_key must point to a buffer of at least qv_dilithium_secret_key_bytes() bytes.
// Returns 0 on success, non-zero on error.
int qv_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key);

// Sign a message using CRYSTALS-Dilithium-3.
// signature must point to a buffer of at least qv_dilithium_signature_bytes() bytes.
// signature_len will receive the actual signature size.
// Returns 0 on success, non-zero on error.
int qv_dilithium_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

// Verify a message signature using CRYSTALS-Dilithium-3.
// Returns 0 on success (signature is valid), non-zero on error or verification failure.
int qv_dilithium_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif // QUANTUM_CRYPTO_H
