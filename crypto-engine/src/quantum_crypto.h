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

#endif // QUANTUM_CRYPTO_H
