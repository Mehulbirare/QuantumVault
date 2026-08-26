#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "quantum_crypto.h"

void qv_crypto_init(void) {
    OQS_init();
}

size_t qv_kyber_public_key_bytes(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return 0;
    size_t len = kem->length_public_key;
    OQS_KEM_free(kem);
    return len;
}

size_t qv_kyber_secret_key_bytes(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return 0;
    size_t len = kem->length_secret_key;
    OQS_KEM_free(kem);
    return len;
}

size_t qv_kyber_ciphertext_bytes(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return 0;
    size_t len = kem->length_ciphertext;
    OQS_KEM_free(kem);
    return len;
}

size_t qv_kyber_shared_secret_bytes(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return 0;
    size_t len = kem->length_shared_secret;
    OQS_KEM_free(kem);
    return len;
}

int qv_kyber_keygen(uint8_t *public_key, uint8_t *secret_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return -1;
    
    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_free(kem);
    
    return (rc == OQS_SUCCESS) ? 0 : -2;
}

int qv_kyber_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return -1;
    
    OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);
    
    return (rc == OQS_SUCCESS) ? 0 : -2;
}

int qv_kyber_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return -1;
    
    OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    OQS_KEM_free(kem);
    
    return (rc == OQS_SUCCESS) ? 0 : -2;
}

void qv_xor_cipher(const uint8_t *input, uint8_t *output, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

size_t qv_dilithium_public_key_bytes(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return 0;
    size_t len = sig->length_public_key;
    OQS_SIG_free(sig);
    return len;
}

size_t qv_dilithium_secret_key_bytes(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return 0;
    size_t len = sig->length_secret_key;
    OQS_SIG_free(sig);
    return len;
}

size_t qv_dilithium_signature_bytes(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return 0;
    size_t len = sig->length_signature;
    OQS_SIG_free(sig);
    return len;
}

int qv_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return -1;
    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? 0 : -2;
}

int qv_dilithium_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return -1;
    OQS_STATUS rc = OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key);
    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? 0 : -2;
}

int qv_dilithium_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return -1;
    OQS_STATUS rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? 0 : -2;
}
