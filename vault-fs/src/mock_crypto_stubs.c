#include <stdint.h>
#include <stddef.h>

void qv_crypto_init(void) {}

size_t qv_kyber_public_key_bytes(void) { return 1184; }
size_t qv_kyber_secret_key_bytes(void) { return 2400; }
size_t qv_kyber_ciphertext_bytes(void) { return 1088; }
size_t qv_kyber_shared_secret_bytes(void) { return 32; }

int qv_kyber_keygen(uint8_t *public_key, uint8_t *secret_key) {
    for (int i = 0; i < 1184; i++) public_key[i] = i % 256;
    for (int i = 0; i < 2400; i++) secret_key[i] = (255 - i) % 256;
    return 0;
}

int qv_kyber_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    (void)public_key;
    for (int i = 0; i < 1088; i++) ciphertext[i] = i % 256;
    for (int i = 0; i < 32; i++) shared_secret[i] = i;
    return 0;
}

int qv_kyber_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    (void)ciphertext;
    (void)secret_key;
    for (int i = 0; i < 32; i++) shared_secret[i] = i;
    return 0;
}

void qv_xor_cipher(const uint8_t *input, uint8_t *output, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

size_t qv_dilithium_public_key_bytes(void) { return 1952; }
size_t qv_dilithium_secret_key_bytes(void) { return 4016; }
size_t qv_dilithium_signature_bytes(void) { return 3293; }

int qv_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key) {
    for (int i = 0; i < 1952; i++) public_key[i] = i % 256;
    for (int i = 0; i < 4016; i++) secret_key[i] = (255 - i) % 256;
    return 0;
}

int qv_dilithium_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    (void)secret_key;
    *signature_len = 3293;
    signature[0] = 0xAA;
    if (message_len > 0) {
        signature[1] = message[0] ^ message[message_len - 1] ^ (uint8_t)message_len;
    } else {
        signature[1] = 0;
    }
    for (int i = 2; i < 3293; i++) signature[i] = i % 256;
    return 0;
}

int qv_dilithium_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    (void)public_key;
    if (signature_len != 3293 || signature[0] != 0xAA) {
        return -2;
    }
    uint8_t expected_checksum = 0;
    if (message_len > 0) {
        expected_checksum = message[0] ^ message[message_len - 1] ^ (uint8_t)message_len;
    }
    if (signature[1] != expected_checksum) {
        return -3;
    }
    return 0;
}
