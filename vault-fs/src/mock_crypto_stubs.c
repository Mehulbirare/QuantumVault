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
