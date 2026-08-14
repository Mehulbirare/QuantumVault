#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void)
{
    OQS_KEM *kem = NULL;

    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_enc = NULL;
    uint8_t *shared_secret_dec = NULL;

    int result = 1;

    printf("=== QuantumVault Week 1: ML-KEM-768 Test ===\n\n");

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL) {
        printf("[FAIL] ML-KEM-768 is not available.\n");
        return 1;
    }

    printf("[OK] ML-KEM-768 initialized\n");
    printf("Public key size: %zu bytes\n", kem->length_public_key);
    printf("Secret key size: %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext size: %zu bytes\n", kem->length_ciphertext);
    printf("Shared secret size: %zu bytes\n\n", kem->length_shared_secret);

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    ciphertext = malloc(kem->length_ciphertext);
    shared_secret_enc = malloc(kem->length_shared_secret);
    shared_secret_dec = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_enc || !shared_secret_dec) {
        printf("[FAIL] Memory allocation failed.\n");
        goto cleanup;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("[FAIL] Key generation failed.\n");
        goto cleanup;
    }

    printf("[OK] Keypair generated\n");

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key)
        != OQS_SUCCESS) {
        printf("[FAIL] Encapsulation failed.\n");
        goto cleanup;
    }

    printf("[OK] Encapsulation successful\n");

    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key)
        != OQS_SUCCESS) {
        printf("[FAIL] Decapsulation failed.\n");
        goto cleanup;
    }

    printf("[OK] Decapsulation successful\n");

    if (memcmp(shared_secret_enc,
               shared_secret_dec,
               kem->length_shared_secret) == 0) {

        printf("[OK] Shared secrets MATCH\n");
        printf("\nRESULT: ML-KEM-768 TEST PASSED\n");
        result = 0;

    } else {
        printf("[FAIL] Shared secrets DO NOT MATCH\n");
    }

cleanup:
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);

    return result;
}
