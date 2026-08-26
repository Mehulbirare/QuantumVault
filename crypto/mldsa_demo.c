#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void)
{
    OQS_SIG *sig = NULL;

    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *signature = NULL;

    const uint8_t message[] =
        "QuantumVault Week 3 Digital Signature Test";

    size_t signature_len = 0;
    int result = 1;

    printf("=== QuantumVault Week 3: ML-DSA-65 Test ===\n\n");

    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == NULL) {
        printf("[FAIL] ML-DSA-65 is not available.\n");
        return 1;
    }

    printf("[OK] ML-DSA-65 initialized\n");
    printf("Public key size: %zu bytes\n", sig->length_public_key);
    printf("Secret key size: %zu bytes\n", sig->length_secret_key);
    printf("Signature max size: %zu bytes\n\n",
           sig->length_signature);

    public_key = malloc(sig->length_public_key);
    secret_key = malloc(sig->length_secret_key);
    signature = malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {
        printf("[FAIL] Memory allocation failed.\n");
        goto cleanup;
    }

    if (OQS_SIG_keypair(sig, public_key, secret_key)
        != OQS_SUCCESS) {
        printf("[FAIL] Key generation failed.\n");
        goto cleanup;
    }

    printf("[OK] Keypair generated\n");

    if (OQS_SIG_sign(
            sig,
            signature,
            &signature_len,
            message,
            sizeof(message) - 1,
            secret_key) != OQS_SUCCESS) {

        printf("[FAIL] Signature generation failed.\n");
        goto cleanup;
    }

    printf("[OK] Signature generated\n");
    printf("Message size: %zu bytes\n", sizeof(message) - 1);
    printf("Signature size: %zu bytes\n", signature_len);

    if (OQS_SIG_verify(
            sig,
            message,
            sizeof(message) - 1,
            signature,
            signature_len,
            public_key) != OQS_SUCCESS) {

        printf("[FAIL] Signature verification failed.\n");
        goto cleanup;
    }

    printf("[OK] Signature verification successful\n");

    uint8_t tampered_message[] =
        "QuantumVault Week 3 Digital Signature Test!";

    if (OQS_SIG_verify(
            sig,
            tampered_message,
            sizeof(tampered_message) - 1,
            signature,
            signature_len,
            public_key) == OQS_SUCCESS) {

        printf("[FAIL] Tampered message was incorrectly accepted.\n");
        goto cleanup;
    }

    printf("[OK] Tampered message rejected\n");

    printf("\nRESULT: ML-DSA-65 SIGNATURE TEST PASSED\n");
    result = 0;

cleanup:
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);

    return result;
}
