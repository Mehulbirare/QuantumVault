#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

int quantumvault_ffi_test(void) {
    OQS_KEM *kem = NULL;

    printf("[C] Initializing ML-KEM-768...\n");

    kem = OQS_KEM_new("ML-KEM-768");

    if (kem == NULL) {
        printf("[C] ERROR: Failed to initialize ML-KEM-768\n");
        return 0;
    }

    printf("[C] ML-KEM-768 initialized successfully\n");
    printf("[C] Public key size: %zu bytes\n", kem->length_public_key);
    printf("[C] Secret key size: %zu bytes\n", kem->length_secret_key);
    printf("[C] Ciphertext size: %zu bytes\n", kem->length_ciphertext);
    printf("[C] Shared secret size: %zu bytes\n", kem->length_shared_secret);

    unsigned char *public_key = OQS_MEM_malloc(kem->length_public_key);
    unsigned char *secret_key = OQS_MEM_malloc(kem->length_secret_key);
    unsigned char *ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
    unsigned char *shared_secret_enc = OQS_MEM_malloc(kem->length_shared_secret);
    unsigned char *shared_secret_dec = OQS_MEM_malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_enc || !shared_secret_dec) {
        printf("[C] ERROR: Memory allocation failed\n");
        OQS_MEM_secure_free(public_key, kem->length_public_key);
        OQS_MEM_secure_free(secret_key, kem->length_secret_key);
        OQS_MEM_secure_free(ciphertext, kem->length_ciphertext);
        OQS_MEM_secure_free(shared_secret_enc, kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_dec, kem->length_shared_secret);
        OQS_KEM_free(kem);
        return 0;
    }

    printf("[C] Generating ML-KEM-768 keypair...\n");

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("[C] ERROR: Keypair generation failed\n");
        goto cleanup_failure;
    }

    printf("[C] Keypair generated successfully\n");

    printf("[C] Encapsulating shared secret...\n");

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS) {
        printf("[C] ERROR: Encapsulation failed\n");
        goto cleanup_failure;
    }

    printf("[C] Encapsulation successful\n");

    printf("[C] Decapsulating shared secret...\n");

    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key) != OQS_SUCCESS) {
        printf("[C] ERROR: Decapsulation failed\n");
        goto cleanup_failure;
    }

    printf("[C] Decapsulation successful\n");

    if (memcmp(shared_secret_enc,
               shared_secret_dec,
               kem->length_shared_secret) != 0) {
        printf("[C] ERROR: Shared secrets DO NOT match\n");
        goto cleanup_failure;
    }

    printf("[C] SUCCESS: Shared secrets match!\n");
    printf("[C] ML-KEM-768 key encapsulation cycle completed successfully\n");

    OQS_MEM_secure_free(public_key, kem->length_public_key);
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    OQS_MEM_secure_free(ciphertext, kem->length_ciphertext);
    OQS_MEM_secure_free(shared_secret_enc, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_dec, kem->length_shared_secret);
    OQS_KEM_free(kem);

    return 1;

cleanup_failure:
    OQS_MEM_secure_free(public_key, kem->length_public_key);
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    OQS_MEM_secure_free(ciphertext, kem->length_ciphertext);
    OQS_MEM_secure_free(shared_secret_enc, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_dec, kem->length_shared_secret);
    OQS_KEM_free(kem);

    return 0;
}
