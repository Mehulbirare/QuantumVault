#include <stdio.h>
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

    OQS_KEM_free(kem);

    return 1;
}
