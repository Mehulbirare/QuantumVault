#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <oqs/oqs.h>

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Initialize liboqs
    OQS_init();

    // Use Kyber-768
    const char *kem_name = OQS_KEM_alg_kyber_768;
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (kem == NULL) {
        fprintf(stderr, "Error: CRYSTALS-Kyber-768 is not supported or enabled in liboqs.\n");
        return EXIT_FAILURE;
    }

    printf("=========================================\n");
    printf("CRYSTALS-Kyber-768 Keypair Generator\n");
    printf("=========================================\n");
    printf("Public key length:  %zu bytes\n", kem->length_public_key);
    printf("Secret key length:  %zu bytes\n", kem->length_secret_key);
    printf("-----------------------------------------\n");

    // Allocate memory for keypair
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);

    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    // Generate Keypair
    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: Keypair generation failed.\n");
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    printf("Keypair generated successfully!\n\n");
    print_hex("Public Key (first 16 bytes)", public_key, 16);
    print_hex("Secret Key (first 16 bytes)", secret_key, 16);
    printf("=========================================\n");

    // Clean up
    free(public_key);
    free(secret_key);
    OQS_KEM_free(kem);
    OQS_destroy();

    return EXIT_SUCCESS;
}
