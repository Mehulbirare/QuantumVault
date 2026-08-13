#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>

// Simple XOR encryption/decryption using the shared secret as key material
void xor_cipher(const uint8_t *input, uint8_t *output, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

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
    printf("CRYSTALS-Kyber-768 Encryption Round-Trip\n");
    printf("=========================================\n");

    // 1. Generate keypair (Recipient side)
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "Memory allocation failed for keypair.\n");
        return EXIT_FAILURE;
    }

    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: Keypair generation failed.\n");
        return EXIT_FAILURE;
    }
    printf("1. Generated Kyber-768 Keypair successfully.\n");

    // 2. Prepare test data (Sender side)
    const char *plaintext = "QuantumVault-PostQuantumCryptographicFilesystem-2026";
    size_t plaintext_len = strlen(plaintext);
    printf("Original Plaintext: \"%s\" (Length: %zu bytes)\n", plaintext, plaintext_len);

    // 3. Encapsulate (Sender side)
    // Generate shared secret and KEM ciphertext using recipient's public key
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_sender = malloc(kem->length_shared_secret);
    if (kem_ciphertext == NULL || shared_secret_sender == NULL) {
        fprintf(stderr, "Memory allocation failed for sender encapsulation.\n");
        return EXIT_FAILURE;
    }

    rc = OQS_KEM_encaps(kem, kem_ciphertext, shared_secret_sender, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: Encapsulation failed.\n");
        return EXIT_FAILURE;
    }
    printf("2. Encapsulated shared secret (generated KEM ciphertext).\n");
    print_hex("   KEM Ciphertext (first 16 bytes)", kem_ciphertext, 16);
    print_hex("   Sender Shared Secret", shared_secret_sender, kem->length_shared_secret);

    // 4. Encrypt Plaintext using the sender's shared secret
    uint8_t *encrypted_data = malloc(plaintext_len + 1);
    if (encrypted_data == NULL) {
        fprintf(stderr, "Memory allocation failed for encrypted data.\n");
        return EXIT_FAILURE;
    }
    xor_cipher((const uint8_t *)plaintext, encrypted_data, plaintext_len, shared_secret_sender, kem->length_shared_secret);
    encrypted_data[plaintext_len] = '\0'; // Null-terminate for printing safety
    printf("3. Encrypted plaintext using sender's shared secret.\n");
    print_hex("   Encrypted Data", encrypted_data, plaintext_len);

    // 5. Decapsulate (Receiver side)
    // Recover the shared secret using KEM ciphertext and recipient's private key
    uint8_t *shared_secret_receiver = malloc(kem->length_shared_secret);
    if (shared_secret_receiver == NULL) {
        fprintf(stderr, "Memory allocation failed for receiver decapsulation.\n");
        return EXIT_FAILURE;
    }

    rc = OQS_KEM_decaps(kem, shared_secret_receiver, kem_ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: Decapsulation failed.\n");
        return EXIT_FAILURE;
    }
    printf("4. Decapsulated KEM ciphertext using private key.\n");
    print_hex("   Receiver Shared Secret", shared_secret_receiver, kem->length_shared_secret);

    // Verify KEM secrets match
    if (memcmp(shared_secret_sender, shared_secret_receiver, kem->length_shared_secret) != 0) {
        fprintf(stderr, "Error: Shared secrets do not match!\n");
        return EXIT_FAILURE;
    }
    printf("   Shared secrets verified and match!\n");

    // 6. Decrypt ciphertext using recovered shared secret
    uint8_t *decrypted_data = malloc(plaintext_len + 1);
    if (decrypted_data == NULL) {
        fprintf(stderr, "Memory allocation failed for decrypted data.\n");
        return EXIT_FAILURE;
    }
    xor_cipher(encrypted_data, decrypted_data, plaintext_len, shared_secret_receiver, kem->length_shared_secret);
    decrypted_data[plaintext_len] = '\0'; // Null-terminate
    printf("5. Decrypted data using receiver's shared secret.\n");
    printf("Decrypted Plaintext: \"%s\"\n", (char *)decrypted_data);

    // 7. Automated Verification
    if (strcmp(plaintext, (char *)decrypted_data) == 0) {
        printf("\nSUCCESS: Plaintext matches decrypted data exactly!\n");
    } else {
        printf("\nFAILURE: Plaintext does not match decrypted data!\n");
        free(public_key);
        free(secret_key);
        free(kem_ciphertext);
        free(shared_secret_sender);
        free(encrypted_data);
        free(shared_secret_receiver);
        free(decrypted_data);
        OQS_KEM_free(kem);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    printf("=========================================\n");

    // Free memory
    free(public_key);
    free(secret_key);
    free(kem_ciphertext);
    free(shared_secret_sender);
    free(encrypted_data);
    free(shared_secret_receiver);
    free(decrypted_data);
    OQS_KEM_free(kem);
    OQS_destroy();

    return EXIT_SUCCESS;
}
