#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    OQS_init();

    const char *sig_name = OQS_SIG_alg_dilithium_3;
    OQS_SIG *sig = OQS_SIG_new(sig_name);
    if (sig == NULL) {
        fprintf(stderr, "Error: CRYSTALS-Dilithium-3 is not supported or enabled in liboqs.\n");
        return EXIT_FAILURE;
    }

    printf("=========================================\n");
    printf("CRYSTALS-Dilithium-3 File Signing Engine\n");
    printf("=========================================\n");
    printf("Public key length:  %zu bytes\n", sig->length_public_key);
    printf("Secret key length:  %zu bytes\n", sig->length_secret_key);
    printf("Max signature len:  %zu bytes\n", sig->length_signature);
    printf("-----------------------------------------\n");

    // 1. Generate keypair
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "Memory allocation failed for keypair.\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: Keypair generation failed.\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    printf("1. Generated Dilithium-3 Keypair successfully.\n");

    // Save keys to files
    FILE *pub_file = fopen("dilithium_public.key", "wb");
    FILE *sec_file = fopen("dilithium_secret.key", "wb");
    if (pub_file && sec_file) {
        fwrite(public_key, 1, sig->length_public_key, pub_file);
        fwrite(secret_key, 1, sig->length_secret_key, sec_file);
        printf("   Keys saved to 'dilithium_public.key' and 'dilithium_secret.key'.\n");
    }
    if (pub_file) fclose(pub_file);
    if (sec_file) fclose(sec_file);

    // 2. Sign a test file
    const char *test_filename = "test_document.txt";
    const char *test_content = "QuantumVault Digital Signature Verification Test Document - 2026";
    size_t message_len = strlen(test_content);

    FILE *doc_file = fopen(test_filename, "w");
    if (doc_file == NULL) {
        fprintf(stderr, "Failed to create test file.\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fwrite(test_content, 1, message_len, doc_file);
    fclose(doc_file);
    printf("2. Created test document '%s' with content: \"%s\"\n", test_filename, test_content);

    // Read the document for signing
    FILE *read_doc = fopen(test_filename, "rb");
    if (read_doc == NULL) {
        fprintf(stderr, "Failed to read test document.\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fseek(read_doc, 0, SEEK_END);
    long doc_len = ftell(read_doc);
    fseek(read_doc, 0, SEEK_SET);

    uint8_t *doc_buf = malloc(doc_len);
    if (doc_buf == NULL) {
        fprintf(stderr, "Memory allocation failed for document buffer.\n");
        fclose(read_doc);
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fread(doc_buf, 1, doc_len, read_doc);
    fclose(read_doc);

    // Perform signing
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len = 0;
    if (signature == NULL) {
        fprintf(stderr, "Memory allocation failed for signature.\n");
        free(doc_buf);
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    rc = OQS_SIG_sign(sig, signature, &signature_len, doc_buf, doc_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: Signing failed.\n");
        free(doc_buf);
        free(signature);
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    printf("3. Signed document successfully. Signature generated.\n");
    printf("   Signature length: %zu bytes\n", signature_len);
    print_hex("   Signature (first 16 bytes)", signature, 16);

    // Save signature to blob file
    FILE *sig_file = fopen("signature.bin", "wb");
    if (sig_file == NULL) {
        fprintf(stderr, "Failed to save signature blob.\n");
        free(doc_buf);
        free(signature);
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fwrite(signature, 1, signature_len, sig_file);
    fclose(sig_file);
    printf("4. Saved signature blob to 'signature.bin'.\n");
    printf("=========================================\n");

    // Clean up
    free(doc_buf);
    free(signature);
    free(public_key);
    free(secret_key);
    OQS_SIG_free(sig);
    OQS_destroy();

    return EXIT_SUCCESS;
}
