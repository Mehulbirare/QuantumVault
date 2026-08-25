#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    OQS_init();

    const char *sig_name = OQS_SIG_alg_dilithium_3;
    OQS_SIG *sig = OQS_SIG_new(sig_name);
    if (sig == NULL) {
        fprintf(stderr, "Error: CRYSTALS-Dilithium-3 is not supported or enabled in liboqs.\n");
        return EXIT_FAILURE;
    }

    printf("=========================================\n");
    printf("CRYSTALS-Dilithium-3 Verification Engine\n");
    printf("=========================================\n");

    // 1. Load Public Key
    FILE *pub_file = fopen("dilithium_public.key", "rb");
    if (pub_file == NULL) {
        fprintf(stderr, "Error: Failed to open 'dilithium_public.key'. Run dilithium_sign first.\n");
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    uint8_t *public_key = malloc(sig->length_public_key);
    if (public_key == NULL) {
        fprintf(stderr, "Memory allocation failed for public key.\n");
        fclose(pub_file);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fread(public_key, 1, sig->length_public_key, pub_file);
    fclose(pub_file);
    printf("1. Loaded Public Key successfully (%zu bytes).\n", sig->length_public_key);

    // 2. Load Test Document
    FILE *doc_file = fopen("test_document.txt", "rb");
    if (doc_file == NULL) {
        fprintf(stderr, "Error: Failed to open 'test_document.txt'. Run dilithium_sign first.\n");
        free(public_key);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fseek(doc_file, 0, SEEK_END);
    long doc_len = ftell(doc_file);
    fseek(doc_file, 0, SEEK_SET);

    uint8_t *doc_buf = malloc(doc_len);
    if (doc_buf == NULL) {
        fprintf(stderr, "Memory allocation failed for document buffer.\n");
        fclose(doc_file);
        free(public_key);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fread(doc_buf, 1, doc_len, doc_file);
    fclose(doc_file);
    printf("2. Loaded document successfully (%ld bytes).\n", doc_len);

    // 3. Load Signature Blob
    FILE *sig_file = fopen("signature.bin", "rb");
    if (sig_file == NULL) {
        fprintf(stderr, "Error: Failed to open 'signature.bin'. Run dilithium_sign first.\n");
        free(doc_buf);
        free(public_key);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fseek(sig_file, 0, SEEK_END);
    long sig_len = ftell(sig_file);
    fseek(sig_file, 0, SEEK_SET);

    uint8_t *signature = malloc(sig_len);
    if (signature == NULL) {
        fprintf(stderr, "Memory allocation failed for signature.\n");
        fclose(sig_file);
        free(doc_buf);
        free(public_key);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    fread(signature, 1, sig_len, sig_file);
    fclose(sig_file);
    printf("3. Loaded signature successfully (%ld bytes).\n", sig_len);
    printf("-----------------------------------------\n");

    // 4. Verify Original Signature
    OQS_STATUS rc = OQS_SIG_verify(sig, doc_buf, doc_len, signature, sig_len, public_key);
    if (rc == OQS_SUCCESS) {
        printf("SUCCESS: Original document signature is VALID!\n");
    } else {
        printf("FAILURE: Original document signature is INVALID!\n");
        free(doc_buf);
        free(signature);
        free(public_key);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    // 5. Verify Tampered Document
    printf("\n4. Simulating document tampering...\n");
    // Modify one byte in the document buffer
    doc_buf[0] ^= 0xFF; // Invert the first character

    rc = OQS_SIG_verify(sig, doc_buf, doc_len, signature, sig_len, public_key);
    if (rc == OQS_SUCCESS) {
        printf("AUDIT FAILED: Tampered document was accepted as valid!\n");
        free(doc_buf);
        free(signature);
        free(public_key);
        OQS_SIG_free(sig);
        OQS_destroy();
        return EXIT_FAILURE;
    } else {
        printf("SUCCESS: Tampered document signature was REJECTED (as expected)!\n");
    }
    printf("=========================================\n");

    // Clean up
    free(doc_buf);
    free(signature);
    free(public_key);
    OQS_SIG_free(sig);
    OQS_destroy();

    return EXIT_SUCCESS;
}
