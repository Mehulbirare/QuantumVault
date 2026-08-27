#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <oqs/oqs.h>

#define QV_PUBLIC_KEY_FILE "/tmp/quantumvault_mldsa_public_key.bin"

/*
 * ML-KEM-768 test
 */
int quantumvault_ffi_test(void)
{
    OQS_KEM *kem = NULL;

    printf("[C] Initializing ML-KEM-768...\n");

    kem = OQS_KEM_new("ML-KEM-768");

    if (kem == NULL) {
        printf("[C] ERROR: Failed to initialize ML-KEM-768\n");
        return 0;
    }

    printf("[C] ML-KEM-768 initialized successfully\n");
    printf("[C] Public key size: %zu bytes\n",
           kem->length_public_key);
    printf("[C] Secret key size: %zu bytes\n",
           kem->length_secret_key);
    printf("[C] Ciphertext size: %zu bytes\n",
           kem->length_ciphertext);
    printf("[C] Shared secret size: %zu bytes\n",
           kem->length_shared_secret);

    uint8_t *public_key =
        OQS_MEM_malloc(kem->length_public_key);

    uint8_t *secret_key =
        OQS_MEM_malloc(kem->length_secret_key);

    uint8_t *ciphertext =
        OQS_MEM_malloc(kem->length_ciphertext);

    uint8_t *shared_secret_enc =
        OQS_MEM_malloc(kem->length_shared_secret);

    uint8_t *shared_secret_dec =
        OQS_MEM_malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_enc || !shared_secret_dec) {

        printf("[C] ERROR: Memory allocation failed\n");

        OQS_MEM_secure_free(
            public_key,
            kem->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            kem->length_secret_key);

        OQS_MEM_secure_free(
            ciphertext,
            kem->length_ciphertext);

        OQS_MEM_secure_free(
            shared_secret_enc,
            kem->length_shared_secret);

        OQS_MEM_secure_free(
            shared_secret_dec,
            kem->length_shared_secret);

        OQS_KEM_free(kem);

        return 0;
    }

    printf("[C] Generating ML-KEM-768 keypair...\n");

    if (OQS_KEM_keypair(
            kem,
            public_key,
            secret_key) != OQS_SUCCESS) {

        printf("[C] ERROR: Keypair generation failed\n");
        goto kem_cleanup_failure;
    }

    printf("[C] Keypair generated successfully\n");

    printf("[C] Encapsulating shared secret...\n");

    if (OQS_KEM_encaps(
            kem,
            ciphertext,
            shared_secret_enc,
            public_key) != OQS_SUCCESS) {

        printf("[C] ERROR: Encapsulation failed\n");
        goto kem_cleanup_failure;
    }

    printf("[C] Encapsulation successful\n");

    printf("[C] Decapsulating shared secret...\n");

    if (OQS_KEM_decaps(
            kem,
            shared_secret_dec,
            ciphertext,
            secret_key) != OQS_SUCCESS) {

        printf("[C] ERROR: Decapsulation failed\n");
        goto kem_cleanup_failure;
    }

    printf("[C] Decapsulation successful\n");

    if (memcmp(
            shared_secret_enc,
            shared_secret_dec,
            kem->length_shared_secret) != 0) {

        printf("[C] ERROR: Shared secrets DO NOT match\n");
        goto kem_cleanup_failure;
    }

    printf("[C] SUCCESS: Shared secrets match!\n");
    printf("[C] ML-KEM-768 key encapsulation cycle completed successfully\n");

    OQS_MEM_secure_free(
        public_key,
        kem->length_public_key);

    OQS_MEM_secure_free(
        secret_key,
        kem->length_secret_key);

    OQS_MEM_secure_free(
        ciphertext,
        kem->length_ciphertext);

    OQS_MEM_secure_free(
        shared_secret_enc,
        kem->length_shared_secret);

    OQS_MEM_secure_free(
        shared_secret_dec,
        kem->length_shared_secret);

    OQS_KEM_free(kem);

    return 1;

kem_cleanup_failure:

    OQS_MEM_secure_free(
        public_key,
        kem->length_public_key);

    OQS_MEM_secure_free(
        secret_key,
        kem->length_secret_key);

    OQS_MEM_secure_free(
        ciphertext,
        kem->length_ciphertext);

    OQS_MEM_secure_free(
        shared_secret_enc,
        kem->length_shared_secret);

    OQS_MEM_secure_free(
        shared_secret_dec,
        kem->length_shared_secret);

    OQS_KEM_free(kem);

    return 0;
}


/*
 * ML-DSA-65 signature test
 */
int quantumvault_mldsa_test(void)
{
    OQS_SIG *sig = NULL;

    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *signature = NULL;

    const uint8_t message[] =
        "QuantumVault ML-DSA-65 signature test";

    uint8_t tampered_message[] =
        "QuantumVault ML-DSA-65 signature TEST";

    size_t signature_len = 0;

    int result = 0;

    printf("[C] Initializing ML-DSA-65...\n");

    sig = OQS_SIG_new("ML-DSA-65");

    if (sig == NULL) {
        printf("[C] ERROR: Failed to initialize ML-DSA-65\n");
        return 0;
    }

    printf("[C] ML-DSA-65 initialized successfully\n");

    printf("[C] Public key size: %zu bytes\n",
           sig->length_public_key);

    printf("[C] Secret key size: %zu bytes\n",
           sig->length_secret_key);

    printf("[C] Signature size: %zu bytes\n",
           sig->length_signature);

    public_key =
        OQS_MEM_malloc(sig->length_public_key);

    secret_key =
        OQS_MEM_malloc(sig->length_secret_key);

    signature =
        OQS_MEM_malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {

        printf("[C] ERROR: ML-DSA memory allocation failed\n");
        goto mldsa_test_cleanup;
    }

    printf("[C] Generating ML-DSA-65 keypair...\n");

    if (OQS_SIG_keypair(
            sig,
            public_key,
            secret_key) != OQS_SUCCESS) {

        printf("[C] ERROR: ML-DSA keypair generation failed\n");
        goto mldsa_test_cleanup;
    }

    printf("[C] Keypair generated successfully\n");

    printf("[C] Signing message...\n");

    if (OQS_SIG_sign(
            sig,
            signature,
            &signature_len,
            message,
            sizeof(message) - 1,
            secret_key) != OQS_SUCCESS) {

        printf("[C] ERROR: ML-DSA signature generation failed\n");
        goto mldsa_test_cleanup;
    }

    printf("[C] Signature generated successfully\n");

    printf("[C] Signature size: %zu bytes\n",
           signature_len);

    printf("[C] Verifying signature...\n");

    if (OQS_SIG_verify(
            sig,
            message,
            sizeof(message) - 1,
            signature,
            signature_len,
            public_key) != OQS_SUCCESS) {

        printf("[C] ERROR: Signature verification failed\n");
        goto mldsa_test_cleanup;
    }

    printf("[C] Signature verification successful\n");

    printf("[C] Testing tampered message...\n");

    if (OQS_SIG_verify(
            sig,
            tampered_message,
            sizeof(tampered_message) - 1,
            signature,
            signature_len,
            public_key) == OQS_SUCCESS) {

        printf("[C] ERROR: Tampered message was accepted\n");
        goto mldsa_test_cleanup;
    }

    printf("[C] Tampered message rejected successfully\n");

    printf("[C] ML-DSA-65 FFI test completed successfully\n");

    result = 1;

mldsa_test_cleanup:

    if (public_key) {
        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);
    }

    if (secret_key) {
        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);
    }

    if (signature) {
        OQS_MEM_secure_free(
            signature,
            sig->length_signature);
    }

    OQS_SIG_free(sig);

    return result;
}


/*
 * QV-17:
 * Sign arbitrary vault data using ML-DSA-65.
 *
 * QV-18:
 * Persist the public key so that the Rust read path
 * can verify the signature later.
 */
int quantumvault_mldsa_sign_data(
    const uint8_t *data,
    size_t data_len,
    uint8_t *signature,
    size_t *signature_len)
{
    if (!data || !signature || !signature_len) {
        printf("[C] ERROR: Invalid ML-DSA signing arguments\n");
        return 0;
    }

    OQS_SIG *sig =
        OQS_SIG_new("ML-DSA-65");

    if (sig == NULL) {
        printf("[C] ERROR: Failed to initialize ML-DSA-65 signer\n");
        return 0;
    }

    uint8_t *public_key =
        OQS_MEM_malloc(sig->length_public_key);

    uint8_t *secret_key =
        OQS_MEM_malloc(sig->length_secret_key);

    if (!public_key || !secret_key) {

        printf("[C] ERROR: Signing key allocation failed\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);

        OQS_SIG_free(sig);

        return 0;
    }

    printf("[C] QV-17: Generating ML-DSA-65 signing keypair...\n");

    if (OQS_SIG_keypair(
            sig,
            public_key,
            secret_key) != OQS_SUCCESS) {

        printf("[C] ERROR: QV-17 keypair generation failed\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);

        OQS_SIG_free(sig);

        return 0;
    }

    /*
     * QV-18:
     * Store public key verification evidence.
     *
     * The secret key is never written to disk.
     */
    FILE *key_file =
        fopen(QV_PUBLIC_KEY_FILE, "wb");

    if (!key_file) {

        printf("[C] QV-18 ERROR: Failed to create public key evidence\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);

        OQS_SIG_free(sig);

        return 0;
    }

    size_t key_written =
        fwrite(
            public_key,
            1,
            sig->length_public_key,
            key_file);

    fclose(key_file);

    if (key_written != sig->length_public_key) {

        printf("[C] QV-18 ERROR: Failed to write public key evidence\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);

        OQS_SIG_free(sig);

        return 0;
    }

    printf("[C] QV-18: ML-DSA public key evidence saved\n");
    printf("[C] QV-18: Public key size: %zu bytes\n",
           sig->length_public_key);

    printf("[C] QV-17: Signing vault data...\n");

    if (OQS_SIG_sign(
            sig,
            signature,
            signature_len,
            data,
            data_len,
            secret_key) != OQS_SUCCESS) {

        printf("[C] ERROR: QV-17 signature generation failed\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);

        OQS_SIG_free(sig);

        return 0;
    }

    printf("[C] QV-17: Vault data signed successfully\n");

    printf("[C] QV-17: Signature size: %zu bytes\n",
           *signature_len);

    /*
     * Verify immediately after signing.
     */
    if (OQS_SIG_verify(
            sig,
            data,
            data_len,
            signature,
            *signature_len,
            public_key) != OQS_SUCCESS) {

        printf("[C] QV-18 ERROR: Immediate signature verification failed\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_MEM_secure_free(
            secret_key,
            sig->length_secret_key);

        OQS_SIG_free(sig);

        return 0;
    }

    printf("[C] QV-18: Signature verified successfully after signing\n");

    OQS_MEM_secure_free(
        public_key,
        sig->length_public_key);

    OQS_MEM_secure_free(
        secret_key,
        sig->length_secret_key);

    OQS_SIG_free(sig);

    return 1;
}


/*
 * QV-18:
 * Verify vault data against the stored ML-DSA-65 signature.
 */
int quantumvault_mldsa_verify_data(
    const uint8_t *data,
    size_t data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    if (!data || !signature || signature_len == 0) {

        printf("[C] QV-18 ERROR: Invalid verification arguments\n");

        return 0;
    }

    OQS_SIG *sig =
        OQS_SIG_new("ML-DSA-65");

    if (sig == NULL) {

        printf("[C] QV-18 ERROR: Failed to initialize ML-DSA-65 verifier\n");

        return 0;
    }

    uint8_t *public_key =
        OQS_MEM_malloc(sig->length_public_key);

    if (!public_key) {

        printf("[C] QV-18 ERROR: Public key allocation failed\n");

        OQS_SIG_free(sig);

        return 0;
    }

    FILE *key_file =
        fopen(QV_PUBLIC_KEY_FILE, "rb");

    if (!key_file) {

        printf("[C] QV-18 ERROR: Public key evidence not found\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_SIG_free(sig);

        return 0;
    }

    size_t key_read =
        fread(
            public_key,
            1,
            sig->length_public_key,
            key_file);

    fclose(key_file);

    if (key_read != sig->length_public_key) {

        printf("[C] QV-18 ERROR: Invalid public key evidence\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_SIG_free(sig);

        return 0;
    }

    printf("[C] QV-18: Verifying ML-DSA-65 signature...\n");

    int result =
        OQS_SIG_verify(
            sig,
            data,
            data_len,
            signature,
            signature_len,
            public_key);

    if (result == OQS_SUCCESS) {

        printf("[C] QV-18: ML-DSA-65 signature verification successful\n");

        OQS_MEM_secure_free(
            public_key,
            sig->length_public_key);

        OQS_SIG_free(sig);

        return 1;
    }

    printf("[C] QV-18 ERROR: ML-DSA-65 signature verification failed\n");

    OQS_MEM_secure_free(
        public_key,
        sig->length_public_key);

    OQS_SIG_free(sig);

    return 0;
}
