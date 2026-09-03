#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <oqs/oqs.h>

/* QuantumVault FFI logging policy */
#define QV_INFO(...) ((void)0)
#define QV_ERROR(...) fprintf(stderr, "ERROR: " __VA_ARGS__)
#define QV_WARNING(...) fprintf(stderr, "WARNING: " __VA_ARGS__)


#define QV_PUBLIC_KEY_FILE "/tmp/quantumvault_mldsa_public_key.bin"

/*
 * : Secure memory helpers
 *
 * Sensitive cryptographic buffers are locked in RAM,
 * wiped explicitly, unlocked, and securely freed.
 */

static int qv_secure_lock(void *buffer, size_t length)
{
 if (!buffer || length == 0) {
 return 0;
 }

 if (mlock(buffer, length) != 0) {
 QV_ERROR("mlock failed: %s\n",
 strerror(errno));
 return 0;
 }

 QV_INFO("[C] : Sensitive memory locked with mlock()\n");

 return 1;
}

static void qv_secure_wipe_unlock(
 void *buffer,
 size_t length,
 int locked)
{
 if (!buffer || length == 0) {
 return;
 }

 explicit_bzero(buffer, length);

 QV_INFO("[C] : Sensitive memory wiped with explicit_bzero()\n");

 if (locked) {
 if (munlock(buffer, length) != 0) {
 QV_WARNING("munlock failed: %s\n",
 strerror(errno));
 } else {
 QV_INFO("[C] : Sensitive memory unlocked\n");
 }
 }

 OQS_MEM_secure_free(buffer, length);
}


/*
 * ML-KEM-768 test
 */
int quantumvault_ffi_test(void)
{
 OQS_KEM *kem = NULL;

 uint8_t *public_key = NULL;
 uint8_t *secret_key = NULL;
 uint8_t *ciphertext = NULL;
 uint8_t *shared_secret_enc = NULL;
 uint8_t *shared_secret_dec = NULL;

 int secret_key_locked = 0;
 int shared_secret_enc_locked = 0;
 int shared_secret_dec_locked = 0;

 QV_INFO("[C] Initializing ML-KEM-768...\n");

 kem = OQS_KEM_new("ML-KEM-768");

 if (kem == NULL) {
 QV_ERROR("Failed to initialize ML-KEM-768\n");
 return 0;
 }

 QV_INFO("[C] ML-KEM-768 initialized successfully\n");
 QV_INFO("[C] Public key size: %zu bytes\n",
 kem->length_public_key);
 QV_INFO("[C] Secret key size: %zu bytes\n",
 kem->length_secret_key);
 QV_INFO("[C] Ciphertext size: %zu bytes\n",
 kem->length_ciphertext);
 QV_INFO("[C] Shared secret size: %zu bytes\n",
 kem->length_shared_secret);

 public_key =
 OQS_MEM_malloc(kem->length_public_key);

 secret_key =
 OQS_MEM_malloc(kem->length_secret_key);

 ciphertext =
 OQS_MEM_malloc(kem->length_ciphertext);

 shared_secret_enc =
 OQS_MEM_malloc(kem->length_shared_secret);

 shared_secret_dec =
 OQS_MEM_malloc(kem->length_shared_secret);

 if (!public_key || !secret_key || !ciphertext ||
 !shared_secret_enc || !shared_secret_dec) {

 QV_ERROR("Memory allocation failed\n");
 goto kem_cleanup_failure;
 }

 /*
 * :
 * Lock sensitive ML-KEM buffers in RAM.
 */

 if (!qv_secure_lock(
 secret_key,
 kem->length_secret_key)) {

 QV_ERROR("Failed to lock ML-KEM secret key\n");
 goto kem_cleanup_failure;
 }

 secret_key_locked = 1;

 if (!qv_secure_lock(
 shared_secret_enc,
 kem->length_shared_secret)) {

 QV_ERROR("Failed to lock encapsulated shared secret\n");
 goto kem_cleanup_failure;
 }

 shared_secret_enc_locked = 1;

 if (!qv_secure_lock(
 shared_secret_dec,
 kem->length_shared_secret)) {

 QV_ERROR("Failed to lock decapsulated shared secret\n");
 goto kem_cleanup_failure;
 }

 shared_secret_dec_locked = 1;

 QV_INFO("[C] : ML-KEM sensitive buffers secured\n");

 QV_INFO("[C] Generating ML-KEM-768 keypair...\n");

 if (OQS_KEM_keypair(
 kem,
 public_key,
 secret_key) != OQS_SUCCESS) {

 QV_ERROR("Keypair generation failed\n");
 goto kem_cleanup_failure;
 }

 QV_INFO("[C] Keypair generated successfully\n");

 QV_INFO("[C] Encapsulating shared secret...\n");

 if (OQS_KEM_encaps(
 kem,
 ciphertext,
 shared_secret_enc,
 public_key) != OQS_SUCCESS) {

 QV_ERROR("Encapsulation failed\n");
 goto kem_cleanup_failure;
 }

 QV_INFO("[C] Encapsulation successful\n");

 QV_INFO("[C] Decapsulating shared secret...\n");

 if (OQS_KEM_decaps(
 kem,
 shared_secret_dec,
 ciphertext,
 secret_key) != OQS_SUCCESS) {

 QV_ERROR("Decapsulation failed\n");
 goto kem_cleanup_failure;
 }

 QV_INFO("[C] Decapsulation successful\n");

 if (memcmp(
 shared_secret_enc,
 shared_secret_dec,
 kem->length_shared_secret) != 0) {

 QV_ERROR("Shared secrets DO NOT match\n");
 goto kem_cleanup_failure;
 }

 QV_INFO("[C] SUCCESS: Shared secrets match!\n");
 QV_INFO("[C] ML-KEM-768 key encapsulation cycle completed successfully\n");

 /*
 * secure cleanup.
 */

 qv_secure_wipe_unlock(
 secret_key,
 kem->length_secret_key,
 secret_key_locked);

 secret_key = NULL;

 qv_secure_wipe_unlock(
 shared_secret_enc,
 kem->length_shared_secret,
 shared_secret_enc_locked);

 shared_secret_enc = NULL;

 qv_secure_wipe_unlock(
 shared_secret_dec,
 kem->length_shared_secret,
 shared_secret_dec_locked);

 shared_secret_dec = NULL;

 OQS_MEM_secure_free(
 public_key,
 kem->length_public_key);

 public_key = NULL;

 OQS_MEM_secure_free(
 ciphertext,
 kem->length_ciphertext);

 ciphertext = NULL;

 OQS_KEM_free(kem);

 return 1;


kem_cleanup_failure:

 if (secret_key) {
 qv_secure_wipe_unlock(
 secret_key,
 kem->length_secret_key,
 secret_key_locked);
 }

 if (shared_secret_enc) {
 qv_secure_wipe_unlock(
 shared_secret_enc,
 kem->length_shared_secret,
 shared_secret_enc_locked);
 }

 if (shared_secret_dec) {
 qv_secure_wipe_unlock(
 shared_secret_dec,
 kem->length_shared_secret,
 shared_secret_dec_locked);
 }

 if (public_key) {
 OQS_MEM_secure_free(
 public_key,
 kem->length_public_key);
 }

 if (ciphertext) {
 OQS_MEM_secure_free(
 ciphertext,
 kem->length_ciphertext);
 }

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

 int secret_key_locked = 0;

 const uint8_t message[] =
 "QuantumVault ML-DSA-65 signature test";

 uint8_t tampered_message[] =
 "QuantumVault ML-DSA-65 signature TEST";

 size_t signature_len = 0;

 int result = 0;

 QV_INFO("[C] Initializing ML-DSA-65...\n");

 sig = OQS_SIG_new("ML-DSA-65");

 if (sig == NULL) {
 QV_ERROR("Failed to initialize ML-DSA-65\n");
 return 0;
 }

 QV_INFO("[C] ML-DSA-65 initialized successfully\n");

 QV_INFO("[C] Public key size: %zu bytes\n",
 sig->length_public_key);

 QV_INFO("[C] Secret key size: %zu bytes\n",
 sig->length_secret_key);

 QV_INFO("[C] Signature size: %zu bytes\n",
 sig->length_signature);

 public_key =
 OQS_MEM_malloc(sig->length_public_key);

 secret_key =
 OQS_MEM_malloc(sig->length_secret_key);

 signature =
 OQS_MEM_malloc(sig->length_signature);

 if (!public_key || !secret_key || !signature) {

 QV_ERROR("ML-DSA memory allocation failed\n");
 goto mldsa_test_cleanup;
 }

 /*
 * :
 * Lock ML-DSA secret key in RAM.
 */

 if (!qv_secure_lock(
 secret_key,
 sig->length_secret_key)) {

 QV_ERROR("Failed to lock ML-DSA secret key\n");
 goto mldsa_test_cleanup;
 }

 secret_key_locked = 1;

 QV_INFO("[C] : ML-DSA secret key secured\n");

 QV_INFO("[C] Generating ML-DSA-65 keypair...\n");

 if (OQS_SIG_keypair(
 sig,
 public_key,
 secret_key) != OQS_SUCCESS) {

 QV_ERROR("ML-DSA keypair generation failed\n");
 goto mldsa_test_cleanup;
 }

 QV_INFO("[C] Keypair generated successfully\n");

 QV_INFO("[C] Signing message...\n");

 if (OQS_SIG_sign(
 sig,
 signature,
 &signature_len,
 message,
 sizeof(message) - 1,
 secret_key) != OQS_SUCCESS) {

 QV_ERROR("ML-DSA signature generation failed\n");
 goto mldsa_test_cleanup;
 }

 QV_INFO("[C] Signature generated successfully\n");

 QV_INFO("[C] Signature size: %zu bytes\n",
 signature_len);

 QV_INFO("[C] Verifying signature...\n");

 if (OQS_SIG_verify(
 sig,
 message,
 sizeof(message) - 1,
 signature,
 signature_len,
 public_key) != OQS_SUCCESS) {

 QV_ERROR("Signature verification failed\n");
 goto mldsa_test_cleanup;
 }

 QV_INFO("[C] Signature verification successful\n");

 QV_INFO("[C] Testing tampered message...\n");

 if (OQS_SIG_verify(
 sig,
 tampered_message,
 sizeof(tampered_message) - 1,
 signature,
 signature_len,
 public_key) == OQS_SUCCESS) {

 QV_ERROR("Tampered message was accepted\n");
 goto mldsa_test_cleanup;
 }

 QV_INFO("[C] Tampered message rejected successfully\n");

 QV_INFO("[C] ML-DSA-65 FFI test completed successfully\n");

 result = 1;

mldsa_test_cleanup:

 if (secret_key) {
 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);
 }

 if (public_key) {
 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);
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
 * / :
 * Sign arbitrary vault data using ML-DSA-65.
 *
 * Public key is persisted for later verification.
 * Secret key is never written to disk.
 */
int quantumvault_mldsa_sign_data(
 const uint8_t *data,
 size_t data_len,
 uint8_t *signature,
 size_t *signature_len)
{
 if (!data || !signature || !signature_len) {

 QV_ERROR("Invalid ML-DSA signing arguments\n");
 return 0;
 }

 OQS_SIG *sig =
 OQS_SIG_new("ML-DSA-65");

 if (sig == NULL) {

 QV_ERROR("Failed to initialize ML-DSA-65 signer\n");
 return 0;
 }

 uint8_t *public_key =
 OQS_MEM_malloc(sig->length_public_key);

 uint8_t *secret_key =
 OQS_MEM_malloc(sig->length_secret_key);

 int secret_key_locked = 0;

 if (!public_key || !secret_key) {

 QV_ERROR("Signing key allocation failed\n");

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

 OQS_SIG_free(sig);

 return 0;
 }

 /*
 * :
 * Lock ML-DSA secret key in RAM.
 */

 if (!qv_secure_lock(
 secret_key,
 sig->length_secret_key)) {

 QV_ERROR("Failed to lock signing secret key\n");

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_MEM_secure_free(
 secret_key,
 sig->length_secret_key);

 OQS_SIG_free(sig);

 return 0;
 }

 secret_key_locked = 1;

 QV_INFO("[C] : ML-DSA signing secret key secured\n");

 QV_INFO("[C] : Generating ML-DSA-65 signing keypair...\n");

 if (OQS_SIG_keypair(
 sig,
 public_key,
 secret_key) != OQS_SUCCESS) {

 QV_ERROR("keypair generation failed\n");

 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 0;
 }

 QV_INFO("[C] : Keypair generated successfully\n");

 /*
 * :
 * Store only the public key.
 * The secret key remains memory-only.
 */

 FILE *key_file =
 fopen(QV_PUBLIC_KEY_FILE, "wb");

 if (!key_file) {

 QV_ERROR("Failed to create public key evidence\n");

 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

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

 QV_ERROR("Failed to write public key evidence\n");

 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 0;
 }

 QV_INFO("[C] : ML-DSA public key evidence saved\n");

 QV_INFO("[C] : Public key size: %zu bytes\n",
 sig->length_public_key);

 QV_INFO("[C] : Signing vault data...\n");

 if (OQS_SIG_sign(
 sig,
 signature,
 signature_len,
 data,
 data_len,
 secret_key) != OQS_SUCCESS) {

 QV_ERROR("signature generation failed\n");

 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 0;
 }

 QV_INFO("[C] : Vault data signed successfully\n");

 QV_INFO("[C] : Signature size: %zu bytes\n",
 *signature_len);

 /*
 * :
 * Verify immediately after signing.
 */

 if (OQS_SIG_verify(
 sig,
 data,
 data_len,
 signature,
 *signature_len,
 public_key) != OQS_SUCCESS) {

 QV_ERROR("Immediate signature verification failed\n");

 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 0;
 }

 QV_INFO("[C] : Signature verified successfully after signing\n");

 /*
 * secure cleanup.
 */

 qv_secure_wipe_unlock(
 secret_key,
 sig->length_secret_key,
 secret_key_locked);

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 1;
}


/*
 * / :
 * Verify vault data against the stored ML-DSA-65 signature.
 */
int quantumvault_mldsa_verify_data(
 const uint8_t *data,
 size_t data_len,
 const uint8_t *signature,
 size_t signature_len)
{
 if (!data || !signature || signature_len == 0) {

 QV_ERROR("Invalid verification arguments\n");

 return 0;
 }

 OQS_SIG *sig =
 OQS_SIG_new("ML-DSA-65");

 if (sig == NULL) {

 QV_ERROR("Failed to initialize ML-DSA-65 verifier\n");

 return 0;
 }

 uint8_t *public_key =
 OQS_MEM_malloc(sig->length_public_key);

 if (!public_key) {

 QV_ERROR("Public key allocation failed\n");

 OQS_SIG_free(sig);

 return 0;
 }

 FILE *key_file =
 fopen(QV_PUBLIC_KEY_FILE, "rb");

 if (!key_file) {

 QV_ERROR("Public key evidence not found\n");

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

 QV_ERROR("Invalid public key evidence\n");

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 0;
 }

 QV_INFO("[C] : Verifying ML-DSA-65 signature...\n");

 int result =
 OQS_SIG_verify(
 sig,
 data,
 data_len,
 signature,
 signature_len,
 public_key);

 if (result == OQS_SUCCESS) {

 QV_INFO("[C] : ML-DSA-65 signature verification successful\n");

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 1;
 }

 QV_ERROR("ML-DSA-65 signature verification failed\n");

 OQS_MEM_secure_free(
 public_key,
 sig->length_public_key);

 OQS_SIG_free(sig);

 return 0;
}

/*
 * ============================================================
 * : Persistent Post-Quantum Key Management FFI
 * ============================================================
 *
 * These wrappers expose the liboqs operations needed by Rust.
 *
 * Architecture:
 *
 * Rust
 * |
 * v
 * QuantumVault C FFI
 * |
 * v
 * liboqs
 *
 * Existing / functions above are intentionally
 * preserved and are NOT modified.
 */

/*
 * : Generate ML-KEM-768 keypair.
 *
 * public_key -> caller-provided public key buffer
 * secret_key -> caller-provided secret key buffer
 *
 * The internal liboqs secret-key buffer is locked in RAM while
 * the keypair is generated and is wiped before returning.
 */
int quantumvault_mlkem_generate_keys(
 uint8_t *public_key,
 size_t public_key_len,
 uint8_t *secret_key,
 size_t secret_key_len)
{
 if (!public_key || !secret_key) {
 QV_ERROR("Invalid ML-KEM key buffers\n");
 return 0;
 }

 OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");

 if (!kem) {
 QV_ERROR("Failed to initialize ML-KEM-768\n");
 return 0;
 }

 if (public_key_len != kem->length_public_key ||
 secret_key_len != kem->length_secret_key) {

 QV_ERROR("Invalid ML-KEM key sizes\n");

 OQS_KEM_free(kem);
 return 0;
 }

 uint8_t *internal_secret =
 OQS_MEM_malloc(kem->length_secret_key);

 if (!internal_secret) {
 QV_ERROR("Secret-key allocation failed\n");

 OQS_KEM_free(kem);
 return 0;
 }

 int locked =
 qv_secure_lock(
 internal_secret,
 kem->length_secret_key);

 if (!locked) {
 QV_ERROR("Failed to lock ML-KEM secret key\n");

 OQS_MEM_secure_free(
 internal_secret,
 kem->length_secret_key);

 OQS_KEM_free(kem);
 return 0;
 }

 QV_INFO("[C] : Generating ML-KEM-768 keypair...\n");

 int result =
 OQS_KEM_keypair(
 kem,
 public_key,
 internal_secret) == OQS_SUCCESS;

 if (result) {
 memcpy(
 secret_key,
 internal_secret,
 kem->length_secret_key);

 QV_INFO("[C] : ML-KEM-768 keypair generated successfully\n");
 } else {
 QV_ERROR("ML-KEM-768 keypair generation failed\n");
 }

 qv_secure_wipe_unlock(
 internal_secret,
 kem->length_secret_key,
 locked);

 OQS_KEM_free(kem);

 return result;
}


/*
 * : ML-KEM-768 encapsulation.
 *
 * public_key -> recipient public key
 * ciphertext -> generated KEM ciphertext
 * shared_secret -> generated shared secret
 */
int quantumvault_mlkem_encapsulate(
 const uint8_t *public_key,
 size_t public_key_len,
 uint8_t *ciphertext,
 size_t ciphertext_len,
 uint8_t *shared_secret,
 size_t shared_secret_len)
{
 if (!public_key || !ciphertext || !shared_secret) {
 QV_ERROR("Invalid ML-KEM encapsulation buffers\n");
 return 0;
 }

 OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");

 if (!kem) {
 QV_ERROR("Failed to initialize ML-KEM-768\n");
 return 0;
 }

 if (public_key_len != kem->length_public_key ||
 ciphertext_len != kem->length_ciphertext ||
 shared_secret_len != kem->length_shared_secret) {

 QV_ERROR("Invalid ML-KEM encapsulation sizes\n");

 OQS_KEM_free(kem);
 return 0;
 }

 uint8_t *internal_shared_secret =
 OQS_MEM_malloc(kem->length_shared_secret);

 if (!internal_shared_secret) {
 QV_ERROR("Shared-secret allocation failed\n");

 OQS_KEM_free(kem);
 return 0;
 }

 int locked =
 qv_secure_lock(
 internal_shared_secret,
 kem->length_shared_secret);

 if (!locked) {
 QV_ERROR("Failed to lock shared secret\n");

 OQS_MEM_secure_free(
 internal_shared_secret,
 kem->length_shared_secret);

 OQS_KEM_free(kem);
 return 0;
 }

 QV_INFO("[C] : Encapsulating ML-KEM-768 shared secret...\n");

 int result =
 OQS_KEM_encaps(
 kem,
 ciphertext,
 internal_shared_secret,
 public_key) == OQS_SUCCESS;

 if (result) {
 memcpy(
 shared_secret,
 internal_shared_secret,
 kem->length_shared_secret);

 QV_INFO("[C] : ML-KEM encapsulation successful\n");
 } else {
 QV_ERROR("ML-KEM encapsulation failed\n");
 }

 qv_secure_wipe_unlock(
 internal_shared_secret,
 kem->length_shared_secret,
 locked);

 OQS_KEM_free(kem);

 return result;
}


/*
 * : ML-KEM-768 decapsulation.
 *
 * secret_key -> recipient secret key
 * ciphertext -> KEM ciphertext
 * shared_secret -> recovered shared secret
 */
int quantumvault_mlkem_decapsulate(
 const uint8_t *secret_key,
 size_t secret_key_len,
 const uint8_t *ciphertext,
 size_t ciphertext_len,
 uint8_t *shared_secret,
 size_t shared_secret_len)
{
 if (!secret_key || !ciphertext || !shared_secret) {
 QV_ERROR("Invalid ML-KEM decapsulation buffers\n");
 return 0;
 }

 OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");

 if (!kem) {
 QV_ERROR("Failed to initialize ML-KEM-768\n");
 return 0;
 }

 if (secret_key_len != kem->length_secret_key ||
 ciphertext_len != kem->length_ciphertext ||
 shared_secret_len != kem->length_shared_secret) {

 QV_ERROR("Invalid ML-KEM decapsulation sizes\n");

 OQS_KEM_free(kem);
 return 0;
 }

 uint8_t *internal_secret_key =
 OQS_MEM_malloc(kem->length_secret_key);

 uint8_t *internal_shared_secret =
 OQS_MEM_malloc(kem->length_shared_secret);

 if (!internal_secret_key || !internal_shared_secret) {
 QV_ERROR("Decapsulation allocation failed\n");

 if (internal_secret_key) {
 OQS_MEM_secure_free(
 internal_secret_key,
 kem->length_secret_key);
 }

 if (internal_shared_secret) {
 OQS_MEM_secure_free(
 internal_shared_secret,
 kem->length_shared_secret);
 }

 OQS_KEM_free(kem);
 return 0;
 }

 memcpy(
 internal_secret_key,
 secret_key,
 kem->length_secret_key);

 int secret_locked =
 qv_secure_lock(
 internal_secret_key,
 kem->length_secret_key);

 int shared_locked =
 qv_secure_lock(
 internal_shared_secret,
 kem->length_shared_secret);

 if (!secret_locked || !shared_locked) {
 QV_ERROR("Failed to lock decapsulation buffers\n");

 qv_secure_wipe_unlock(
 internal_secret_key,
 kem->length_secret_key,
 secret_locked);

 qv_secure_wipe_unlock(
 internal_shared_secret,
 kem->length_shared_secret,
 shared_locked);

 OQS_KEM_free(kem);
 return 0;
 }

 QV_INFO("[C] : Decapsulating ML-KEM-768 shared secret...\n");

 int result =
 OQS_KEM_decaps(
 kem,
 internal_shared_secret,
 ciphertext,
 internal_secret_key) == OQS_SUCCESS;

 if (result) {
 memcpy(
 shared_secret,
 internal_shared_secret,
 kem->length_shared_secret);

 QV_INFO("[C] : ML-KEM decapsulation successful\n");
 } else {
 QV_ERROR("ML-KEM decapsulation failed\n");
 }

 qv_secure_wipe_unlock(
 internal_secret_key,
 kem->length_secret_key,
 secret_locked);

 qv_secure_wipe_unlock(
 internal_shared_secret,
 kem->length_shared_secret,
 shared_locked);

 OQS_KEM_free(kem);

 return result;
}


/*
 * : Generate ML-DSA-65 keypair.
 *
 * public_key -> caller-provided public key buffer
 * secret_key -> caller-provided secret key buffer
 */
int quantumvault_mldsa_generate_keys(
 uint8_t *public_key,
 size_t public_key_len,
 uint8_t *secret_key,
 size_t secret_key_len)
{
 if (!public_key || !secret_key) {
 QV_ERROR("Invalid ML-DSA key buffers\n");
 return 0;
 }

 OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");

 if (!sig) {
 QV_ERROR("Failed to initialize ML-DSA-65\n");
 return 0;
 }

 if (public_key_len != sig->length_public_key ||
 secret_key_len != sig->length_secret_key) {

 QV_ERROR("Invalid ML-DSA key sizes\n");

 OQS_SIG_free(sig);
 return 0;
 }

 uint8_t *internal_secret =
 OQS_MEM_malloc(sig->length_secret_key);

 if (!internal_secret) {
 QV_ERROR("ML-DSA secret allocation failed\n");

 OQS_SIG_free(sig);
 return 0;
 }

 int locked =
 qv_secure_lock(
 internal_secret,
 sig->length_secret_key);

 if (!locked) {
 QV_ERROR("Failed to lock ML-DSA secret key\n");

 OQS_MEM_secure_free(
 internal_secret,
 sig->length_secret_key);

 OQS_SIG_free(sig);
 return 0;
 }

 QV_INFO("[C] : Generating ML-DSA-65 keypair...\n");

 int result =
 OQS_SIG_keypair(
 sig,
 public_key,
 internal_secret) == OQS_SUCCESS;

 if (result) {
 memcpy(
 secret_key,
 internal_secret,
 sig->length_secret_key);

 QV_INFO("[C] : ML-DSA-65 keypair generated successfully\n");
 } else {
 QV_ERROR("ML-DSA-65 keypair generation failed\n");
 }

 qv_secure_wipe_unlock(
 internal_secret,
 sig->length_secret_key,
 locked);

 OQS_SIG_free(sig);

 return result;
}


/*
 * : Sign data using an existing ML-DSA-65 secret key.
 *
 * IMPORTANT:
 * The caller owns the persistent key material.
 * The secret key is copied into locked C memory and wiped
 * immediately after signing.
 */
int quantumvault_mldsa_sign_with_key(
 const uint8_t *data,
 size_t data_len,
 const uint8_t *secret_key,
 size_t secret_key_len,
 uint8_t *signature,
 size_t *signature_len)
{
 if (!data || !secret_key || !signature || !signature_len) {
 QV_ERROR("Invalid ML-DSA signing arguments\n");
 return 0;
 }

 OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");

 if (!sig) {
 QV_ERROR("Failed to initialize ML-DSA-65\n");
 return 0;
 }

 if (secret_key_len != sig->length_secret_key) {
 QV_ERROR("Invalid ML-DSA secret-key size\n");

 OQS_SIG_free(sig);
 return 0;
 }

 uint8_t *internal_secret =
 OQS_MEM_malloc(sig->length_secret_key);

 if (!internal_secret) {
 QV_ERROR("Secret-key allocation failed\n");

 OQS_SIG_free(sig);
 return 0;
 }

 memcpy(
 internal_secret,
 secret_key,
 sig->length_secret_key);

 int locked =
 qv_secure_lock(
 internal_secret,
 sig->length_secret_key);

 if (!locked) {
 QV_ERROR("Failed to lock signing key\n");

 OQS_MEM_secure_free(
 internal_secret,
 sig->length_secret_key);

 OQS_SIG_free(sig);
 return 0;
 }

 QV_INFO("[C] : Signing data with persistent ML-DSA-65 key...\n");

 int result =
 OQS_SIG_sign(
 sig,
 signature,
 signature_len,
 data,
 data_len,
 internal_secret) == OQS_SUCCESS;

 if (result) {
 QV_INFO("[C] : ML-DSA-65 signing successful\n");
 QV_INFO("[C] : Signature size: %zu bytes\n",
 *signature_len);
 } else {
 QV_ERROR("ML-DSA-65 signing failed\n");
 }

 qv_secure_wipe_unlock(
 internal_secret,
 sig->length_secret_key,
 locked);

 OQS_SIG_free(sig);

 return result;
}


/*
 * : Verify data using an existing ML-DSA-65 public key.
 */
int quantumvault_mldsa_verify_with_key(
 const uint8_t *data,
 size_t data_len,
 const uint8_t *public_key,
 size_t public_key_len,
 const uint8_t *signature,
 size_t signature_len)
{
 if (!data || !public_key || !signature || signature_len == 0) {
 QV_ERROR("Invalid ML-DSA verification arguments\n");
 return 0;
 }

 OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");

 if (!sig) {
 QV_ERROR("Failed to initialize ML-DSA-65\n");
 return 0;
 }

 if (public_key_len != sig->length_public_key) {
 QV_ERROR("Invalid ML-DSA public-key size\n");

 OQS_SIG_free(sig);
 return 0;
 }

 QV_INFO("[C] : Verifying ML-DSA-65 signature...\n");

 int result =
 OQS_SIG_verify(
 sig,
 data,
 data_len,
 signature,
 signature_len,
 public_key) == OQS_SUCCESS;

 if (result) {
 QV_INFO("[C] : ML-DSA-65 signature verification successful\n");
 } else {
 QV_ERROR("ML-DSA-65 signature verification failed\n");
 }

 OQS_SIG_free(sig);

 return result;
}
