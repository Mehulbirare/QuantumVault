use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyWrite, Request, TimeOrNow,
};

use libc::{EIO, ENOENT};

use rand::RngCore;
use rpassword::read_password;
use sha2::{Digest, Sha256};

use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, SystemTime},
};

/* ============================================================
 * QuantumVault Secure Filesystem * ============================================================
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
 * Persistent private keys are NEVER stored plaintext.
 *
 * Password
 * |
 * v
 * AES-256-GCM
 * |
 * v
 * encrypted PQ key bundle
 *
 * File encryption:
 *
 * ML-KEM-768
 * |
 * v
 * shared secret
 * |
 * v
 * AES-256-GCM
 *
 * File integrity:
 *
 * plaintext
 * |
 * v
 * ML-DSA-65 signature
 *
 * ============================================================
 */

/* ============================================================
 * C FFI
 * ============================================================
 */

unsafe extern "C" {
    fn quantumvault_ffi_test() -> i32;

    fn quantumvault_mldsa_test() -> i32;

    fn quantumvault_mlkem_generate_keys(
        public_key: *mut u8,
        public_key_len: usize,
        secret_key: *mut u8,
        secret_key_len: usize,
    ) -> i32;

    fn quantumvault_mlkem_encapsulate(
        public_key: *const u8,
        public_key_len: usize,
        ciphertext: *mut u8,
        ciphertext_len: usize,
        shared_secret: *mut u8,
        shared_secret_len: usize,
    ) -> i32;

    fn quantumvault_mlkem_decapsulate(
        secret_key: *const u8,
        secret_key_len: usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
        shared_secret: *mut u8,
        shared_secret_len: usize,
    ) -> i32;

    fn quantumvault_mldsa_generate_keys(
        public_key: *mut u8,
        public_key_len: usize,
        secret_key: *mut u8,
        secret_key_len: usize,
    ) -> i32;

    fn quantumvault_mldsa_sign_with_key(
        data: *const u8,
        data_len: usize,
        secret_key: *const u8,
        secret_key_len: usize,
        signature: *mut u8,
        signature_len: *mut usize,
    ) -> i32;

    fn quantumvault_mldsa_verify_with_key(
        data: *const u8,
        data_len: usize,
        public_key: *const u8,
        public_key_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> i32;
}

/* ============================================================
 * Constants
 * ============================================================
 */

const TTL: Duration = Duration::from_secs(1);

const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;

/* ML-KEM-768 */
const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
const MLKEM_SECRET_KEY_SIZE: usize = 2400;
const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
const MLKEM_SHARED_SECRET_SIZE: usize = 32;

/* ML-DSA-65 */
const MLDSA_PUBLIC_KEY_SIZE: usize = 1952;
const MLDSA_SECRET_KEY_SIZE: usize = 4032;
const MLDSA_SIGNATURE_SIZE: usize = 3309;

/* AES-GCM */
const AES_KEY_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;
const AES_TAG_SIZE: usize = 16;

/* ============================================================
 * Persistent files
 * ============================================================
 */

const BACKING_FILE: &str = "/tmp/quantumvault_encrypted.bin";

const KEY_BUNDLE_FILE: &str = "/tmp/quantumvault_keys.bin";

const SIGNATURE_FILE: &str = "/tmp/quantumvault_signature.bin";

/* ============================================================
 * File format magic/version
 * ============================================================
 */

/*
 * encrypted data:
 *
 * [4 bytes magic]
 * [1 byte version]
 * [1088 bytes ML-KEM ciphertext]
 * [12 bytes AES nonce]
 * [AES-GCM ciphertext + 16 byte tag]
 */
const DATA_MAGIC: &[u8; 4] = b"QVF2";

const DATA_VERSION: u8 = 1;

const DATA_HEADER_SIZE: usize = 4 + 1 + MLKEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE;

/*
 * signature evidence:
 *
 * [4 bytes magic]
 * [1 byte version]
 * [8 bytes plaintext length]
 * [ML-DSA-65 signature]
 */
const SIGNATURE_MAGIC: &[u8; 4] = b"QVS2";

const SIGNATURE_VERSION: u8 = 1;

const SIGNATURE_HEADER_SIZE: usize = 4 + 1 + 8;

/*
 * encrypted key bundle:
 *
 * [4 bytes magic]
 * [1 byte version]
 * [12 byte password AES nonce]
 * [AES-GCM encrypted key material + tag]
 *
 * Plain key material:
 *
 * ML-KEM public 1184
 * ML-KEM secret 2400
 * ML-DSA public 1952
 * ML-DSA secret 4032
 */
const KEY_BUNDLE_MAGIC: &[u8; 4] = b"QVK2";

const KEY_BUNDLE_VERSION: u8 = 1;

const KEY_BUNDLE_HEADER_SIZE: usize = 4 + 1 + AES_NONCE_SIZE;

const KEY_MATERIAL_SIZE: usize =
    MLKEM_PUBLIC_KEY_SIZE + MLKEM_SECRET_KEY_SIZE + MLDSA_PUBLIC_KEY_SIZE + MLDSA_SECRET_KEY_SIZE;

/* ============================================================
 * Secure memory
 * ============================================================
 */

struct SecureBytes {
    data: Vec<u8>,
    locked: bool,
}

impl SecureBytes {
    fn new(size: usize) -> Result<Self, ()> {
        let mut data = vec![0u8; size];

        let locked =
            unsafe { libc::mlock(data.as_mut_ptr() as *const libc::c_void, data.len()) == 0 };

        if locked {
        } else {
            println!("WARNING: Rust mlock() unavailable; continuing with memory wiping");
        }

        Ok(Self { data, locked })
    }

    fn from_vec(mut data: Vec<u8>) -> Result<Self, ()> {
        let locked =
            unsafe { libc::mlock(data.as_mut_ptr() as *const libc::c_void, data.len()) == 0 };

        if locked {
        } else {
            println!("WARNING: Rust mlock() unavailable; continuing with memory wiping");
        }

        Ok(Self { data, locked })
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.data.as_mut_ptr(), 0, self.data.len());

            if self.locked {
                let _ = libc::munlock(
                    self.data.as_mut_ptr() as *const libc::c_void,
                    self.data.len(),
                );
            }
        }
    }
}

/* ============================================================
 * Persistent PQ key material
 * ============================================================
 */

struct VaultKeys {
    mlkem_public: Vec<u8>,
    mlkem_secret: SecureBytes,

    mldsa_public: Vec<u8>,
    mldsa_secret: SecureBytes,
}

/* ============================================================
 * QuantumVault filesystem
 * ============================================================
 */

struct QuantumVaultFS {
    backing_file: PathBuf,
    keys: VaultKeys,
}

impl QuantumVaultFS {
    /* ========================================================
     *
     * ML-KEM-768 + AES-256-GCM encryption
     * ========================================================
     */

    fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut kem_ciphertext = vec![0u8; MLKEM_CIPHERTEXT_SIZE];

        let mut shared_secret = SecureBytes::new(MLKEM_SHARED_SECRET_SIZE)?;

        let result = unsafe {
            quantumvault_mlkem_encapsulate(
                self.keys.mlkem_public.as_ptr(),
                self.keys.mlkem_public.len(),
                kem_ciphertext.as_mut_ptr(),
                kem_ciphertext.len(),
                shared_secret.as_mut_ptr(),
                shared_secret.len(),
            )
        };

        if result != 1 {
            println!("ERROR: ML-KEM encapsulation failed");

            return Err(());
        }

        let key =
            Key::<Aes256Gcm>::try_from(shared_secret.as_slice()).expect("invalid AES key length");

        let cipher = Aes256Gcm::new(&key);

        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];

        rand::rng().fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("invalid AES nonce length");

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| ())?;

        let mut output = Vec::with_capacity(DATA_HEADER_SIZE + ciphertext.len());

        output.extend_from_slice(DATA_MAGIC);

        output.push(DATA_VERSION);

        output.extend_from_slice(&kem_ciphertext);

        output.extend_from_slice(&nonce_bytes);

        output.extend_from_slice(&ciphertext);

        println!("Hybrid encrypted file format created");

        Ok(output)
    }

    /* ========================================================
     *
     * ML-KEM decapsulation + AES-GCM decryption
     * ========================================================
     */

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, ()> {
        if encrypted_data.len() < DATA_HEADER_SIZE + AES_TAG_SIZE {
            println!("ERROR: Encrypted file is too small");

            return Err(());
        }

        if &encrypted_data[..4] != DATA_MAGIC {
            println!("ERROR: Invalid encrypted-file magic");

            return Err(());
        }

        if encrypted_data[4] != DATA_VERSION {
            println!("ERROR: Unsupported encrypted-file version");

            return Err(());
        }

        let kem_start = 5;

        let kem_end = kem_start + MLKEM_CIPHERTEXT_SIZE;

        let nonce_start = kem_end;

        let nonce_end = nonce_start + AES_NONCE_SIZE;

        let ciphertext_start = nonce_end;

        let kem_ciphertext = &encrypted_data[kem_start..kem_end];

        let nonce_bytes = &encrypted_data[nonce_start..nonce_end];

        let ciphertext = &encrypted_data[ciphertext_start..];

        let mut shared_secret = SecureBytes::new(MLKEM_SHARED_SECRET_SIZE)?;

        let result = unsafe {
            quantumvault_mlkem_decapsulate(
                self.keys.mlkem_secret.as_ptr(),
                self.keys.mlkem_secret.len(),
                kem_ciphertext.as_ptr(),
                kem_ciphertext.len(),
                shared_secret.as_mut_ptr(),
                shared_secret.len(),
            )
        };

        if result != 1 {
            println!("ERROR: ML-KEM decapsulation failed");

            return Err(());
        }

        println!("ML-KEM-768 decapsulation successful");

        let key =
            Key::<Aes256Gcm>::try_from(shared_secret.as_slice()).expect("invalid AES key length");

        let cipher = Aes256Gcm::new(&key);

        let nonce = Nonce::try_from(nonce_bytes).expect("invalid AES nonce length");

        let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| ())?;

        Ok(plaintext)
    }

    /* ========================================================
     *
     * Persistent ML-DSA signing
     * ========================================================
     */

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let mut signature = vec![0u8; MLDSA_SIGNATURE_SIZE];

        let mut signature_len = 0usize;

        let result = unsafe {
            quantumvault_mldsa_sign_with_key(
                data.as_ptr(),
                data.len(),
                self.keys.mldsa_secret.as_ptr(),
                self.keys.mldsa_secret.len(),
                signature.as_mut_ptr(),
                &mut signature_len,
            )
        };

        if result != 1 || signature_len == 0 || signature_len > signature.len() {
            println!("ERROR: ML-DSA-65 signing failed");

            return Err(());
        }

        signature.truncate(signature_len);

        Ok(signature)
    }

    /* ========================================================
     *
     * Persistent ML-DSA verification
     * ========================================================
     */

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<(), ()> {
        let result = unsafe {
            quantumvault_mldsa_verify_with_key(
                data.as_ptr(),
                data.len(),
                self.keys.mldsa_public.as_ptr(),
                self.keys.mldsa_public.len(),
                signature.as_ptr(),
                signature.len(),
            )
        };

        if result != 1 {
            println!("SECURITY ERROR: ML-DSA-65 verification failed");

            return Err(());
        }

        Ok(())
    }

    /* ========================================================
     * Write encrypted backing file
     * ========================================================
     */

    fn write_backing_file(&self, data: &[u8]) -> Result<(), ()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.backing_file)
            .map_err(|error| {
                println!("ERROR: Cannot open backing file: {}", error);
            })?;

        file.write_all(data).map_err(|error| {
            println!("ERROR: Backing write failed: {}", error);
        })?;

        file.flush().map_err(|error| {
            println!("ERROR: Backing flush failed: {}", error);
        })?;

        Ok(())
    }

    /* ========================================================
     * Clear backing data
     * ========================================================
     */

    fn clear_backing_file(&self) -> Result<(), ()> {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.backing_file)
            .map(|_| ())
            .map_err(|error| {
                println!("ERROR: Cannot clear backing file: {}", error);
            })
    }
}

/* ============================================================
 * FUSE implementation
 * ============================================================
 */

impl Filesystem for QuantumVaultFS {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &hello_attr(), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match ino {
            ROOT_INO => {
                reply.attr(&TTL, &root_attr());
            }

            HELLO_INO => {
                reply.attr(&TTL, &hello_attr());
            }

            _ => {
                reply.error(ENOENT);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(ENOENT);
            return;
        }

        let entries = [
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (HELLO_INO, FileType::RegularFile, "hello.txt"),
        ];

        for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*entry_ino, (i + 1) as i64, *kind, *name) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if ino == HELLO_INO {
            reply.opened(0, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if ino != HELLO_INO {
            reply.error(ENOENT);
            return;
        }

        if let Some(new_size) = size {
            if new_size == 0 {
                if self.clear_backing_file().is_err() {
                    reply.error(EIO);
                    return;
                }

                let _ = fs::remove_file(SIGNATURE_FILE);

                println!("Signature evidence cleared");
            }
        }

        reply.attr(&TTL, &hello_attr());
    }

    /* ========================================================
     * + READ
     * ========================================================
     */

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if ino != HELLO_INO {
            reply.error(ENOENT);
            return;
        }

        let mut encrypted_data = Vec::new();

        let read_result = OpenOptions::new()
            .read(true)
            .open(&self.backing_file)
            .and_then(|mut file| file.read_to_end(&mut encrypted_data));

        if read_result.is_err() || encrypted_data.is_empty() {
            reply.data(&[]);
            return;
        }

        /* decryption */

        let plaintext = match self.decrypt_data(&encrypted_data) {
            Ok(data) => data,

            Err(_) => {
                println!("SECURITY ERROR: Decryption/authentication failed");

                reply.error(EIO);
                return;
            }
        };

        /* signature evidence */

        let mut evidence = Vec::new();

        if OpenOptions::new()
            .read(true)
            .open(SIGNATURE_FILE)
            .and_then(|mut file| file.read_to_end(&mut evidence))
            .is_err()
        {
            println!("SECURITY ERROR: Signature evidence missing");

            reply.error(EIO);
            return;
        }

        if evidence.len() < SIGNATURE_HEADER_SIZE {
            println!("SECURITY ERROR: Signature evidence too small");

            reply.error(EIO);
            return;
        }

        if &evidence[..4] != SIGNATURE_MAGIC {
            println!("SECURITY ERROR: Invalid signature magic");

            reply.error(EIO);
            return;
        }

        if evidence[4] != SIGNATURE_VERSION {
            println!("SECURITY ERROR: Unsupported signature version");

            reply.error(EIO);
            return;
        }

        let mut length_bytes = [0u8; 8];

        length_bytes.copy_from_slice(&evidence[5..13]);

        let expected_length = u64::from_le_bytes(length_bytes);

        if expected_length != plaintext.len() as u64 {
            println!("SECURITY ERROR: Plaintext length mismatch");

            reply.error(EIO);
            return;
        }

        let signature = &evidence[SIGNATURE_HEADER_SIZE..];

        if signature.len() != MLDSA_SIGNATURE_SIZE {
            println!("SECURITY ERROR: Invalid ML-DSA signature size");

            reply.error(EIO);
            return;
        }

        /*
         * IMPORTANT:
         * Do not return plaintext until signature
         * verification succeeds.
         */

        if self.verify_signature(&plaintext, signature).is_err() {
            println!("SECURITY ERROR: Tampering detected");

            reply.error(EIO);
            return;
        }

        let start = offset.max(0) as usize;

        if start >= plaintext.len() {
            reply.data(&[]);
            return;
        }

        let end = std::cmp::min(start + size as usize, plaintext.len());

        reply.data(&plaintext[start..end]);
    }

    /* ========================================================
     * + WRITE
     * ========================================================
     */

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if ino != HELLO_INO {
            reply.error(ENOENT);
            return;
        }

        println!("Write offset: {}", offset);

        /*
         * :
         * Sign plaintext using persistent ML-DSA key.
         */

        let signature = match self.sign_data(data) {
            Ok(signature) => signature,

            Err(_) => {
                reply.error(EIO);
                return;
            }
        };

        /*
         * Signature evidence.
         */

        let mut signature_evidence = Vec::with_capacity(SIGNATURE_HEADER_SIZE + signature.len());

        signature_evidence.extend_from_slice(SIGNATURE_MAGIC);

        signature_evidence.push(SIGNATURE_VERSION);

        signature_evidence.extend_from_slice(&(data.len() as u64).to_le_bytes());

        signature_evidence.extend_from_slice(&signature);

        /*
         * :
         * Hybrid ML-KEM + AES-GCM encryption.
         */

        let encrypted_data = match self.encrypt_data(data) {
            Ok(data) => data,

            Err(_) => {
                println!("ERROR: Hybrid encryption failed");

                reply.error(EIO);
                return;
            }
        };

        /*
         * Write encrypted data first.
         */

        if let Err(error) = self.write_backing_file(&encrypted_data) {
            println!("ERROR: Encrypted backing write failed: {:?}", error);

            reply.error(EIO);
            return;
        }

        /*
         * Write signature evidence only
         * after encrypted data succeeds.
         */

        let signature_result = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(SIGNATURE_FILE)
            .and_then(|mut file| {
                file.write_all(&signature_evidence)?;

                file.flush()?;

                Ok(())
            });

        if let Err(error) = signature_result {
            println!("ERROR: Signature evidence write failed: {}", error);

            let _ = self.clear_backing_file();

            reply.error(EIO);
            return;
        }

        println!("ML-DSA-65 signature evidence stored");

        reply.written(data.len() as u32);
    }
}

/* ============================================================
 * File attributes
 * ============================================================
 */

fn root_attr() -> FileAttr {
    FileAttr {
        ino: ROOT_INO,
        size: 0,
        blocks: 0,
        blksize: 512,
        atime: SystemTime::now(),
        mtime: SystemTime::now(),
        ctime: SystemTime::now(),
        crtime: SystemTime::now(),
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        flags: 0,
    }
}

fn hello_attr() -> FileAttr {
    FileAttr {
        ino: HELLO_INO,
        size: 4096,
        blocks: 1,
        blksize: 512,
        atime: SystemTime::now(),
        mtime: SystemTime::now(),
        ctime: SystemTime::now(),
        crtime: SystemTime::now(),
        kind: FileType::RegularFile,
        perm: 0o666,
        nlink: 1,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        flags: 0,
    }
}

/* ============================================================
 * Password-derived key
 * ============================================================
 */

fn derive_password_key(password: &str) -> [u8; AES_KEY_SIZE] {
    let mut hasher = Sha256::new();

    hasher.update(b"QuantumVault-QV30-KeyBundle-v1:");

    hasher.update(password.as_bytes());

    let digest = hasher.finalize();

    let mut key = [0u8; AES_KEY_SIZE];

    key.copy_from_slice(&digest);

    key
}

/* ============================================================
 * Key generation
 * ============================================================
 */

fn generate_pq_key_material() -> Result<VaultKeys, ()> {
    println!();
    println!("──────────────────────────────────────────────");
    println!("              KEY GENERATION");
    println!("──────────────────────────────────────────────");
    println!();

    let mut mlkem_public = vec![0u8; MLKEM_PUBLIC_KEY_SIZE];

    let mut mlkem_secret = SecureBytes::new(MLKEM_SECRET_KEY_SIZE)?;

    let result = unsafe {
        quantumvault_mlkem_generate_keys(
            mlkem_public.as_mut_ptr(),
            mlkem_public.len(),
            mlkem_secret.as_mut_ptr(),
            mlkem_secret.len(),
        )
    };

    if result != 1 {
        println!("ERROR: ML-KEM-768 key generation failed");

        return Err(());
    }

    println!("  ML-KEM-768 keypair        ✓ GENERATED");

    let mut mldsa_public = vec![0u8; MLDSA_PUBLIC_KEY_SIZE];

    let mut mldsa_secret = SecureBytes::new(MLDSA_SECRET_KEY_SIZE)?;

    let result = unsafe {
        quantumvault_mldsa_generate_keys(
            mldsa_public.as_mut_ptr(),
            mldsa_public.len(),
            mldsa_secret.as_mut_ptr(),
            mldsa_secret.len(),
        )
    };

    if result != 1 {
        println!("ERROR: ML-DSA-65 key generation failed");

        return Err(());
    }

    println!("  ML-DSA-65 keypair         ✓ GENERATED");

    Ok(VaultKeys {
        mlkem_public,
        mlkem_secret,
        mldsa_public,
        mldsa_secret,
    })
}

/* ============================================================
 *
 * Serialize key material in memory
 * ============================================================
 */

fn serialize_key_material(keys: &VaultKeys) -> Vec<u8> {
    let mut material = Vec::with_capacity(KEY_MATERIAL_SIZE);

    material.extend_from_slice(&keys.mlkem_public);

    material.extend_from_slice(keys.mlkem_secret.as_slice());

    material.extend_from_slice(&keys.mldsa_public);

    material.extend_from_slice(keys.mldsa_secret.as_slice());

    material
}

/* ============================================================
 *
 * Save encrypted PQ key bundle
 * ============================================================
 */

fn save_encrypted_key_bundle(keys: &VaultKeys, password: &str) -> Result<(), ()> {
    println!();
    println!("──────────────────────────────────────────────");
    println!("              KEY PROTECTION");
    println!("──────────────────────────────────────────────");
    println!();

    let material = serialize_key_material(keys);

    let password_key = derive_password_key(password);

    let key = Key::<Aes256Gcm>::try_from(password_key.as_slice()).expect("invalid AES key length");

    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];

    rand::rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("invalid AES nonce length");

    let encrypted = cipher
        .encrypt(&nonce, material.as_slice())
        .map_err(|_| ())?;

    let mut bundle = Vec::with_capacity(KEY_BUNDLE_HEADER_SIZE + encrypted.len());

    bundle.extend_from_slice(KEY_BUNDLE_MAGIC);

    bundle.push(KEY_BUNDLE_VERSION);

    bundle.extend_from_slice(&nonce_bytes);

    bundle.extend_from_slice(&encrypted);

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(KEY_BUNDLE_FILE)
        .map_err(|error| {
            println!("ERROR: Cannot create key bundle: {}", error);
        })?;

    file.write_all(&bundle).map_err(|_| ())?;

    file.flush().map_err(|_| ())?;

    fs::set_permissions(KEY_BUNDLE_FILE, fs::Permissions::from_mode(0o600)).map_err(|error| {
        println!("ERROR: Failed to set key bundle permissions: {}", error);
    })?;

    println!("  PQ key bundle          ✓ ENCRYPTED");
    println!("  Private keys           ✓ PROTECTED");
    println!("  File permissions       ✓ SECURED (0600)");

    Ok(())
}

/* ============================================================
 *
 * Load/decrypt persistent PQ key bundle
 * ============================================================
 */

fn load_encrypted_key_bundle(password: &str) -> Result<VaultKeys, ()> {
    println!("Loading encrypted PQ key bundle...");

    let bundle = fs::read(KEY_BUNDLE_FILE).map_err(|error| {
        println!("ERROR: Cannot read key bundle: {}", error);
    })?;

    if bundle.len() < KEY_BUNDLE_HEADER_SIZE {
        println!("ERROR: Key bundle too small");

        return Err(());
    }

    if &bundle[..4] != KEY_BUNDLE_MAGIC {
        println!("ERROR: Invalid key bundle magic");

        return Err(());
    }

    if bundle[4] != KEY_BUNDLE_VERSION {
        println!("ERROR: Unsupported key bundle version");

        return Err(());
    }

    let nonce_start = 5;

    let nonce_end = nonce_start + AES_NONCE_SIZE;

    let nonce_bytes = &bundle[nonce_start..nonce_end];

    let ciphertext = &bundle[nonce_end..];

    if ciphertext.len() < AES_TAG_SIZE {
        println!("ERROR: Encrypted key bundle ciphertext too small");

        return Err(());
    }

    let password_key = derive_password_key(password);

    let key = Key::<Aes256Gcm>::try_from(password_key.as_slice()).expect("invalid AES key length");

    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::try_from(nonce_bytes).expect("invalid AES nonce length");

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        println!("ERROR: Password authentication/key-bundle decryption failed");
    })?;

    if plaintext.len() != KEY_MATERIAL_SIZE {
        println!("ERROR: Invalid decrypted key material size");

        return Err(());
    }

    let material = SecureBytes::from_vec(plaintext)?;

    let mut cursor = 0usize;

    let mlkem_public = material.as_slice()[cursor..cursor + MLKEM_PUBLIC_KEY_SIZE].to_vec();

    cursor += MLKEM_PUBLIC_KEY_SIZE;

    let mut mlkem_secret = SecureBytes::new(MLKEM_SECRET_KEY_SIZE)?;

    mlkem_secret
        .as_mut_slice()
        .copy_from_slice(&material.as_slice()[cursor..cursor + MLKEM_SECRET_KEY_SIZE]);

    cursor += MLKEM_SECRET_KEY_SIZE;

    let mldsa_public = material.as_slice()[cursor..cursor + MLDSA_PUBLIC_KEY_SIZE].to_vec();

    cursor += MLDSA_PUBLIC_KEY_SIZE;

    let mut mldsa_secret = SecureBytes::new(MLDSA_SECRET_KEY_SIZE)?;

    mldsa_secret
        .as_mut_slice()
        .copy_from_slice(&material.as_slice()[cursor..cursor + MLDSA_SECRET_KEY_SIZE]);

    println!("Encrypted PQ key bundle decrypted successfully");

    println!("ML-KEM-768 private key loaded into protected memory");

    println!("ML-DSA-65 private key loaded into protected memory");

    Ok(VaultKeys {
        mlkem_public,
        mlkem_secret,
        mldsa_public,
        mldsa_secret,
    })
}

/* ============================================================
 * Initialization
 * ============================================================
 */

fn initialize_vault() -> Result<[u8; 32], ()> {
    println!();
    println!("================================================");
    println!(" QuantumVault Secure Filesystem INIT");
    println!("================================================");
    println!();

    println!("Set master password:");

    let password = read_password().map_err(|_| ())?;

    if password.len() < 8 {
        println!("ERROR: Password must contain at least 8 characters");

        return Err(());
    }

    println!("Confirm master password:");

    let confirmation = read_password().map_err(|_| ())?;

    if password != confirmation {
        println!("ERROR: Password confirmation failed");

        return Err(());
    }

    /*
     * Generate persistent PQ keys.
     */

    let keys = generate_pq_key_material()?;

    /*
     * Encrypt PQ private/public bundle.
     */

    save_encrypted_key_bundle(&keys, &password)?;

    /*
     * Clean old runtime data.
     */

    let _ = fs::remove_file(BACKING_FILE);

    let _ = fs::remove_file(SIGNATURE_FILE);

    println!();
    println!("Vault initialization successful");

    println!("Master password protects the PQ key bundle");

    println!("Ready for secure mount");

    /*
     * Return password-derived key only for
     * compatibility with the runtime structure.
     *
     * Actual file encryption uses ML-KEM shared
     * secrets in .
     */

    Ok(derive_password_key(&password))
}

/* ============================================================
 * Unlock
 * ============================================================
 */

fn unlock_vault() -> Result<VaultKeys, ()> {
    println!();
    println!("──────────────────────────────────────────────");
    println!("         QuantumVault Secure Unlock");
    println!("──────────────────────────────────────────────");
    println!();

    if !PathBuf::from(KEY_BUNDLE_FILE).exists() {
        println!("ERROR: QuantumVault is not initialized");
        println!("Run: quantumvault-fuse init <mountpoint>");

        return Err(());
    }

    println!("  Master password required");
    println!();

    print!("  Enter master password: ");
    std::io::stdout().flush().map_err(|_| ())?;

    let password = read_password().map_err(|_| ())?;

    println!();
    println!("  Loading encrypted key bundle...");

    let keys = load_encrypted_key_bundle(&password)?;

    println!("  Key bundle decrypted       ✓");
    println!("  ML-KEM-768 private key     ✓ LOADED");
    println!("  ML-DSA-65 private key      ✓ LOADED");

    println!();
    println!("──────────────────────────────────────────────");
    println!("        QuantumVault Secure Unlocked");
    println!("──────────────────────────────────────────────");
    println!();
    println!("  ✓ QuantumVault unlocked successfully.");
    println!("  ✓ Protected keys loaded into secure memory.");
    println!();

    Ok(keys)
}

/* ============================================================
 * Status
 * ============================================================
 */

fn status_vault() {
    let key_bundle = PathBuf::from(KEY_BUNDLE_FILE).exists();
    let encrypted_data = PathBuf::from(BACKING_FILE).exists();
    let signature = PathBuf::from(SIGNATURE_FILE).exists();

    println!();
    println!("╔══════════════════════════════════════════════╗");
    println!("║                                              ║");
    println!("║                                              ║");
    println!("║         ◈ Q U A N T U M V A U L T ◈          ║");
    println!("║                                              ║");
    println!("║                                              ║");
    println!("║    --- Quantum-Resistant Secure Vault ---    ║");
    println!("║                                              ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    println!("──────────────────────────────────────────────");
    println!("                VAULT STATUS");
    println!("──────────────────────────────────────────────");
    println!(
        "  Vault              {}",
        if key_bundle {
            "● READY"
        } else {
            "● NOT INITIALIZED"
        }
    );
    println!(
        "  Encrypted Data     {}",
        if encrypted_data {
            "● PRESENT"
        } else {
            "○ EMPTY"
        }
    );
    println!(
        "  Signature Evidence {}",
        if signature {
            "● PRESENT"
        } else {
            "○ EMPTY"
        }
    );

    println!();
    println!("──────────────────────────────────────────────");
    println!("                 CRYPTOGRAPHY");
    println!("──────────────────────────────────────────────");
    println!("  Key Encapsulation  ML-KEM-768");
    println!("  Digital Signature  ML-DSA-65");
    println!("  Encryption         AES-256-GCM");
    println!("  Integrity          ML-DSA-65");

    println!();
    println!("──────────────────────────────────────────────");
    println!("                 KEY SECURITY");
    println!("──────────────────────────────────────────────");
    println!("  Key Bundle         AES-256-GCM encrypted");
    println!("  Private Keys       ENCRYPTED ON DISK");

    println!();
    if key_bundle {
        println!("✓ QuantumVault is ready.");
    } else {
        println!("! Initialize QuantumVault with: quantumvault-fuse init <mountpoint>");
    }
    println!();
}

/* ============================================================
 * Test
 * ============================================================
 */

fn run_crypto_test() -> bool {
    println!();
    println!("──────────────────────────────────────────────");
    println!("           CRYPTOGRAPHIC SELF-TEST");
    println!("──────────────────────────────────────────────");
    println!();

    println!("  ML-KEM-768");
    println!("  ├─ Key encapsulation test   ...");

    let kem = unsafe { quantumvault_ffi_test() };

    if kem != 1 {
        println!("  └─ ✗ FAILED");
        println!();
        println!("──────────────────────────────────────────────");
        println!("           SELF-TEST FAILED");
        println!("──────────────────────────────────────────────");
        println!();

        return false;
    }

    println!("  └─ ✓ PASSED");
    println!();

    println!("  ML-DSA-65");
    println!("  ├─ Digital signature test   ...");

    let dsa = unsafe { quantumvault_mldsa_test() };

    if dsa != 1 {
        println!("  └─ ✗ FAILED");
        println!();
        println!("──────────────────────────────────────────────");
        println!("           SELF-TEST FAILED");
        println!("──────────────────────────────────────────────");
        println!();

        return false;
    }

    println!("  └─ ✓ PASSED");
    println!();

    println!("──────────────────────────────────────────────");
    println!("             TEST SUMMARY");
    println!("──────────────────────────────────────────────");
    println!();
    println!("  ML-KEM-768              ✓ PASSED");
    println!("  ML-DSA-65               ✓ PASSED");
    println!("  Cryptographic tests     ✓ PASSED");
    println!();

    println!("──────────────────────────────────────────────");
    println!("        CRYPTOGRAPHY VERIFIED ✓");
    println!("──────────────────────────────────────────────");
    println!();

    true
}

/* ============================================================
 * Mount
 * ============================================================
 */

fn mount_vault(mountpoint: String, keys: VaultKeys) {
    println!();
    println!("──────────────────────────────────────────────");
    println!("              SECURE VAULT MOUNT");
    println!("──────────────────────────────────────────────");
    println!();

    println!("  Mountpoint          {}", mountpoint);
    println!("  Key Management      ✓ PQ KEYS LOADED");
    println!("  Encryption          ✓ ML-KEM-768 + AES-256-GCM");
    println!("  Integrity           ✓ ML-DSA-65");
    println!("  Memory Security     ✓ ENABLED");
    println!("  Backing Storage     {}", BACKING_FILE);
    println!("  Key Bundle          {}", KEY_BUNDLE_FILE);

    println!();
    println!("──────────────────────────────────────────────");
    println!("              QUANTUMVAULT READY");
    println!("──────────────────────────────────────────────");
    println!();

    fuser::mount2(
        QuantumVaultFS {
            backing_file: PathBuf::from(BACKING_FILE),
            keys,
        },
        mountpoint,
        &[
            fuser::MountOption::FSName("quantumvault".to_string()),
            fuser::MountOption::AutoUnmount,
        ],
    )
    .expect("Failed to mount QuantumVault filesystem");
}

/* ============================================================
 * CLI
 * ============================================================
 */

fn print_usage() {
    println!();
    println!("╔══════════════════════════════════════════════╗");
    println!("║                                              ║");
    println!("║         ◈ Q U A N T U M V A U L T ◈          ║");
    println!("║                                              ║");
    println!("║    --- Quantum-Resistant Secure Vault ---    ║");
    println!("║                                              ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    println!("──────────────────────────────────────────────");
    println!("                  USAGE");
    println!("──────────────────────────────────────────────");
    println!();

    println!("  quantumvault-fuse init <mountpoint>");
    println!("      Initialize vault and generate PQ keys");
    println!();

    println!("  quantumvault-fuse <mountpoint>");
    println!("      Unlock and mount an existing vault");
    println!();

    println!("  quantumvault-fuse status");
    println!("      Display vault and cryptographic status");
    println!();

    println!("  quantumvault-fuse test");
    println!("      Run ML-KEM-768 and ML-DSA-65 self-tests");
    println!();

    println!("  quantumvault-fuse help");
    println!("      Display this help information");
    println!();

    println!("──────────────────────────────────────────────");
    println!("                 COMMANDS");
    println!("──────────────────────────────────────────────");
    println!();

    println!("  init <mountpoint>    Initialize secure vault");
    println!("  <mountpoint>         Unlock and mount vault");
    println!("  status               Show vault status");
    println!("  test                 Run cryptographic self-tests");
    println!("  help                 Show command reference");
    println!();

    println!("──────────────────────────────────────────────");
    println!("             SECURITY ARCHITECTURE");
    println!("──────────────────────────────────────────────");
    println!();

    println!("  Key Encapsulation     ML-KEM-768");
    println!("  Digital Signature     ML-DSA-65");
    println!("  File Encryption       AES-256-GCM");
    println!("  Memory Protection     mlock + secure wipe");
    println!();

    println!("✓ QuantumVault — Quantum-Resistant Secure Storage");
    println!();
}

/* ============================================================
 * MAIN
 * ============================================================
 */

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    if args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        print_usage();
        return;
    }

    if args[1] == "status" {
        status_vault();
        return;
    }

    if args[1] == "test" {
        if !run_crypto_test() {
            println!();
            println!("ERROR: Cryptographic self-test failed");
            println!();

            std::process::exit(1);
        }

        return;
    }

    if args[1] == "init" {
        if args.len() != 3 {
            println!();
            println!("──────────────────────────────────────────────");
            println!("              INVALID COMMAND");
            println!("──────────────────────────────────────────────");
            println!();
            println!("  ERROR: init requires a mountpoint");
            println!();
            println!("  Example:");
            println!("    quantumvault-fuse init /tmp/quantumvault-mnt");
            println!();

            print_usage();
            return;
        }

        let mountpoint = args[2].clone();

        println!();
        println!("──────────────────────────────────────────────");
        println!("          QUANTUMVAULT INITIALIZATION");
        println!("──────────────────────────────────────────────");
        println!();
        println!("  Mountpoint: {}", mountpoint);
        println!();

        if initialize_vault().is_err() {
            println!();
            println!("──────────────────────────────────────────────");
            println!("          INITIALIZATION FAILED");
            println!("──────────────────────────────────────────────");
            println!();
            println!("  ERROR: Vault initialization failed");
            println!();

            return;
        }

        println!();
        println!("  Vault initialization       ✓ COMPLETE");
        println!();

        let keys = match unlock_vault() {
            Ok(keys) => keys,

            Err(_) => {
                println!();
                println!("──────────────────────────────────────────────");
                println!("            UNLOCK FAILED");
                println!("──────────────────────────────────────────────");
                println!();
                println!("  ERROR: Post-initialization unlock failed");
                println!();

                return;
            }
        };

        mount_vault(mountpoint, keys);

        return;
    }

    if args.len() == 2 {
        let mountpoint = args[1].clone();

        let keys = match unlock_vault() {
            Ok(keys) => keys,

            Err(_) => {
                println!();
                println!("──────────────────────────────────────────────");
                println!("             VAULT ACCESS DENIED");
                println!("──────────────────────────────────────────────");
                println!();
                println!("  ERROR: QuantumVault unlock failed");
                println!("  Check your master password and try again.");
                println!();

                return;
            }
        };

        mount_vault(mountpoint, keys);

        return;
    }

    println!();
    println!("──────────────────────────────────────────────");
    println!("              INVALID COMMAND");
    println!("──────────────────────────────────────────────");
    println!();
    println!("  ERROR: Unknown command or invalid arguments.");
    println!();

    print_usage();
}
