use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};

use libc::{EIO, ENOENT};

use std::{
    ffi::OsStr,
    fs::OpenOptions,
    io::{Read, Write},
    path::PathBuf,
    time::{Duration, SystemTime},
};

unsafe extern "C" {
    fn quantumvault_ffi_test() -> i32;

    fn quantumvault_mldsa_test() -> i32;

    fn quantumvault_mldsa_sign_data(
        data: *const u8,
        data_len: usize,
        signature: *mut u8,
        signature_len: *mut usize,
    ) -> i32;

    fn quantumvault_mldsa_verify_data(
        data: *const u8,
        data_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> i32;
}

const TTL: Duration = Duration::from_secs(1);

const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;

const ENCRYPTION_KEY: [u8; 32] = [0x42; 32];
const ENCRYPTION_NONCE: [u8; 12] = *b"QVNonce12345";

const SIGNATURE_FILE: &str = "/tmp/quantumvault_signature.bin";

struct QuantumVaultFS {
    backing_file: PathBuf,
}

impl QuantumVaultFS {
    fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        let key = Key::<Aes256Gcm>::from_slice(&ENCRYPTION_KEY);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&ENCRYPTION_NONCE);

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| ())
    }

    fn decrypt_data(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let key = Key::<Aes256Gcm>::from_slice(&ENCRYPTION_KEY);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&ENCRYPTION_NONCE);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| ())
    }

    fn clear_backing_file(&self) -> Result<(), ()> {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.backing_file)
            .map(|_| ())
            .map_err(|_| ())
    }

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

        let mut signature = vec![0u8; ML_DSA_65_SIGNATURE_SIZE];
        let mut signature_len: usize = 0;

        let result = unsafe {
            quantumvault_mldsa_sign_data(
                data.as_ptr(),
                data.len(),
                signature.as_mut_ptr(),
                &mut signature_len,
            )
        };

        if result != 1 || signature_len == 0 {
            println!(
                "[Rust] ERROR: ML-DSA-65 signing failed"
            );

            return Err(());
        }

        signature.truncate(signature_len);

        Ok(signature)
    }
}

impl Filesystem for QuantumVaultFS {
    fn lookup(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        if parent == ROOT_INO && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &hello_attr(), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: Option<u64>,
        reply: ReplyAttr,
    ) {
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

        for (i, (entry_ino, kind, name)) in entries
            .iter()
            .enumerate()
            .skip(offset as usize)
        {
            if reply.add(
                *entry_ino,
                (i + 1) as i64,
                *kind,
                *name,
            ) {
                break;
            }
        }

        reply.ok();
    }

    fn open(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _flags: i32,
        reply: ReplyOpen,
    ) {
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
            println!(
                "[Rust] FUSE setattr() received size request: {} bytes",
                new_size
            );

            if new_size == 0 {
                if self.clear_backing_file().is_err() {
                    println!(
                        "[Rust] ERROR: Failed to truncate encrypted backing file"
                    );

                    reply.error(EIO);
                    return;
                }

                let _ = std::fs::remove_file(SIGNATURE_FILE);

                println!(
                    "[Rust] Encrypted backing file truncated successfully"
                );

                println!(
                    "[Rust] ML-DSA signature evidence cleared"
                );
            }
        }

        reply.attr(&TTL, &hello_attr());
    }

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
            .and_then(|mut file| {
                file.read_to_end(&mut encrypted_data)
            });

        if read_result.is_err() || encrypted_data.is_empty() {
            reply.data(&[]);
            return;
        }

        match self.decrypt_data(&encrypted_data) {
            Ok(plaintext) => {
                println!(
                    "[Rust] QV-19: AES-GCM decryption successful"
                );

                let mut signature = Vec::new();

                match OpenOptions::new()
                    .read(true)
                    .open(SIGNATURE_FILE)
                    .and_then(|mut file| {
                        file.read_to_end(&mut signature)
                    })
                {
                    Ok(_) => {
                        if signature.is_empty() {
                            println!(
                                "[Rust] QV-19 ERROR: Signature evidence is empty"
                            );

                            reply.error(EIO);
                            return;
                        }
                    }

                    Err(_) => {
                        println!(
                            "[Rust] QV-19 ERROR: Failed to read ML-DSA signature evidence"
                        );

                        reply.error(EIO);
                        return;
                    }
                }

                println!(
                    "[Rust] QV-19: Verifying ML-DSA-65 signature..."
                );

                let verify_result = unsafe {
                    quantumvault_mldsa_verify_data(
                        plaintext.as_ptr(),
                        plaintext.len(),
                        signature.as_ptr(),
                        signature.len(),
                    )
                };

                if verify_result != 1 {
                    println!(
                        "[Rust] QV-19 ERROR: ML-DSA-65 signature verification failed"
                    );

                    reply.error(EIO);
                    return;
                }

                println!(
                    "[Rust] QV-19: ML-DSA-65 signature verification successful"
                );

                let start = offset.max(0) as usize;

                if start >= plaintext.len() {
                    reply.data(&[]);
                    return;
                }

                let end = std::cmp::min(
                    start + size as usize,
                    plaintext.len(),
                );

                reply.data(&plaintext[start..end]);
            }

            Err(_) => {
                println!(
                    "[Rust] ERROR: AES-GCM decryption failed"
                );

                reply.error(EIO);
            }
        }
    }

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

        println!(
            "[Rust] FUSE write() received {} plaintext bytes",
            data.len()
        );

        println!(
            "[Rust] Write offset: {}",
            offset
        );

        /*
         * QV-17 DIGITAL SIGNATURE
         *
         * Sign the plaintext before encryption so the vault
         * retains cryptographic integrity evidence for the
         * original file content.
         */
        println!(
            "[Rust] QV-17: Generating ML-DSA-65 signature..."
        );

        let signature = match self.sign_data(data) {
            Ok(signature) => signature,

            Err(_) => {
                println!(
                    "[Rust] ERROR: ML-DSA-65 signature generation failed"
                );

                reply.error(EIO);
                return;
            }
        };

        println!(
            "[Rust] QV-17: ML-DSA-65 signature generated successfully"
        );

        println!(
            "[Rust] QV-17: Signature size: {} bytes",
            signature.len()
        );

        let signature_write_result = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(SIGNATURE_FILE)
            .and_then(|mut file| {
                file.write_all(&signature)?;
                file.flush()?;
                Ok(())
            });

        if let Err(error) = signature_write_result {
            println!(
                "[Rust] ERROR: Failed to write ML-DSA signature: {}",
                error
            );

            reply.error(EIO);
            return;
        }

        println!(
            "[Rust] QV-17: Signature written to: {}",
            SIGNATURE_FILE
        );

        /*
         * Existing AES-GCM encryption flow.
         */
        let ciphertext = match self.encrypt_data(data) {
            Ok(ciphertext) => ciphertext,

            Err(_) => {
                println!(
                    "[Rust] ERROR: AES-GCM encryption failed"
                );

                reply.error(EIO);
                return;
            }
        };

        println!(
            "[Rust] AES-GCM encryption successful"
        );

        println!(
            "[Rust] Plaintext size: {} bytes",
            data.len()
        );

        println!(
            "[Rust] Ciphertext size: {} bytes",
            ciphertext.len()
        );

        let write_result = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.backing_file)
            .and_then(|mut file| {
                file.write_all(&ciphertext)?;
                file.flush()?;
                Ok(())
            });

        match write_result {
            Ok(()) => {
                println!(
                    "[Rust] Encrypted data written to: {}",
                    self.backing_file.display()
                );

                println!(
                    "[Rust] QV-17: Digital signature + encryption completed"
                );

                reply.written(data.len() as u32);
            }

            Err(error) => {
                println!(
                    "[Rust] ERROR: Encrypted write failed: {}",
                    error
                );

                reply.error(EIO);
            }
        }
    }
}

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

fn main() {
    let mountpoint = std::env::args()
        .nth(1)
        .expect(
            "Usage: quantumvault-fuse <mountpoint>"
        );

    println!("QuantumVault filesystem");
    println!("Mounting at: {}", mountpoint);

    let ffi_result = unsafe {
        quantumvault_ffi_test()
    };

    println!(
        "[Rust] FFI test returned: {}",
        ffi_result
    );

    if ffi_result == 1 {
        println!(
            "[Rust] PQC FFI test successful"
        );
    } else {
        println!(
            "[Rust] WARNING: PQC FFI test failed"
        );
    }

    let mldsa_result = unsafe {
        quantumvault_mldsa_test()
    };

    println!(
        "[Rust] ML-DSA FFI test returned: {}",
        mldsa_result
    );

    if mldsa_result == 1 {
        println!(
            "[Rust] ML-DSA FFI test successful"
        );
    } else {
        println!(
            "[Rust] WARNING: ML-DSA FFI test failed"
        );
    }

    let backing_file =
        PathBuf::from(
            "/tmp/quantumvault_encrypted.bin"
        );

    println!(
        "[Rust] Encrypted backing file: {}",
        backing_file.display()
    );

    println!(
        "[Rust] ML-DSA signature file: {}",
        SIGNATURE_FILE
    );

    fuser::mount2(
        QuantumVaultFS {
            backing_file,
        },
        mountpoint,
        &[
            fuser::MountOption::FSName(
                "quantumvault".to_string()
            ),
            fuser::MountOption::AutoUnmount,
        ],
    )
    .expect(
        "Failed to mount FUSE filesystem"
    );
}
