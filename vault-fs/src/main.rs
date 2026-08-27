pub mod crypto;

use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyWrite, ReplyCreate, Request,
};
use libc::ENOENT;

const TTL: Duration = Duration::from_secs(1);

struct InodeMap {
    next_ino: u64,
    ino_to_path: HashMap<u64, PathBuf>,
    path_to_ino: HashMap<PathBuf, u64>,
}

impl InodeMap {
    fn new() -> Self {
        let mut map = InodeMap {
            next_ino: 2, // 1 is root directory
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
        };
        map.ino_to_path.insert(1, PathBuf::from(""));
        map.path_to_ino.insert(PathBuf::from(""), 1);
        map
    }

    fn get_path(&self, ino: u64) -> Option<PathBuf> {
        self.ino_to_path.get(&ino).cloned()
    }

    fn get_ino(&mut self, path: &Path) -> u64 {
        let path_buf = path.to_path_buf();
        if let Some(&ino) = self.path_to_ino.get(&path_buf) {
            ino
        } else {
            let ino = self.next_ino;
            self.next_ino += 1;
            self.ino_to_path.insert(ino, path_buf.clone());
            self.path_to_ino.insert(path_buf, ino);
            ino
        }
    }
}

struct QuantumFS {
    backend: PathBuf,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    dilithium_public: Vec<u8>,
    dilithium_secret: Vec<u8>,
    inode_map: Mutex<InodeMap>,
}

impl QuantumFS {
    fn new(backend: PathBuf, keys: crypto::KyberKeys, dil_keys: crypto::DilithiumKeys) -> Self {
        QuantumFS {
            backend,
            public_key: keys.public_key,
            secret_key: keys.secret_key,
            dilithium_public: dil_keys.public_key,
            dilithium_secret: dil_keys.secret_key,
            inode_map: Mutex::new(InodeMap::new()),
        }
    }

    fn verify_file_authenticity(&self, full_path: &Path) -> bool {
        if full_path.is_dir() {
            return true;
        }

        let mut sig_path = full_path.to_path_buf();
        let mut file_name = match full_path.file_name() {
            Some(n) => n.to_os_string(),
            None => return false,
        };
        file_name.push(".sig");
        sig_path.set_file_name(file_name);

        if !sig_path.exists() {
            log::warn!("Missing signature for file: {:?}", full_path);
            return false;
        }

        // Read signature
        let signature = match std::fs::read(&sig_path) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // Read backing file
        let disk_data = match std::fs::read(full_path) {
            Ok(data) => data,
            Err(_) => return false,
        };

        if disk_data.is_empty() {
            // Verify signature on empty payload
            return crypto::verify(b"", &signature, &self.dilithium_public).is_ok();
        }

        if disk_data.len() < 1088 {
            return false;
        }

        let kem_ciphertext = &disk_data[0..1088];
        let ciphertext = &disk_data[1088..];

        // Decrypt plaintext to verify signature on plaintext
        let plaintext = match crypto::decrypt(ciphertext, kem_ciphertext, &self.secret_key) {
            Ok(pt) => pt,
            Err(_) => return false,
        };

        // Verify signature using Dilithium public key
        crypto::verify(&plaintext, &signature, &self.dilithium_public).is_ok()
    }
}

fn file_attr_from_metadata(ino: u64, metadata: &std::fs::Metadata) -> FileAttr {
    let size = if metadata.is_file() {
        let raw_size = metadata.len();
        // Transparent size adjustment: hide the 1088-byte KEM ciphertext prefix
        if raw_size >= 1088 {
            raw_size - 1088
        } else {
            0
        }
    } else {
        0
    };

    let kind = if metadata.is_dir() {
        FileType::Directory
    } else {
        FileType::RegularFile
    };

    FileAttr {
        ino,
        size,
        blocks: (size + 511) / 512,
        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
        ctime: metadata.created().unwrap_or(UNIX_EPOCH),
        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
        kind,
        perm: if metadata.is_dir() { 0o755 } else { 0o644 },
        nlink: if metadata.is_dir() { 2 } else { 1 },
        uid: 501,
        gid: 20,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

impl Filesystem for QuantumFS {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = match self.inode_map.lock().unwrap().get_path(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let rel_path = parent_path.join(name);
        let full_path = self.backend.join(&rel_path);

        if full_path.exists() {
            if name.to_string_lossy().ends_with(".sig") {
                reply.error(ENOENT);
                return;
            }

            if !self.verify_file_authenticity(&full_path) {
                log::error!("Authenticity verification failed for lookup of {:?}", full_path);
                reply.error(libc::EACCES);
                return;
            }

            let mut inode_map = self.inode_map.lock().unwrap();
            let ino = inode_map.get_ino(&rel_path);
            
            if let Ok(metadata) = std::fs::metadata(&full_path) {
                let attr = file_attr_from_metadata(ino, &metadata);
                reply.entry(&TTL, &attr, 0);
            } else {
                reply.error(ENOENT);
            }
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let rel_path = match self.inode_map.lock().unwrap().get_path(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let full_path = self.backend.join(&rel_path);
        if !self.verify_file_authenticity(&full_path) {
            log::error!("Authenticity verification failed for getattr of {:?}", full_path);
            reply.error(libc::EACCES);
            return;
        }

        if let Ok(metadata) = std::fs::metadata(&full_path) {
            let attr = file_attr_from_metadata(ino, &metadata);
            reply.attr(&TTL, &attr);
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
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let rel_path = match self.inode_map.lock().unwrap().get_path(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let full_path = self.backend.join(&rel_path);

        if !full_path.exists() {
            reply.error(ENOENT);
            return;
        }

        if full_path.is_dir() {
            if size.is_some() {
                reply.error(libc::EISDIR);
                return;
            }
        }

        // Handle file truncation / resizing
        if let Some(new_size) = size {
            let new_size = new_size as usize;
            let mut plaintext = Vec::new();

            if full_path.exists() {
                match std::fs::read(&full_path) {
                    Ok(disk_data) => {
                        if disk_data.len() >= 1088 {
                            let kem_ciphertext = &disk_data[0..1088];
                            let ciphertext = &disk_data[1088..];
                            match crypto::decrypt(ciphertext, kem_ciphertext, &self.secret_key) {
                                Ok(decrypted) => {
                                    plaintext = decrypted;
                                }
                                Err(err) => {
                                    log::error!("Decryption failed during setattr resize: {:?}", err);
                                    reply.error(libc::EIO);
                                    return;
                                }
                            }
                        } else if disk_data.len() > 0 {
                            log::error!("Backing file is corrupted during setattr (size {} < 1088)", disk_data.len());
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                    Err(err) => {
                        log::error!("Failed to read backing file during setattr: {:?}", err);
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }

            plaintext.resize(new_size, 0);

            let encrypted = match crypto::encrypt(&plaintext, &self.public_key) {
                Ok(enc) => enc,
                Err(err) => {
                    log::error!("Encryption failed during setattr resize: {:?}", err);
                    reply.error(libc::EIO);
                    return;
                }
            };

            // Dilithium signing for truncated plaintext
            let signature = match crypto::sign(&plaintext, &self.dilithium_secret) {
                Ok(sig) => sig,
                Err(err) => {
                    log::error!("Dilithium signing failed during setattr: {:?}", err);
                    reply.error(libc::EIO);
                    return;
                }
            };

            let mut disk_buffer = Vec::with_capacity(1088 + encrypted.ciphertext.len());
            disk_buffer.extend_from_slice(&encrypted.kem_ciphertext);
            disk_buffer.extend_from_slice(&encrypted.ciphertext);

            if let Err(err) = std::fs::write(&full_path, disk_buffer) {
                log::error!("Failed to write truncated file to backing store: {:?}", err);
                reply.error(libc::EIO);
                return;
            }

            // Write updated signature
            let mut sig_path = full_path.clone();
            let mut file_name = full_path.file_name().unwrap_or_default().to_os_string();
            file_name.push(".sig");
            sig_path.set_file_name(file_name);
            if let Err(err) = std::fs::write(&sig_path, signature) {
                log::error!("Failed to write signature during setattr: {:?}", err);
                reply.error(libc::EIO);
                return;
            }
        }

        if let Ok(metadata) = std::fs::metadata(&full_path) {
            let attr = file_attr_from_metadata(ino, &metadata);
            reply.attr(&TTL, &attr);
        } else {
            reply.error(ENOENT);
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.inode_map.lock().unwrap().get_path(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let rel_path = parent_path.join(name);
        let full_path = self.backend.join(&rel_path);

        if std::fs::File::create(&full_path).is_ok() {
            // Write signature for empty plaintext
            if let Ok(sig) = crypto::sign(b"", &self.dilithium_secret) {
                let mut sig_path = full_path.clone();
                let mut file_name = full_path.file_name().unwrap_or_default().to_os_string();
                file_name.push(".sig");
                sig_path.set_file_name(file_name);
                let _ = std::fs::write(&sig_path, sig);
            }

            let mut inode_map = self.inode_map.lock().unwrap();
            let ino = inode_map.get_ino(&rel_path);
            
            if let Ok(metadata) = std::fs::metadata(&full_path) {
                let attr = file_attr_from_metadata(ino, &metadata);
                reply.created(&TTL, &attr, 0, 0, 0);
            } else {
                reply.error(ENOENT);
            }
        } else {
            reply.error(libc::EACCES);
        }
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
        let rel_path = match self.inode_map.lock().unwrap().get_path(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let full_path = self.backend.join(&rel_path);

        if !full_path.exists() {
            reply.error(ENOENT);
            return;
        }

        match std::fs::read(&full_path) {
            Ok(disk_data) => {
                if disk_data.is_empty() {
                    // Check signature for empty payload
                    let mut sig_path = full_path.clone();
                    let mut file_name = match full_path.file_name() {
                        Some(n) => n.to_os_string(),
                        None => {
                            reply.error(libc::EIO);
                            return;
                        }
                    };
                    file_name.push(".sig");
                    sig_path.set_file_name(file_name);

                    let signature = match std::fs::read(&sig_path) {
                        Ok(sig) => sig,
                        Err(_) => {
                            log::error!("Missing signature for empty file: {:?}", full_path);
                            reply.error(libc::EIO);
                            return;
                        }
                    };

                    if crypto::verify(b"", &signature, &self.dilithium_public).is_err() {
                        log::error!("Signature verification failed for empty file: {:?}", full_path);
                        reply.error(libc::EIO);
                        return;
                    }

                    reply.data(&[]);
                    return;
                }

                if disk_data.len() >= 1088 {
                    let kem_ciphertext = &disk_data[0..1088];
                    let ciphertext = &disk_data[1088..];
                    
                    match crypto::decrypt(ciphertext, kem_ciphertext, &self.secret_key) {
                        Ok(plaintext) => {
                            // Verify signature on plaintext
                            let mut sig_path = full_path.clone();
                            let mut file_name = match full_path.file_name() {
                                Some(n) => n.to_os_string(),
                                None => {
                                    reply.error(libc::EIO);
                                    return;
                                }
                            };
                            file_name.push(".sig");
                            sig_path.set_file_name(file_name);

                            let signature = match std::fs::read(&sig_path) {
                                Ok(sig) => sig,
                                Err(_) => {
                                    log::error!("Missing signature for file: {:?}", full_path);
                                    reply.error(libc::EIO);
                                    return;
                                }
                            };

                            if crypto::verify(&plaintext, &signature, &self.dilithium_public).is_err() {
                                log::error!("Signature verification failed during read of {:?}", full_path);
                                reply.error(libc::EIO);
                                return;
                            }

                            let plaintext_len = plaintext.len() as i64;
                            if offset < plaintext_len {
                                let start = offset as usize;
                                let end = std::cmp::min(plaintext_len, offset + size as i64) as usize;
                                reply.data(&plaintext[start..end]);
                            } else {
                                reply.data(&[]);
                            }
                        }
                        Err(err) => {
                            log::error!("Decryption failed during read: {:?}", err);
                            reply.error(libc::EIO);
                        }
                    }
                } else {
                    log::error!("Corrupted backing file size {} < 1088 during read of {:?}", disk_data.len(), full_path);
                    reply.error(libc::EIO);
                }
            }
            Err(_) => reply.error(libc::EIO),
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
        let rel_path = match self.inode_map.lock().unwrap().get_path(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let full_path = self.backend.join(&rel_path);

        if full_path.is_dir() {
            reply.error(libc::EISDIR);
            return;
        }

        let mut plaintext = Vec::new();
        if full_path.exists() {
            match std::fs::read(&full_path) {
                Ok(disk_data) => {
                    if disk_data.len() >= 1088 {
                        let kem_ciphertext = &disk_data[0..1088];
                        let ciphertext = &disk_data[1088..];
                        match crypto::decrypt(ciphertext, kem_ciphertext, &self.secret_key) {
                            Ok(decrypted) => {
                                plaintext = decrypted;
                            }
                            Err(err) => {
                                log::error!("Decryption failed during write: {:?}", err);
                                reply.error(libc::EIO);
                                return;
                            }
                        }
                    } else if disk_data.len() > 0 {
                        log::error!("Backing file is corrupted (size {} < 1088)", disk_data.len());
                        reply.error(libc::EIO);
                        return;
                    }
                }
                Err(err) => {
                    log::error!("Failed to read backing file: {:?}", err);
                    reply.error(libc::EIO);
                    return;
                }
            }
        }

        let offset = offset as usize;
        if plaintext.len() < offset {
            plaintext.resize(offset, 0);
        }

        let end = offset + data.len();
        if plaintext.len() < end {
            plaintext.resize(end, 0);
        }
        plaintext[offset..end].copy_from_slice(data);

        let encrypted = match crypto::encrypt(&plaintext, &self.public_key) {
            Ok(enc) => enc,
            Err(err) => {
                log::error!("Encryption failed during write: {:?}", err);
                reply.error(libc::EIO);
                return;
            }
        };

        // Dilithium signing for updated plaintext
        let signature = match crypto::sign(&plaintext, &self.dilithium_secret) {
            Ok(sig) => sig,
            Err(err) => {
                log::error!("Dilithium signing failed during write: {:?}", err);
                reply.error(libc::EIO);
                return;
            }
        };

        let mut disk_buffer = Vec::with_capacity(1088 + encrypted.ciphertext.len());
        disk_buffer.extend_from_slice(&encrypted.kem_ciphertext);
        disk_buffer.extend_from_slice(&encrypted.ciphertext);

        if let Err(err) = std::fs::write(&full_path, disk_buffer) {
            log::error!("Failed to write encrypted file to backing store: {:?}", err);
            reply.error(libc::EIO);
        } else {
            // Write updated signature
            let mut sig_path = full_path.clone();
            let mut file_name = full_path.file_name().unwrap_or_default().to_os_string();
            file_name.push(".sig");
            sig_path.set_file_name(file_name);
            if let Err(err) = std::fs::write(&sig_path, signature) {
                log::error!("Failed to write signature to backing store: {:?}", err);
                reply.error(libc::EIO);
            } else {
                reply.written(data.len() as u32);
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
        let parent_path = match self.inode_map.lock().unwrap().get_path(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let full_path = self.backend.join(&parent_path);
        
        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (1, FileType::Directory, "..".to_string()),
        ];

        if let Ok(read_dir) = std::fs::read_dir(&full_path) {
            let mut inode_map = self.inode_map.lock().unwrap();
            for entry_res in read_dir {
                if let Ok(entry) = entry_res {
                    let file_name = entry.file_name().to_string_lossy().into_owned();
                    if file_name.ends_with(".sig") {
                        continue;
                    }
                    let rel_entry_path = parent_path.join(&file_name);
                    
                    let file_type = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    
                    let child_ino = inode_map.get_ino(&rel_entry_path);
                    entries.push((child_ino, file_type, file_name));
                }
            }
        }

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, &entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    // Initialize env logger for debugging
    env_logger::init();

    println!("=========================================");
    println!("QuantumVault FUSE Filesystem");
    println!("=========================================");

    // Parse arguments (expect mount point and backend store directory)
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <MOUNT_POINT> <BACKEND_DIR>", args[0]);
        process::exit(1);
    }

    let mountpoint = &args[1];
    let backend_dir = &args[2];
    println!("Mounting filesystem to: {}", mountpoint);
    println!("Backing store directory: {}", backend_dir);

    // Ensure backend store exists
    let backend_path = PathBuf::from(backend_dir);
    if !backend_path.exists() {
        std::fs::create_dir_all(&backend_path).expect("Failed to create backing store directory");
    }

    // Generate CRYSTALS-Kyber-768 session keys
    println!("Generating post-quantum session keypair...");
    let keys = crypto::generate_keypair().expect("Failed to generate CRYSTALS-Kyber-768 session keys");
    println!("Session keypair generated successfully.");

    // Generate CRYSTALS-Dilithium-3 keys
    println!("Generating CRYSTALS-Dilithium-3 authenticity keypair...");
    let dil_keys = crypto::generate_dilithium_keypair().expect("Failed to generate CRYSTALS-Dilithium-3 keys");
    println!("Dilithium-3 keypair generated successfully.");

    let options = vec![
        MountOption::RW,
        MountOption::FSName("quantum_fs".to_string()),
        MountOption::AutoUnmount,
    ];

    let quantum_fs = QuantumFS::new(backend_path, keys, dil_keys);

    #[cfg(target_os = "linux")]
    {
        if let Err(err) = fuser::mount2(quantum_fs, mountpoint, &options) {
            eprintln!("Error mounting filesystem: {:?}", err);
            process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = quantum_fs;
        eprintln!("Warning: FUSE mounts are only supported on Linux targets. Active OS is not Linux.");
        eprintln!("QuantumFS compiled successfully! To test actual mounting, run on WSL2 or native Linux.");
    }
}
