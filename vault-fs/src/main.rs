use std::env;
use std::ffi::OsStr;
use std::process;
use std::time::{Duration, UNIX_EPOCH};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::ENOENT;

const TTL: Duration = Duration::from_secs(1);

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    blksize: 512,
    flags: 0,
};

const HELLO_TXT_CONTENT: &str = "Hello World\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: HELLO_TXT_CONTENT.len() as u64,
    blocks: 1,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    blksize: 512,
    flags: 0,
};

struct HelloFS;

impl Filesystem for HelloFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name == "hello.txt" {
            reply.entry(&TTL, &HELLO_TXT_ATTR, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == 2 {
            let content_bytes = HELLO_TXT_CONTENT.as_bytes();
            let content_len = content_bytes.len() as i64;
            if offset < content_len {
                let start = offset as usize;
                let end = std::cmp::min(content_len, offset + size as i64) as usize;
                reply.data(&content_bytes[start..end]);
            } else {
                reply.data(&[]);
            }
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != 1 {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // Number of bytes of buffer space used is returned. If the buffer is full,
            // we stop adding and return.
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
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
    println!("QuantumVault FUSE Filesystem (Hello World)");
    println!("=========================================");

    // Parse arguments (expect mount point)
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <MOUNT_POINT>", args[0]);
        process::exit(1);
    }

    let mountpoint = &args[1];
    println!("Mounting filesystem to: {}", mountpoint);

    let options = vec![
        MountOption::RO,
        MountOption::FSName("hello_fs".to_string()),
        MountOption::AutoUnmount,
    ];

    #[cfg(target_os = "linux")]
    {
        if let Err(err) = fuser::mount2(HelloFS, mountpoint, &options) {
            eprintln!("Error mounting filesystem: {:?}", err);
            process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Warning: FUSE mounts are only supported on Linux targets. Active OS is not Linux.");
        eprintln!("Scaffolding compiled successfully! To test actual mounting, run on WSL2 or native Linux.");
    }
}
