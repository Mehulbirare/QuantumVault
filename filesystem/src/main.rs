use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::ENOENT;
use std::{
    ffi::OsStr,
    time::{Duration, SystemTime},
};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;

struct QuantumVaultFS;

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
            ROOT_INO => reply.attr(&TTL, &root_attr()),
            HELLO_INO => reply.attr(&TTL, &hello_attr()),
            _ => reply.error(ENOENT),
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

        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }

        reply.ok();
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

        let data = b"Hello World from QuantumVault!\n";
        let start = offset.max(0) as usize;

        if start >= data.len() {
            reply.data(&[]);
            return;
        }

        let end = std::cmp::min(start + size as usize, data.len());
        reply.data(&data[start..end]);
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
        size: b"Hello World from QuantumVault!\n".len() as u64,
        blocks: 1,
        blksize: 512,
        atime: SystemTime::now(),
        mtime: SystemTime::now(),
        ctime: SystemTime::now(),
        crtime: SystemTime::now(),
        kind: FileType::RegularFile,
        perm: 0o444,
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
        .expect("Usage: quantumvault-fuse-week1 <mountpoint>");

    println!("QuantumVault Week 1 FUSE filesystem");
    println!("Mounting at: {}", mountpoint);

    fuser::mount2(
        QuantumVaultFS,
        mountpoint,
        &[
            fuser::MountOption::FSName("quantumvault-week1".to_string()),
            fuser::MountOption::AutoUnmount,
        ],
    )
    .expect("Failed to mount FUSE filesystem");
}
