# QuantumVault - Week 1: Foundations (Summary Report) 🛡️

This document provides a detailed summary of the architecture, implementation details, and verification steps completed during **Week 1** (Days 1 to 7) of the QuantumVault project.

---

## 1. Overview of Week 1 Deliverables

The first week of development focused on building the post-quantum cryptographic foundations in C and scaffolding the virtual filesystem interface in Rust. 

All 7 milestones defined in the project plan have been implemented:
1. **Day 1**: Scaffolding the repository structure & starter documentation.
2. **Day 2**: Environment bootstrap script for WSL2/Linux dependencies.
3. **Day 3**: Submodule integration of `liboqs` (pinned at release `0.10.0`).
4. **Day 4**: CRYSTALS-Kyber keypair generation C implementation.
5. **Day 5**: CRYSTALS-Kyber encapsulation/decapsulation encryption round-trip.
6. **Day 6**: Rust FUSE filesystem project scaffold (`Cargo.toml`).
7. **Day 7**: Basic FUSE mount implementation returning mock "Hello World" data.

---

## 2. Directory Structure & Files Created

The workspace now contains the core directories and files required for the project:

```
quantumvault/
├── cli/
│   └── .gitkeep
├── crypto-engine/               # C Crypto Engine wrapper & liboqs submodule
│   ├── liboqs/                  # [Submodule] Pinned at v0.10.0
│   ├── src/
│   │   ├── kyber_keypair.c      # Key generation program
│   │   └── kyber_roundtrip.c    # Encryption round-trip test program
│   ├── tests/
│   │   └── .gitkeep
│   └── CMakeLists.txt           # Build instructions linking liboqs
├── docs/
│   ├── .gitkeep
│   └── WEEK_1_SUMMARY.md        # [This File] Summary report for Week 1
├── keymgmt/
│   └── src/
│       └── .gitkeep
├── scripts/
│   ├── .gitkeep
│   └── bootstrap.sh             # Dependency installer for Ubuntu/WSL2
├── vault-fs/                    # Rust virtual filesystem package
│   ├── src/
│   │   └── main.rs              # FUSE mount & mock HelloFS implementation
│   └── Cargo.toml               # Cargo config and dependency definitions
├── PLANNING.md                  # Comprehensive 28-day timeline
└── README.md                    # Main project documentation & guides
```

---

## 3. Detailed Component Implementations

### A. Environment Bootstrap (`scripts/bootstrap.sh`)
* **Purpose**: Installs system requirements for compilers, FUSE, and Rust tooling.
* **Libraries Installed**: `build-essential`, `cmake`, `ninja-build`, `libfuse3-dev`, `pkg-config`, `git`, `curl`, and `rustup`.
* **Details**: Formatted with Unix line endings (`LF`) to run natively on Ubuntu/WSL2 systems. Detects existing installations of Rust to prevent duplicate downloads.

### B. C Crypto Engine (`crypto-engine/`)
* **Submodule Integration**: Pinned to the official release of `liboqs` tag `0.10.0` (Commit: `36be57445`). Built statically using CMake without OpenSSL dependencies for maximum portability.
* **Key Generator (`src/kyber_keypair.c`)**:
  * Initializes the `liboqs` framework (`OQS_init`).
  * Creates an instance of `OQS_KEM_alg_kyber_768`.
  * Invokes `OQS_KEM_keypair` to generate public and secret keys in memory.
  * Outputs the first 16 bytes of both keys in hexadecimal format.
  * Safely cleans up all KEM states and memory allocations on exit.
* **Round-Trip Encrypter (`src/kyber_roundtrip.c`)**:
  * Extends the keypair code to simulate a complete cryptographic transaction.
  * **Sender**: Uses the recipient's public key to run `OQS_KEM_encaps`, generating a shared secret and KEM ciphertext. It encrypts a test string ("*QuantumVault-PostQuantumCryptographicFilesystem-2026*") using the shared secret as key material via a standard XOR stream cipher.
  * **Receiver**: Uses the KEM ciphertext and the recipient's private key to run `OQS_KEM_decaps`, recovering the identical shared secret.
  * **Verification**: Decrypts the cipher text using the recovered secret and runs an automated check confirming the result matches the original input byte-for-byte.

### C. Virtual Filesystem (`vault-fs/`)
* **Cargo Configuration (`Cargo.toml`)**: Added crates `fuser` (Rust FUSE bindings), `libc` (error code maps), `log` and `env_logger` (debugging tools).
* **FUSE Trait Implementation (`src/main.rs`)**:
  * Implements `fuser::Filesystem` for structural mounting.
  * `lookup`: Finds files in root, matching `hello.txt`.
  * `getattr`: Defines metadata, permissions (`0o755` for directory, `0o644` for file), and size attributes.
  * `readdir`: Presents virtual layout containing `.`, `..`, and `hello.txt`.
  * `read`: Yields mock content `"Hello World\n"` when `hello.txt` is opened.
  * **Compatibility Guard**: Uses conditional compilation (`#[cfg(target_os = "linux")]`) for the mount launcher (`fuser::mount2`) so the workspace compiles cleanly on Windows development PCs while preserving Linux mounts.

---

## 4. Compile & Build Verification Commands

Once in a WSL2 or native Linux terminal, the following commands verify the Week 1 work:

### 1. Run Bootstrap Setup
```bash
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

### 2. Build and Run C Crypto Engine
```bash
cd crypto-engine
mkdir -p build && cd build
cmake -GNinja ..
ninja

# Run key generation
./kyber_keypair

# Run round-trip encryption test
./kyber_roundtrip
```

### 3. Build and Run Rust Filesystem
```bash
cd vault-fs
cargo build

# Create mock mountpoint and mount the filesystem
mkdir -p /tmp/quantum_mount
cargo run -- /tmp/quantum_mount

# In another terminal, read from the mountpoint:
cat /tmp/quantum_mount/hello.txt
# Output: Hello World

# To unmount:
fusermount3 -u /tmp/quantum_mount
```

---

## 5. Week 1 Commit Checklist (for Reference)

Verify that your Git log shows the following Day 1 to Day 7 commits in order:

* [x] **Day 1**: `chore(repo): initialize project structure and README`
* [x] **Day 2**: `build(repo): add environment bootstrap script for liboqs+rust+fuse3`
* [x] **Day 3**: `build(crypto): vendor and pin liboqs v0.10.0`
* [x] **Day 4**: `feat(crypto): generate CRYSTALS-Kyber keypair`
* [x] **Day 5**: `feat(crypto): add encrypt/decrypt round-trip for test string`
* [x] **Day 6**: `feat(vault-fs): scaffold Rust FUSE project skeleton`
* [x] **Day 7**: `feat(vault-fs): implement basic FUSE mount with hello world read`
