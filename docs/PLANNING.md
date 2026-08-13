# QuantumVault - Implementation & Execution Plan 🛡️🔒

This document captures the project rules, hard constraints, daily tasks, and the exact commit schedule for building **QuantumVault**—a post-quantum encrypted virtual filesystem for Linux.

---

## 1. Role & Context

QuantumVault is a locally-hosted, quantum-resistant encrypted filesystem. It acts as a FUSE-based virtual drive on Linux. 

* **What it is**: Any file dropped into the mounted folder is transparently encrypted with **CRYSTALS-Kyber** (NIST post-quantum key encapsulation standard) and signed with **CRYSTALS-Dilithium** (NIST post-quantum digital signature standard) before touching disk. This defends against **"Harvest Now, Decrypt Later" (HNDL)** attacks.
* **What it is NOT**: It is **not** a website. No browser, no HTML/CSS/JS frontend, no web server, no database. It is a native Linux systems tool composed of:
  * A C-based cryptography engine (`liboqs` wrapper)
  * A Rust-based FUSE filesystem (`vault-fs`)
  * A Rust-based key-management daemon (`keymgmt`)
  * A Rust-based command-line interface (`cli`)

---

## 2. Hard Constraints (Do Not Violate)

1. **Environment**: Linux-only (WSL2 Ubuntu or native Linux). Windows-specific paths or code paths are strictly disallowed.
2. **Languages**:
   * Cryptography core in C (`liboqs`).
   * Filesystem layer and key management in Rust.
   * CLI in Rust.
3. **Commit Cadence**: **One feature = one commit = one day**.
   * Do not combine multiple days' work into a single commit.
   * Do not skip ahead to a later day's task before the current day's is committed.
   * Split tasks further if they are too large for one day—never merge them.
4. **Commit Formatting**: Must follow Conventional Commits exactly (e.g. `feat(vault-fs): ...` or `build(crypto): ...`).
5. **Branching Strategy**: 
   * Solo work → commit directly to `main`.
   * Team work → each member commits to `member-<name>`. The Team Lead merges via Pull Request at the end of each week.
6. **Memory Hardening**: Private keys must never be written to disk in plaintext or paged to swap. This is a core requirement, verified using `mlock` and memory zeroization (`explicit_bzero` equivalent) in Week 4.
7. **Scope and Scope Creep**: Ask before making any architectural decisions not covered in the plan. Do not silently improvise scope.
8. **Build Verification**: Every day's commit must build and pass its own tests before moving to the next day. Broken builds must never be committed.

---

## 3. Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Cryptography** | C, `liboqs` (CRYSTALS-Kyber, CRYSTALS-Dilithium) |
| **Filesystem Bridge** | Rust, FUSE3 (`fuser` crate) |
| **FFI Bridge** | Rust ↔ C via bindgen / manual safe FFI wrappers |
| **Key Management** | Rust daemon, `mlock` + `explicit_bzero`-equivalent memory hardening |
| **CLI** | Rust (`clap` or similar) |
| **Platform** | Linux kernel FUSE subsystem (WSL2 Ubuntu acceptable) |

*Note: Pin the exact `liboqs` release tag used on Day 3 in `README.md`.*

---

## 4. Repository Structure

```
quantumvault/
├── crypto-engine/       # C + liboqs (Kyber, Dilithium)
│   ├── src/
│   └── tests/
├── vault-fs/            # Rust FUSE filesystem
│   ├── src/
│   └── Cargo.toml
├── keymgmt/             # Rust key management daemon
│   └── src/
├── cli/                 # CLI entrypoint
├── docs/                # Audit evidence, review notes
├── scripts/             # Build/test/bootstrap helper scripts
└── README.md
```

---

## 5. Daily Build Plan (Days 1–28)

### Week 1 — Foundations

#### Day 1 — Repo scaffolding
* **Task**: Create the full repo structure. Write a starter `README.md` with project description, architecture summary, and placeholder build instructions.
* **Acceptance**: Repo pushed with correct folder layout and a non-empty `README.md`.
* **Commit**: `chore(repo): initialize project structure and README`

#### Day 2 — Environment bootstrap script
* **Task**: Write `scripts/bootstrap.sh` that installs `build-essential`, `cmake`, `ninja`, `libfuse3-dev`, `pkg-config`, and `rustup` on Ubuntu/WSL2.
* **Acceptance**: Fresh WSL2 Ubuntu instance can run the script and end up with a working C + Rust toolchain.
* **Commit**: `build(repo): add environment bootstrap script for liboqs+rust+fuse3`

#### Day 3 — Vendor liboqs
* **Task**: Clone/vendor `liboqs`, pin a specific release tag, build it via CMake+Ninja, document the exact version in `README.md`.
* **Acceptance**: `liboqs` builds successfully and is installed/linkable.
* **Commit**: `build(crypto): vendor and pin liboqs v<X.Y.Z>`

#### Day 4 — Kyber keypair generation
* **Task**: Write a C program in `crypto-engine/src/` that generates a CRYSTALS-Kyber public/private keypair.
* **Acceptance**: Program runs and prints/stores a valid keypair; no crashes, no memory leaks.
* **Commit**: `feat(crypto): generate CRYSTALS-Kyber keypair`

#### Day 5 — Encrypt/decrypt round trip
* **Task**: Extend the C program to encrypt a short test string with the Kyber-derived key and decrypt it back.
* **Acceptance**: Decrypted output exactly matches original plaintext in an automated test.
* **Commit**: `feat(crypto): add encrypt/decrypt round-trip for test string`

#### Day 6 — Rust FUSE project scaffold
* **Task**: Initialize the `vault-fs` Rust project, add `fuser` as a dependency, set up the basic project skeleton (no mount logic yet).
* **Acceptance**: `cargo build` succeeds with no warnings.
* **Commit**: `feat(vault-fs): scaffold Rust FUSE project skeleton`

#### Day 7 — Basic FUSE mount ("Hello World")
* **Task**: Implement the minimal FUSE trait methods needed to mount a virtual folder and return a static "Hello World" when a file inside it is read.
* **Acceptance**: Mount command mounts the folder; `cat` on the virtual file returns "Hello World"; `umount` cleans up without errors.
* **Commit**: `feat(vault-fs): implement basic FUSE mount with hello world read`

---

### Week 2 — Bridge & Write-Path Encryption

#### Day 8 — Rust↔C FFI bindings
* **Task**: Create safe Rust FFI wrappers around the C encrypt/decrypt/keygen functions from Week 1.
* **Acceptance**: Rust code can call into the C crypto engine and get correct results; all unsafe blocks are minimal and documented.
* **Commit**: `feat(ffi): add Rust FFI bindings for liboqs Kyber functions`

#### Day 9 — FFI unit tests
* **Task**: Write Rust unit tests exercising the FFI bridge (encrypt/decrypt round trip, invalid input handling).
* **Acceptance**: `cargo test` passes for the FFI module.
* **Commit**: `test(ffi): add unit tests for kyber FFI bridge`

#### Day 10 — Hook FUSE write() handler
* **Task**: Implement the FUSE `write()` handler stub that intercepts file-write calls (no encryption logic yet—just routing/buffering).
* **Acceptance**: Writing a file into the mount triggers the handler, verified via debug logging.
* **Commit**: `feat(vault-fs): hook FUSE write() handler`

#### Day 11 — Transparent write-path encryption
* **Task**: Wire the write handler to the FFI crypto module—bytes are encrypted before being persisted to the backing store.
* **Acceptance**: A file written into the mount is stored as ciphertext on the backing disk; verified by inspecting the raw backing file with `hexdump`/`openssl` and confirming it is not readable plaintext.
* **Commit**: `feat(vault-fs): encrypt file content before writing to backing store`

#### Day 12 — Write-path edge cases
* **Task**: Handle partial writes, zero-byte files, and large-buffer edge cases in the write path.
* **Acceptance**: Edge-case test files (empty file, >10MB file) write successfully with no corruption.
* **Commit**: `fix(vault-fs): handle partial writes and buffer edge cases`

#### Day 13 — Crypto audit evidence
* **Task**: Document in `docs/` a reproducible test proving the C engine encrypts with Kyber and that `openssl`/standard tools cannot decrypt the resulting ciphertext.
* **Acceptance**: `docs/crypto-audit.md` contains commands + output demonstrating this.
* **Commit**: `docs(docs): add crypto audit evidence for mid review`

#### Day 14 — Mount validation evidence
* **Task**: Document a reproducible test proving the FUSE app mounts cleanly and the filesystem tree is visible/navigable.
* **Acceptance**: `docs/mount-validation.md` contains commands + output/screenshots.
* **Commit**: `docs(docs): add mount validation evidence for mid review`

---

### Week 3 — Signatures & Read-Path Decryption

#### Day 15 — Dilithium signing
* **Task**: In the C crypto engine, implement file signing using CRYSTALS-Dilithium.
* **Acceptance**: Program signs a test file and produces a valid signature blob.
* **Commit**: `feat(crypto): implement Dilithium file signing`

#### Day 16 — Dilithium verification
* **Task**: Implement signature verification against the signed blob from Day 15.
* **Acceptance**: Valid signatures pass verification; a deliberately tampered file fails verification.
* **Commit**: `feat(crypto): implement Dilithium signature verification`

#### Day 17 — FFI bindings for Dilithium
* **Task**: Extend the Rust FFI layer to expose sign/verify functions.
* **Acceptance**: Rust can call sign/verify and get correct pass/fail results, covered by unit tests.
* **Commit**: `feat(ffi): add Rust FFI bindings for Dilithium sign/verify`

#### Day 18 — Hook FUSE read() handler
* **Task**: Implement the FUSE `read()` handler to decrypt ciphertext from the backing store in memory before returning bytes to the OS.
* **Acceptance**: Reading a file previously written through the mount returns the original plaintext, byte-for-byte.
* **Commit**: `feat(vault-fs): hook FUSE read() handler for in-memory decryption`

#### Day 19 — Tamper detection on read
* **Task**: Integrate Dilithium signature verification into the read path—if a file's ciphertext has been tampered with, the read must fail loudly, not silently return garbage.
* **Acceptance**: A manually corrupted backing file causes the read to be rejected with a clear error.
* **Commit**: `feat(vault-fs): verify Dilithium signature on file read`

#### Day 20 — Fix read-path bugs
* **Task**: Fix any partial-read / offset bugs discovered while testing Day 18–19 (e.g. reading files larger than one FUSE buffer chunk).
* **Acceptance**: Large file (>10MB) reads correctly across multiple buffer chunks.
* **Commit**: `fix(vault-fs): fix partial-read offset bug in decrypt path`

#### Day 21 — End-to-end round-trip tests
* **Task**: Write an automated integration test: mount → write file → unmount → remount → read file → compare bytes.
* **Acceptance**: Test passes reliably across multiple file sizes and types.
* **Commit**: `test(vault-fs): add end-to-end read/write round-trip tests`

---

### Week 4 — Hardening, CLI, and Final Polish

#### Day 22 — Memory locking
* **Task**: In the key management daemon, use `mlock` (or Rust equivalent) to prevent private key pages from being swapped to disk.
* **Acceptance**: A memory/swap audit shows locked key pages are never written to the swap file during normal operation.
* **Commit**: `security(keymgmt): lock private key memory pages with mlock`

#### Day 23 — Explicit memory wipe
* **Task**: Implement `explicit_bzero`-equivalent wiping of key material immediately after use and on daemon shutdown.
* **Acceptance**: A memory dump taken after key use/shutdown shows no recoverable key bytes.
* **Commit**: `security(keymgmt): wipe key material with explicit_bzero on exit`

#### Day 24 — CLI: init
* **Task**: Implement `quantumvault init`—creates a new vault, prompts for a master password.
* **Acceptance**: Running the command creates the expected vault structure with no manual file editing required.
* **Commit**: `feat(cli): add init command`

#### Day 25 — CLI: keygen
* **Task**: Implement `quantumvault keygen`—generates a new post-quantum identity (keypair) for the vault.
* **Acceptance**: Command produces a valid keypair, stored securely per Day 22–23 hardening.
* **Commit**: `feat(cli): add keygen command`

#### Day 26 — CLI: mount / unmount
* **Task**: Implement `quantumvault mount <path>` and `quantumvault unmount <path>` wrapping the FUSE logic from Weeks 1–3.
* **Acceptance**: Full flow works end-to-end from the CLI alone: `init` → `keygen` → `mount` → `use` → `unmount`.
* **Commit**: `feat(cli): add mount and unmount commands`

#### Day 27 — README + demo script
* **Task**: Finalize `README.md` with full build/usage instructions. Add `scripts/demo.sh` that runs the entire `init`→`mount`→`write`→`read`→`unmount` flow automatically.
* **Acceptance**: A new team member can clone the repo and run `scripts/demo.sh` successfully with no manual steps beyond the bootstrap script.
* **Commit**: `docs(repo): finalize README and add end-to-end demo script`

#### Day 28 — Final review evidence
* **Task**: Document in `docs/` the final memory audit (no swapped plaintext keys) and a tamper-test demo (corrupted file rejected on read).
* **Acceptance**: `docs/final-review-evidence.md` contains all required proof for the Definition of Done.
* **Commit**: `docs(docs): add final review evidence — memory audit and tamper test`

---

## 6. Definition of Done (Do Not Report Complete Until All True)

* [ ] A file written into the mounted vault is unreadable by any tool outside the vault (verified via OpenSSL/hexdump).
* [ ] The same file, read back through the mount, is byte-identical to the original.
* [ ] A tampered ciphertext file fails Dilithium signature verification and is rejected, not silently served.
* [ ] A memory audit shows zero unencrypted private-key bytes swapped to disk.
* [ ] CLI can fully `init` → `keygen` → `mount` → `use` → `unmount` a vault with no manual file editing.
* [ ] Every day above has exactly one corresponding commit, in order, with the correct Conventional Commit prefix.
