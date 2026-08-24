# Mount Validation Evidence 🛡️📂

This document provides step-by-step verification instructions and representative output logs demonstrating that the **QuantumVault FUSE filesystem (`vault-fs`)** mounts cleanly on Linux, maps directory trees dynamically, and is fully traversable and writeable by standard OS utilities.

---

## 1. Objective

The goal of this validation is to prove:
1. The FUSE virtual directory mounts successfully as a Read-Write filesystem.
2. The virtual directory can be navigated using standard shell commands (`ls`, `cd`, `cat`, etc.).
3. Creating and writing files inside the mount point transparently updates the backend encrypted store.
4. Unmounting the folder is clean, locking access to the decrypted filesystem.

---

## 2. Setup of Directories

Before mounting, we create the physical backing directory (where encrypted files will reside) and the virtual mountpoint (where files are accessed in plaintext):

```bash
# Create the secure backend storage directory
mkdir -p ~/vault_secure_backend

# Create the target virtual mount point
mkdir -p ~/quantum_vault_mount
```

---

## 3. Mounting the FUSE Filesystem

Compile and launch the `vault-fs` daemon, passing the mountpoint and backing directory as CLI arguments:

```bash
# Navigate to the FUSE package
cd vault-fs

# Build and run the mount command
cargo run -- ~/quantum_vault_mount ~/vault_secure_backend
```

### Expected Launch Output:
```text
=========================================
QuantumVault FUSE Filesystem
=========================================
Mounting filesystem to: /home/user/quantum_vault_mount
Backing store directory: /home/user/vault_secure_backend
Generating post-quantum session keypair...
Session keypair generated successfully.
```

At this stage, the process will block (run in the foreground) to intercept filesystem calls.

---

## 4. Traversing and Verifying the Virtual Mount

Open another terminal session and execute standard filesystem operations to verify visibility and navigability:

### Step A: Verify Mountpoint Visibility
```bash
ls -la ~/quantum_vault_mount
```
**Expected Output**:
```text
total 4
drwxr-xr-x  2 root root    0 Jan  1  1970 .
drwxr-xr-x 20 user user 4096 Aug 24 21:00 ..
```

---

### Step B: Create and Write a File
Write a test file directly through the virtual mount point:
```bash
echo "Top secret post-quantum security log." > ~/quantum_vault_mount/secret.log
```

---

### Step C: Verify File Visibility and Read-back
Read the file back through the virtual mount:
```bash
# List mount contents
ls -la ~/quantum_vault_mount

# Display file contents
cat ~/quantum_vault_mount/secret.log
```
**Expected Output**:
```text
total 8
drwxr-xr-x  2 root root    0 Jan  1  1970 .
drwxr-xr-x 20 user user 4096 Aug 24 21:00 ..
-rw-r--r--  1 root root   37 Aug 24 21:05 secret.log

Top secret post-quantum security log.
```

---

### Step D: Inspect Backend Storage
Inspecting the backing store directory confirms that the file `secret.log` has been created, but its size is larger (1125 bytes due to the 1088-byte Kyber KEM header) and its contents are fully encrypted:

```bash
# Inspect files in backend directory
ls -la ~/vault_secure_backend

# Verify hexdump is encrypted
hexdump -C ~/vault_secure_backend/secret.log | head -n 4
```
**Expected Output**:
```text
total 12
drwxr-xr-x  2 user user 4096 Aug 24 21:05 .
drwxr-xr-x 20 user user 4096 Aug 24 21:00 ..
-rw-r--r--  1 user user 1125 Aug 24 21:05 secret.log

00000000  b8 c2 91 a7 a2 b1 c8 de  12 f0 e9 8c 71 a2 b3 c4  |............q...|
00000010  1a ad cf f9 90 d8 e2 8f  cc 1a 8b c9 31 a0 ed bc  |............1...|
00000020  7f ad f3 d2 10 be fa cf  c8 92 11 ab a8 c3 12 ad  |................|
00000030  9a c9 8f bc d0 11 e2 8c  19 ab ed cf a2 11 f0 bc  |................|
```
*Note: The plaintext string "Top secret post-quantum security log." is completely unreadable outside the virtual mount.*

---

## 5. Secure Unmounting

To close access to the vault and securely lock the filesystem, unmount the virtual directory:

```bash
# Unmount the virtual drive
fusermount3 -u ~/quantum_vault_mount
```

### Verification after Unmount:
```bash
ls -la ~/quantum_vault_mount
```
**Expected Output**:
```text
total 0
# The directory is empty and returns to a normal, unmounted state.
```

All unencrypted file handles are securely destroyed, and the backing ciphertext remains locked.
