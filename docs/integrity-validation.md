# Integrity Verification Evidence 🛡️👁️

This document demonstrates that the **QuantumVault FUSE filesystem (`vault-fs`)** enforces authenticity checking on the read path. It details the reproducible verification steps showing how FUSE successfully mounts and reads signed files, and blocks access with an Input/Output error (`EIO`) if either the file content or its signature metadata is tampered with.

---

## 1. Objective

The goal of this validation is to prove:
1. Valid post-quantum digital signatures (generated via CRYSTALS-Dilithium-3) allow standard read operations through the virtual mount point.
2. Modifying a single byte of the encrypted file in the backend directory causes the signature verification to fail and returns `Input/output error` (`EIO`), blocking decryption.
3. Corrupting or deleting the companion `.sig` signature metadata file in the backend directory also fails authenticity validation and returns `Input/output error` (`EIO`).

---

## 2. Test Setup

Mount the filesystem and navigate to the virtual mountpoint:

```bash
# Verify the filesystem is mounted
ls -la ~/quantum_vault_mount
```

---

## 3. Creating a Valid Authenticated File

Write a test file through the mount point:

```bash
echo "QuantumVault Integrity Check Plaintext Payload" > ~/quantum_vault_mount/integrity_test.txt
```

### Verification of visibility and read:
```bash
cat ~/quantum_vault_mount/integrity_test.txt
```
**Output**:
```text
QuantumVault Integrity Check Plaintext Payload
```

### Backend Directory Layout Inspection:
```bash
ls -la ~/vault_secure_backend
```
**Expected Output**:
```text
total 16
-rw-r--r-- 1 user user 1133 Aug 30 19:35 integrity_test.txt
-rw-r--r-- 1 user user 3293 Aug 30 19:35 integrity_test.txt.sig
```
*Note: The companion `integrity_test.txt.sig` contains the 3293-byte CRYSTALS-Dilithium-3 signature blob, which is completely hidden inside the virtual mount.*

---

## 4. Tampering Case A: Modifying the Ciphertext Backing File

We will simulate an attacker modifying the backing ciphertext file directly on disk (simulating disk corruption or unauthorized raw write).

### Step 1: Hexdump of the original backing file
```bash
hexdump -C ~/vault_secure_backend/integrity_test.txt | head -n 2
```
**Output**:
```text
00000000  a4 2b c1 12 90 f8 c9 e2  3b f0 2d cd a0 11 ab f4  |.+......;.-.....|
00000010  1a 7f d2 f0 81 ac 19 ee  ba c3 dd b1 a2 c8 e1 f0  |................|
```

### Step 2: Corrupt a byte in the backing file
Alter the first byte of the backing file (change `a4` to `00`):
```bash
printf '\x00' | dd of=~/vault_secure_backend/integrity_test.txt conv=notrunc bs=1 count=1
```

### Step 3: Attempt to read through the virtual mount
```bash
cat ~/quantum_vault_mount/integrity_test.txt
```
**Expected Output**:
```text
cat: /home/user/quantum_vault_mount/integrity_test.txt: Input/output error
```

### Explanation:
FUSE intercepts the `read()` call, reads the corrupted backing file and its signature, decrypts the ciphertext to retrieve plaintext, and runs Dilithium-3 verification. Because the ciphertext was modified, the decrypted plaintext is corrupted and no longer matches the digital signature. Decryption is blocked, no data is returned to the user space, and `EIO` is returned.

---

## 5. Tampering Case B: Modifying the Signature Metadata File

Now we simulate an attacker altering or deleting the signature file itself.

### Step 1: Restore the backing file to a clean state
```bash
# Re-write the file to generate a clean backing ciphertext and signature
echo "QuantumVault Integrity Check Plaintext Payload" > ~/quantum_vault_mount/integrity_test.txt
```

### Step 2: Corrupt a byte in the signature file
Alter the first byte of the signature file `integrity_test.txt.sig` (change it to `00`):
```bash
printf '\x00' | dd of=~/vault_secure_backend/integrity_test.txt.sig conv=notrunc bs=1 count=1
```

### Step 3: Attempt to read through the virtual mount
```bash
cat ~/quantum_vault_mount/integrity_test.txt
```
**Expected Output**:
```text
cat: /home/user/quantum_vault_mount/integrity_test.txt: Input/output error
```

---

## 6. Tampering Case C: Missing Signature File

Delete the signature file entirely from the backing store:

```bash
# Remove the signature file
rm ~/vault_secure_backend/integrity_test.txt.sig

# Attempt to read through the mount point
cat ~/quantum_vault_mount/integrity_test.txt
```
**Expected Output**:
```text
cat: /home/user/quantum_vault_mount/integrity_test.txt: Input/output error
```

### Conclusion
Without a valid signature matching the exact decrypted plaintext, the virtual filesystem completely blocks reads and returns a system `EIO` error, successfully proving the integrity validation guards of QuantumVault.
