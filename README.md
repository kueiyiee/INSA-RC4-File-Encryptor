# RC4 File Encryptor & Decryptor

## Overview

This project is an educational implementation of the **RC4 stream cipher**, developed in C as a practical assignment for the **INSA CTC Summer Camp — Malware Development** course. It demonstrates how a simple symmetric stream cipher can be used to encrypt and decrypt the contents of a file, and it illustrates core low-level concepts such as binary file I/O, dynamic memory management, and byte-level data processing.

The program operates exclusively on a single, designated test file (`file.txt`) and performs no actions beyond the scope of the assignment.

## Objectives

This project demonstrates:

- **RC4** — a simple, historically significant stream cipher
- **Symmetric cryptography** — encryption and decryption performed with the same secret key
- **File encryption / decryption** — transforming file contents into unreadable ciphertext and back
- **Binary file processing** — reading and writing raw bytes, including null and non-printable bytes
- **Memory-buffer processing** — loading a file fully into memory, transforming it, then writing it back out

## Architecture

| File           | Role                                                                 |
|----------------|-----------------------------------------------------------------------|
| `encryptor.c`  | Reads `file.txt`, encrypts its contents with RC4, and overwrites it with the ciphertext. |
| `decryptor.c`  | Reads the encrypted `file.txt`, decrypts it with the same RC4 key, and restores the original contents. |
| `file.txt`     | The controlled test file used as input/output for the demonstration.  |

Both programs share the same RC4 logic (`rc4_init` for key scheduling, `rc4_crypt` for keystream generation and XOR), implemented independently in each source file so that each is self-contained and can be compiled on its own.

## The RC4 Process

RC4 is a **stream cipher**: instead of encrypting data in fixed-size blocks, it generates a pseudo-random stream of bytes (the *keystream*) and combines it with the plaintext using XOR.

### 1. Key Scheduling Algorithm (KSA)

The KSA takes the secret key and uses it to scramble a 256-byte array (the "S-box") from its initial identity state (`0, 1, 2, ..., 255`) into a key-dependent permutation. This scrambled S-box is the internal state the cipher will draw its keystream from.

### 2. Pseudo-Random Generation Algorithm (PRGA)

The PRGA repeatedly shuffles the S-box and extracts one keystream byte at a time. Each keystream byte is XORed with one byte of input data, producing one byte of output.

### 3. Why the Same Code Encrypts *and* Decrypts

XOR is its own inverse: `plaintext XOR keystream = ciphertext`, and `ciphertext XOR keystream = plaintext`, provided the *same* keystream is generated both times. Because the keystream depends only on the key (not on whether you are "encrypting" or "decrypting"), running the identical algorithm with the identical key on the ciphertext reproduces the original plaintext exactly.

## Workflow

```text
Plaintext (file.txt)
        │
        ▼
   RC4 + Key  ──── encryptor.c
        │
        ▼
Ciphertext (file.txt, now binary/unreadable)
        │
        ▼
   RC4 + Same Key  ──── decryptor.c
        │
        ▼
Plaintext restored (file.txt, identical to original)
```

## Requirements

- A C compiler (GCC recommended)
- Linux, macOS, or Windows (with GCC via MinGW or WSL)

## Compilation

**Linux / macOS:**

```bash
gcc encryptor.c -o encryptor
gcc decryptor.c -o decryptor
```

**Windows (MinGW):**

```cmd
gcc encryptor.c -o encryptor.exe
gcc decryptor.c -o decryptor.exe
```

## Usage

1. Make sure `file.txt` contains the readable test content you want to encrypt.
2. Compile and run the encryptor:
   ```bash
   ./encryptor
   ```
   `file.txt` is now overwritten with encrypted binary data.
3. (Optional) Inspect the file to confirm it is no longer readable, e.g. `file file.txt` or opening it in a hex viewer.
4. Compile and run the decryptor:
   ```bash
   ./decryptor
   ```
   `file.txt` is restored to its original, readable contents.

## Verification

To confirm that decryption restores the file exactly, compare cryptographic hashes before encryption and after decryption:

```bash
sha256sum file.txt        # record this hash before encryption
./encryptor
sha256sum file.txt        # hash will differ — file is now ciphertext
./decryptor
sha256sum file.txt        # hash should match the very first value
```

This project was tested with this exact procedure, including edge cases (empty file, single-byte file, and 5,000 bytes of random binary data containing null and non-printable bytes). In every case the SHA-256 hash after decryption matched the hash of the original file exactly. See the final submission report for details.

## Security Note

**RC4 is a cryptographically obsolete algorithm.** It has known statistical biases in its keystream and has been deprecated or banned in modern protocols (e.g., TLS). It is used here **only** for educational purposes, to illustrate stream cipher mechanics at a low level.

Do **not** use RC4, or the fixed demonstration key in this repository, to protect real or sensitive data. Modern applications should use authenticated, well-vetted algorithms such as:

- **AES-GCM**
- **ChaCha20-Poly1305**

## Educational Disclaimer

This project was created strictly for controlled educational and laboratory use as part of a cybersecurity training curriculum. It is intentionally scoped to operate only on the single test file `file.txt` and contains no persistence, network communication, self-propagation, privilege escalation, or any other capability beyond the assigned demonstration.
