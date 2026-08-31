/*
 * ============================================================================
 *  decryptor.c
 *
 *  RC4 File Decryptor
 *  INSA CTC Summer Camp - Malware Development Practical Assignment
 *
 *  Description:
 *      Reads the encrypted contents of "file.txt" in binary mode, decrypts
 *      the data in memory using the RC4 stream cipher with the SAME key
 *      used by encryptor.c, and writes the restored plaintext back to
 *      "file.txt".
 *
 *  Educational Note:
 *      RC4 encrypts by XOR-ing the plaintext with a generated keystream.
 *      XOR is its own inverse, so applying the identical keystream to the
 *      ciphertext reproduces the original plaintext exactly. This is why
 *      the encryption and decryption routines below are identical - only
 *      the direction of the operation (which file state you feed in)
 *      differs.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TARGET_FILE   "file.txt"
#define RC4_KEY       "INSA_CTC_RC4_2026"   /* Must match encryptor.c exactly */
#define SBOX_SIZE     256

/*
 * rc4_init
 * --------
 * RC4 Key Scheduling Algorithm (KSA). Identical to the encryptor's version -
 * the S-box depends only on the key, not on whether we are encrypting or
 * decrypting.
 */
void rc4_init(unsigned char s[SBOX_SIZE], const unsigned char *key, size_t key_len)
{
    int i, j = 0;
    unsigned char temp;

    for (i = 0; i < SBOX_SIZE; i++) {
        s[i] = (unsigned char)i;
    }

    for (i = 0; i < SBOX_SIZE; i++) {
        j = (j + s[i] + key[i % key_len]) % SBOX_SIZE;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

/*
 * rc4_crypt
 * ---------
 * RC4 Pseudo-Random Generation Algorithm (PRGA). Generates the same
 * keystream as the encryptor (given the same key) and XORs it with the
 * input buffer, which reverses the encryption.
 */
void rc4_crypt(unsigned char *data, size_t data_len, unsigned char s[SBOX_SIZE])
{
    int i = 0, j = 0, k;
    unsigned char temp;

    for (size_t n = 0; n < data_len; n++) {
        i = (i + 1) % SBOX_SIZE;
        j = (j + s[i]) % SBOX_SIZE;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        k = s[(s[i] + s[j]) % SBOX_SIZE];
        data[n] ^= (unsigned char)k;
    }
}

int main(void)
{
    FILE *fp;
    unsigned char *buffer = NULL;
    long file_size;
    unsigned char sbox[SBOX_SIZE];
    const unsigned char *key = (const unsigned char *)RC4_KEY;
    size_t key_len = strlen(RC4_KEY);

    printf("=== RC4 File Decryptor ===\n");

    /* --- Step 1: Open the encrypted file in binary read mode --- */
    fp = fopen(TARGET_FILE, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error: could not open '%s' for reading.\n", TARGET_FILE);
        return EXIT_FAILURE;
    }

    /* --- Step 2: Determine file size --- */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: fseek failed while measuring file size.\n");
        fclose(fp);
        return EXIT_FAILURE;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        fprintf(stderr, "Error: ftell failed while measuring file size.\n");
        fclose(fp);
        return EXIT_FAILURE;
    }
    rewind(fp);

    if (file_size == 0) {
        printf("Notice: '%s' is empty. Nothing to decrypt.\n", TARGET_FILE);
        fclose(fp);
        return EXIT_SUCCESS;
    }

    /* --- Step 3: Allocate a buffer for the encrypted data --- */
    buffer = (unsigned char *)malloc((size_t)file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error: memory allocation failed (%ld bytes).\n", file_size);
        fclose(fp);
        return EXIT_FAILURE;
    }

    /* --- Step 4: Read the entire encrypted file into memory --- */
    size_t bytes_read = fread(buffer, 1, (size_t)file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Error: expected to read %ld bytes but got %zu.\n",
                file_size, bytes_read);
        free(buffer);
        return EXIT_FAILURE;
    }

    /* --- Step 5: Decrypt the buffer in place using RC4 --- */
    rc4_init(sbox, key, key_len);
    rc4_crypt(buffer, bytes_read, sbox);

    /* --- Step 6: Write the restored plaintext back to the file --- */
    fp = fopen(TARGET_FILE, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Error: could not open '%s' for writing.\n", TARGET_FILE);
        free(buffer);
        return EXIT_FAILURE;
    }

    size_t bytes_written = fwrite(buffer, 1, bytes_read, fp);
    fclose(fp);

    if (bytes_written != bytes_read) {
        fprintf(stderr, "Error: expected to write %zu bytes but wrote %zu.\n",
                bytes_read, bytes_written);
        free(buffer);
        return EXIT_FAILURE;
    }

    /* --- Step 7: Clean up --- */
    free(buffer);

    printf("Success: %zu byte(s) decrypted and written to '%s'.\n",
           bytes_written, TARGET_FILE);
    printf("The original file contents should now be restored.\n");

    return EXIT_SUCCESS;
}
