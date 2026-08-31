/*
 * ============================================================================
 *  encryptor.c
 *
 *  RC4 File Encryptor
 *  INSA CTC Summer Camp - Malware Development Practical Assignment
 *
 *  Description:
 *      Reads the contents of "file.txt" in binary mode, encrypts the data
 *      in memory using the RC4 stream cipher, and writes the resulting
 *      ciphertext back to "file.txt".
 *
 *  Educational Note:
 *      RC4 is used here strictly for academic demonstration of stream
 *      cipher mechanics (Key Scheduling Algorithm and Pseudo-Random
 *      Generation Algorithm). RC4 is cryptographically broken and must
 *      never be used to protect real, sensitive data. See README.md for
 *      details and modern alternatives.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TARGET_FILE   "file.txt"
#define RC4_KEY       "INSA_CTC_RC4_2026"   /* Shared educational demo key */
#define SBOX_SIZE     256

/*
 * rc4_init
 * --------
 * RC4 Key Scheduling Algorithm (KSA).
 *
 * Initializes the 256-byte substitution box "s" with a permutation of
 * 0..255 that depends on the supplied key. This scrambled S-box is what
 * makes the later keystream unpredictable to anyone without the key.
 */
void rc4_init(unsigned char s[SBOX_SIZE], const unsigned char *key, size_t key_len)
{
    int i, j = 0;
    unsigned char temp;

    /* Start with the identity permutation */
    for (i = 0; i < SBOX_SIZE; i++) {
        s[i] = (unsigned char)i;
    }

    /* Scramble the S-box using the key (standard KSA loop) */
    for (i = 0; i < SBOX_SIZE; i++) {
        j = (j + s[i] + key[i % key_len]) % SBOX_SIZE;

        /* Swap s[i] and s[j] */
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

/*
 * rc4_crypt
 * ---------
 * RC4 Pseudo-Random Generation Algorithm (PRGA) applied directly to data.
 *
 * Because RC4 encrypts by XOR-ing plaintext with a generated keystream,
 * calling this exact same function with the exact same key on ciphertext
 * reproduces the original plaintext. This single function therefore
 * serves as both the encryption and decryption routine.
 *
 * data      : buffer to encrypt/decrypt (processed in place)
 * data_len  : number of bytes in the buffer
 * s         : S-box previously initialized by rc4_init()
 */
void rc4_crypt(unsigned char *data, size_t data_len, unsigned char s[SBOX_SIZE])
{
    int i = 0, j = 0, k;
    unsigned char temp;

    for (size_t n = 0; n < data_len; n++) {
        i = (i + 1) % SBOX_SIZE;
        j = (j + s[i]) % SBOX_SIZE;

        /* Swap s[i] and s[j] */
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        /* Generate the next keystream byte and XOR it with the data byte */
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

    printf("=== RC4 File Encryptor ===\n");

    /* --- Step 1: Open the target file in binary read mode --- */
    fp = fopen(TARGET_FILE, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error: could not open '%s' for reading.\n", TARGET_FILE);
        return EXIT_FAILURE;
    }

    /* --- Step 2: Determine file size (do NOT use strlen on binary data) --- */
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

    /* Handle the empty-file edge case explicitly */
    if (file_size == 0) {
        printf("Notice: '%s' is empty. Nothing to encrypt.\n", TARGET_FILE);
        fclose(fp);
        return EXIT_SUCCESS;
    }

    /* --- Step 3: Allocate a buffer large enough to hold the whole file --- */
    buffer = (unsigned char *)malloc((size_t)file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error: memory allocation failed (%ld bytes).\n", file_size);
        fclose(fp);
        return EXIT_FAILURE;
    }

    /* --- Step 4: Read the entire file into memory --- */
    size_t bytes_read = fread(buffer, 1, (size_t)file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Error: expected to read %ld bytes but got %zu.\n",
                file_size, bytes_read);
        free(buffer);
        return EXIT_FAILURE;
    }

    /* --- Step 5: Encrypt the buffer in place using RC4 --- */
    rc4_init(sbox, key, key_len);
    rc4_crypt(buffer, bytes_read, sbox);

    /* --- Step 6: Write the encrypted bytes back to the same file --- */
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

    printf("Success: %zu byte(s) encrypted and written to '%s'.\n",
           bytes_written, TARGET_FILE);
    printf("Run decryptor with the same key to restore the original file.\n");

    return EXIT_SUCCESS;
}
