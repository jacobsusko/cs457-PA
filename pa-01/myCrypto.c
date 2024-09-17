/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- 
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}


//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
//
//       ALL PREVIOUS CODE FROM pLab-01
//           MUST  EXIST  HERE
//
    int status;
    unsigned len = 0, encryptedLen = 0;

    /* Create and initialize the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encrypt: failed to create CTX");

    // Initialize the encryption operation
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");

    // Call EncryptUpdate as many times as needed
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len,pPlainText, plainText_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len;

    // Finalize the encryption
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;  // len could be 0 if no additional cipher text was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;

}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
//
//       ALL PREVIOUS CODE FROM pLab-01
//           MUST  EXIST  HERE
//
    int status;
    unsigned len = 0, decryptedLen = 0;

    /* Create and initialize the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decrypt: failed to create CTX");

    // Initialize the decryption operation
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");

    // Call DecryptUpdate as many times as needed
    // to perform regular decryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // If additional decrypted text may still be generated, 
    // the pDecryptedText pointed must be first advanced
    pDecryptedText += len;

    // Finalize the decryption
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;

}


//-----------------------------------------------------------------------------


static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

int encryptFile(int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
    int bytes_read, cipherText_len, total_cipherText_len = 0;
    unsigned char final_block[PLAINTEXT_LEN_MAX];  // Buffer for final block encryption
    int last_block_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encryptFile: failed to create CTX");

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv))
        handleErrors("encryptFile: failed to EncryptInit_ex");

    // Read and encrypt all but the last chunk
    while ((bytes_read = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)
    {
        // Buffer the last block
        if (bytes_read < PLAINTEXT_LEN_MAX)
        {
            memcpy(final_block, plaintext, bytes_read);
            last_block_len = bytes_read;
            break;  // This is the last block, break the loop
        }

        cipherText_len = 0;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &cipherText_len, plaintext, bytes_read))
            handleErrors("encryptFile: failed to EncryptUpdate");

        if (write(fd_out, ciphertext, cipherText_len) != cipherText_len)
        {
            printf("This is Amal. Failed to write cipherText to %d", fd_out);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        total_cipherText_len += cipherText_len;
    }

    // Handle any errors reading from input file
    if (bytes_read < 0)
    {
        printf("This is Amal. Failed to read from %d", fd_in);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt the final block and apply padding
    if (last_block_len > 0)
    {
        cipherText_len = 0;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &cipherText_len, final_block, last_block_len))
            handleErrors("encryptFile: failed to EncryptUpdate (final block)");

        total_cipherText_len += cipherText_len;
        if (write(fd_out, ciphertext, cipherText_len) != cipherText_len)
        {
            printf("This is Amal. Failed to write final cipherText to %d", fd_out);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Finalize encryption (handles padding for the last block)
    cipherText_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext, &cipherText_len))
        handleErrors("encryptFile: failed to EncryptFinal_ex");

    total_cipherText_len += cipherText_len;
    if (write(fd_out, ciphertext, cipherText_len) != cipherText_len)
    {
        printf("This is Amal. Failed to write final padded cipherText to %d", fd_out);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return total_cipherText_len;
}


//-----------------------------------------------------------------------------


int decryptFile(int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
    int bytes_read, decryptedLen, total_decryptedLen = 0;
    unsigned char final_block[PLAINTEXT_LEN_MAX]; // Buffer for the final block
    int final_block_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decryptFile: failed to create CTX");

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv))
        handleErrors("decryptFile: failed to DecryptInit_ex");

    // Read and decrypt all but the last chunk
    while ((bytes_read = read(fd_in, ciphertext, PLAINTEXT_LEN_MAX)) > 0)
    {
        if (bytes_read < PLAINTEXT_LEN_MAX)
        {
            // If the read is less than buffer size, it's the final block
            memcpy(final_block, ciphertext, bytes_read);
            final_block_len = bytes_read;
            break;  // Exit loop as this is the last block
        }

        decryptedLen = 0;
        if (1 != EVP_DecryptUpdate(ctx, decryptext, &decryptedLen, ciphertext, bytes_read))
            handleErrors("decryptFile: failed to DecryptUpdate");

        if (write(fd_out, decryptext, decryptedLen) != decryptedLen)
        {
            printf("This is Amal. Failed to write decrypted text to %d", fd_out);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        total_decryptedLen += decryptedLen;
    }

    // Handle any errors reading from the input file
    if (bytes_read < 0)
    {
        printf("This is Amal. Failed to read from %d", fd_in);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrypt the final block and remove padding
    if (final_block_len > 0)
    {
        decryptedLen = 0;
        if (1 != EVP_DecryptUpdate(ctx, decryptext, &decryptedLen, final_block, final_block_len))
            handleErrors("decryptFile: failed to DecryptUpdate (final block)");

        total_decryptedLen += decryptedLen;
        if (write(fd_out, decryptext, decryptedLen) != decryptedLen)
        {
            printf("This is Amal. Failed to write final decrypted text to %d", fd_out);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Finalize decryption (handles padding removal for the last block)
    decryptedLen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, decryptext, &decryptedLen))
        handleErrors("decryptFile: failed to DecryptFinal_ex");

    if (decryptedLen > 0)
    {
        total_decryptedLen += decryptedLen;
        if (write(fd_out, decryptext, decryptedLen) != decryptedLen)
        {
            printf("This is Amal. Failed to write final decrypted text to %d", fd_out);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return total_decryptedLen;
}

