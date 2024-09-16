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

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int bytes_read, cipherText_len, total_cipherText_len;

    while ((bytes_read = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)
    {
        cipherText_len = encrypt(plaintext, PLAINTEXT_LEN_MAX, key, iv, ciphertext);

        if (write(fd_out, ciphertext, cipherText_len) != cipherText_len)
        {
            perrorf("This is Amal. Failed to write cipherText to %s", fd_out);
            return -1;
        }
        total_cipherText_len += cipherText_len;
    }

    if (bytes_read < 0)
        { perrorf("THis is Amal. Failed to read from %s", fd_in); return -1; }

    return total_cipherText_len;
}

//-----------------------------------------------------------------------------


int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int bytes_read, decryptedText_len, total_decryptedText_len;

    while ((bytes_read = read(fd_in, ciphertext, CIPHER_LEN_MAX)) > 0)
    {
        decryptedText_len = decrypt(ciphertext, CIPHER_LEN_MAX, key, iv, decryptext);

        if (write(fd_out, decryptext, decryptedText_len) != decryptedText_len) 
        {
            perrorf("This is Basim. Failed to write decryptedText to %s", fd_out);
            return -1;
        }
        total_decryptedText_len += decryptedText_len;
    }

    if (bytes_read < 0)
        { perrorf("This is Basim. Failed to read from %s", fd_in); return -1; }

    return total_decryptedText_len;
}
