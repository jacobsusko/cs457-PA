/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team # 8
     1- Jacob Susko
     2- Sydney Nguyen

Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}


//***********************************************************************
// pLAB-01
//***********************************************************************

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

    // Your code from pLab-01
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

    // Your code from pLab-01
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

//***********************************************************************
// PA-01
//***********************************************************************

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , 
                       ciphertext[ CIPHER_LEN_MAX    ] ,
                       decryptext[ DECRYPTED_LEN_MAX ] ;

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

    // Your code from PA-01
    int bytes_read, cipherText_len, total_cipherText_len = 0;
    unsigned char final_block[PLAINTEXT_LEN_MAX]; 
    int last_block_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encryptFile: failed to create CTX");

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv))
        handleErrors("encryptFile: failed to EncryptInit_ex");


    while ((bytes_read = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)
    {
        if (bytes_read < PLAINTEXT_LEN_MAX)
        {
            memcpy(final_block, plaintext, bytes_read);
            last_block_len = bytes_read;
            break;
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
int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

    // Your code from PA-01
    int bytes_read, decryptedLen, total_decryptedLen = 0;
    unsigned char final_block[PLAINTEXT_LEN_MAX];
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
            memcpy(final_block, ciphertext, bytes_read);
            final_block_len = bytes_read;
            break;
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


//***********************************************************************
// pLAB-02
//***********************************************************************

EVP_PKEY *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    EVP_PKEY *key = EVP_PKEY_new() ;
    if ( public )
        key = PEM_read_PUBKEY( fp, &key , NULL , NULL );
    else
        key = PEM_read_PrivateKey( fp , &key , NULL , NULL );
 
    fclose( fp );

    return key;
}

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    // Guard against incoming NULL pointers
    if (!sig || !sigLen || !privKey || !inData || !inLen)
        { printf("\n privKeySign was passed a NULL pointer\n"); exit(-1); }

    // Create and Initialize a context for RSA private-key signing
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx)
        { printf("\nUnable to create a new context with Private Key\n"); exit(-1); }

    if (EVP_PKEY_sign_init(ctx) <= 0)
        { printf("\nUnable to initialize context for private key\n"); exit(-1); }

    // Determine how big the size of the signature could be
    size_t cipherLen ; 
    if (EVP_PKEY_sign(ctx, NULL, &cipherLen, inData, inLen) <= 0)
        { printf("\nUnable to determine output length of private key signature\n"); exit(-1); }
    // Next allocate memory for the ciphertext
    *sig = malloc(cipherLen);
    if (!sig)
        { printf("\nInsufficient memory to Sign\n"); exit(-1); }

    // Now, actually sign the inData using EVP_PKEY_sign( )
    if (EVP_PKEY_sign(ctx, *sig, &cipherLen, inData, inLen) <= 0)
        { printf("\nSignature of the data failed\n"); exit(-1); }

    *sigLen = cipherLen;
    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA public-key signature verification
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if (!ctx)
        { printf("\nUnable to create a new context of public key\n"); exit(-1); }

    if (EVP_PKEY_verify_init(ctx) <= 0)
        { printf("\nUnable to initialize the context for signature verification\n"); exit(-1); }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen) ;
    //  free any dynamically-allocated objects
    EVP_PKEY_CTX_free( ctx );

    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes ;
    unsigned int  mdLen, bytes_read ;
    unsigned char buffer[ CIPHER_LEN_MAX ];

	// Use EVP_MD_CTX_create() to create new hashing context    
    mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
        { printf("\nFailed to create new hashing context\n"); exit(-1); }

    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the HASH_ALGORITHM() hashing function 
    if (EVP_DigestInit(mdCtx, HASH_ALGORITHM()) <=0 )
        { printf("\nFailed to initalize hash function\n"); exit(-1); }

    mdLen = 0;
    while ((bytes_read = read(fd_in, buffer, CIPHER_LEN_MAX)) > 0)   // Loop until end-of input file
    {
        // Read a chund of input from fd_in. Exit the loop when End-of-File is reached

        if (EVP_DigestUpdate( mdCtx, buffer, bytes_read) != 1)
            { fprintf(stderr, "\nFailed to DigestUpdate\n"); exit(-1); }
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
        if (fd_out > 0)
        { write(fd_out, buffer, bytes_read); }
    }

    if (EVP_DigestFinal( mdCtx, digest, &mdLen) != 1)
        { fprintf(stderr, "\nFailed to DigestFinal\n"); exit(-1); }
    
    EVP_MD_CTX_free( mdCtx);

    return mdLen ;
}

