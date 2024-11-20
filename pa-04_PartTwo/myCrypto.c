/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- Jacob Susko
	 2- Sydney Nyugen
Submitted on: 
     11/21/2024 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs
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

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

size_t MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{
    //  Check agains any NULL pointers in the arguments
    if ( !log || !msg1 || !IDa || !IDb )
    {
        printf( "\n******* MSG1_new received some NULL pointers\n" ); 
        return 0 ; 
    }

    size_t  LenA    = strlen(IDa) + 1 ; //  number of bytes in IDa ; Including Null terminator with + 1
    size_t  LenB    = strlen(IDb) + 1 ; //  number of bytes in IDb ; Including Null terminator with + 1
    size_t  LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + sizeof(Nonce_t) ; //  number of bytes in the completed MSG1 ;;
    size_t *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = (uint8_t *)malloc(LenMsg1);
    if ( !*msg1 )
        { printf("failed to malloc in msg1_new"); exit(-1); }

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    
	// use the pointer p to traverse through msg1 and fill the successive parts of the msg
    memcpy(p, &LenA, LENSIZE);
    p += LENSIZE;

    memcpy(p, IDa, LenA);
    p += LenA;

    memcpy(p, &LenB, LENSIZE);
    p += LENSIZE;

    memcpy(p, IDb, LenB);
    p += LenB;

    memcpy(p, Na, NONCELEN);

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp( log, *msg1, LenMsg1, 4);
    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if ( !log || !IDa || ! IDb )
    {
        printf( "\n******* MSG1_reveive received some NULL pointers\n" ); 
        return;
    }

    size_t LenMsg1 = 0, LenA , LenB, bytesRead ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na

    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa):
    bytesRead = read(fd, &LenA, LENSIZE);
    LenMsg1 += bytesRead;
    if (bytesRead != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }

    
    // 2) Allocate memory for ID_A ... But on failure to allocate memory:
    *IDa = (char *)malloc(LenA);
    if ( !IDa )
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    bytesRead = read(fd, *IDa, LenA);
    LenMsg1 += bytesRead;
    if (bytesRead != LenA)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    bytesRead = read(fd, &LenB, LENSIZE);
    LenMsg1 += bytesRead;
    if (bytesRead != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    *IDb = (char *)malloc(LenB);
    if ( !IDb )
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , LenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    bytesRead = read(fd, *IDb, LenB);
    LenMsg1 += bytesRead;
    if (bytesRead != LenB)
    {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , LenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    
    // 5) Read Na   But on failure to read Na from the pipe
    bytesRead = read(fd, Na, sizeof(Nonce_t));
    LenMsg1 += bytesRead;
    if (bytesRead != sizeof(Nonce_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}

//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
/*  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

*/

// Also, use this new one for your convenience
static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are size_t integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

size_t MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{
    if ( !log || !msg2 || !IDa || !IDb )
    {
        printf("MSG2_new received NULL Pointers\n");
        return 0;
    }

    size_t offset = 0; // for moving memcpy
    
    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]
    size_t lenIDa = strlen(IDa) + 1;

    memcpy(plaintext + offset, Ks, sizeof(myKey_t));
    offset += sizeof(myKey_t);

    memcpy(plaintext + offset, &lenIDa, LENSIZE);
    offset += LENSIZE;

    memcpy(plaintext + offset, IDa, lenIDa);
    offset += lenIDa;
    size_t TktPlainLen = offset;

    // Compute its encrypted version in the global scratch buffer ciphertext[]
    fprintf( log , "Plaintext Ticket (%lu Bytes) is\n" ,  TktPlainLen  ) ;
    BIO_dump_indent_fp( log , plaintext ,  TktPlainLen  , 4 ) ;    fprintf( log , "\n" ) ; 

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]
    size_t TktCipherLen = encrypt(plaintext, TktPlainLen, Kb->key, Kb->iv, ciphertext);

    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na || lenTktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2
    offset = 0; // reset scratch buffer
    size_t lenIDb = strlen(IDb) + 1;
    
    memcpy(plaintext + offset, Ks, sizeof(myKey_t));
    offset += sizeof(myKey_t);

    memcpy(plaintext + offset, &lenIDb, LENSIZE);
    offset += LENSIZE;

    memcpy(plaintext + offset, IDb, lenIDb);
    offset += lenIDb;

    memcpy(plaintext + offset, Na, NONCELEN);
    offset += NONCELEN;

    memcpy(plaintext + offset, &TktCipherLen, LENSIZE);
    offset += LENSIZE;

    memcpy(plaintext + offset, ciphertext, TktCipherLen);
    offset += TktCipherLen;

    size_t m2_len = offset;
    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results
    size_t msg2_len = encrypt(plaintext, m2_len, Ka->key, Ka->iv, ciphertext2);

    // allocate memory on behalf of the caller for a copy of MSG2 ciphertext
    *msg2 = (uint8_t *)malloc(msg2_len);
    uint8_t *p;
    p = *msg2;
    if ( !*msg2 )
        { fprintf(log, "Memory Allocation failed for msg2\n"); exit(-1); }
    memcpy(p, ciphertext2, msg2_len);
    
    // Copy the encrypted ciphertext to Caller's msg2 buffer.

    fprintf( log , "The following Encrypted MSG2 ( %lu bytes ) has been"
                   " created by MSG2_new():  \n" ,  msg2_len  ) ;
    BIO_dump_indent_fp( log , *msg2 ,  msg2_len  , 4 ) ;    fprintf( log , "\n" ) ;    

    fprintf( log ,"This is the content of MSG2 ( %lu Bytes ) before Encryption:\n" ,  m2_len );  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log ,  Ks  ,  KEYSIZE  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%lu Bytes) is:\n" , lenIDb);
    BIO_dump_indent_fp ( log ,  IDb  ,  lenIDb  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log ,  Na  ,  NONCELEN  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%lu Bytes) is\n" ,  TktCipherLen );
    BIO_dump_indent_fp ( log ,  ciphertext  ,  TktCipherLen  , 4 ) ;  fprintf( log , "\n") ; 

    fflush( log ) ;    
    
    return msg2_len ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher )
{
    if ( !log || !IDb || !tktCipher )
    { 
        printf("MSG2_receive received NULL Pointers\n");
        return;
    }

    size_t LenMsg2 = 0, LenB, bytesRead ;

    // 1) Read Length of MSG2
    bytesRead = read(fd, &LenMsg2, LENSIZE);
    if (bytesRead != LENSIZE)
    {
        fprintf( log, "Unable to read size of Msg2\n");
        return;
    }
    // 2) Read MSG2
    uint8_t *msg2_Enc = (uint8_t *)malloc(LenMsg2);
    if ( !msg2_Enc )
        { fprintf(log, "Memory Allocation failed for msg2\n"); exit(-1); }
    bytesRead = read(fd, msg2_Enc, LenMsg2);
    if (bytesRead != LenMsg2)
    {
        fprintf(log, "Unable to read MSG2\n");
        return;
    }
    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n", LenMsg2);
    BIO_dump_indent_fp ( log ,  msg2_Enc  ,  LenMsg2  , 4 ) ;  fprintf( log , "\n") ;
    fflush(log);
    // 3) Decrypt MSG2 and store decrypted in global ciphertext buffer
    uint8_t *decryptedText = (uint8_t *)malloc(LenMsg2);
    if ( !decryptedText )
    {
        fprintf(log, "failed to malloc for decrypted msg2\n");
        fflush(log);
        return;
    }
    size_t decryptedLen = decrypt(msg2_Enc, LenMsg2, Ka->key, Ka->iv, decryptedText);
    free(msg2_Enc); // Free encrypted message buffer
    // 4) Parse Decrypted Message
    size_t offset = 0;
    memcpy(Ks, decryptedText + offset, KEYSIZE);
    offset += KEYSIZE;

    memcpy(&LenB, decryptedText + offset, LENSIZE);
    offset += LENSIZE;

    *IDb = NULL;
    *IDb = (char *)malloc(LenB);
    if (!IDb) {
        fprintf(log, "Memory allocation failed for IDb\n");
        fflush(log);
        return;
    }
    memcpy(*IDb, decryptedText + offset, LenB);
    (*IDb)[LenB] = '\0';
    offset += LenB;

    memcpy(Na, decryptedText + offset, NONCELEN);
    offset += NONCELEN;

    memcpy(lenTktCipher, decryptedText + offset, LENSIZE);
    offset += LENSIZE;

    *tktCipher = NULL;
    *tktCipher = (uint8_t *)malloc(*lenTktCipher);  // Allocate memory for TktCipher
    if (!*tktCipher) {
        fprintf(log, "Memory allocation failed for TktCipher\n");
        fflush(log);
        free(*IDb);
        return;
    }
    memcpy(*tktCipher, decryptedText + offset, *lenTktCipher);
    offset += *lenTktCipher;
    
    
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{

    size_t    LenMsg3 ;
    uint8_t *p;
    LenMsg3 = LENSIZE + lenTktCipher + NONCELEN; // size_t + lenTktCipher + Nonce_t

    // 1) Allocate memory for msg3
    *msg3 = (uint8_t *)malloc(LenMsg3);
    if ( !*msg3 )
        { printf("failed to malloc in msg3_new\n"); exit(-1); }

    // 2) Fill MSG3 with parts
    p = *msg3;
    memcpy(p, &lenTktCipher, LENSIZE);
    p += LENSIZE;

    memcpy(p, tktCipher, lenTktCipher);
    p += lenTktCipher;

    memcpy(p, Na2, NONCELEN);
    p += NONCELEN; 

    return( LenMsg3 ) ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{
    if ( !log || !IDa )
        { printf("MSG3_recieve received NULL Pointers\n"); return; }

    size_t LenMsg3 = 0, LenTicket, LenA, bytesRead ;
    // 1) Read Length of Encrypted Ticket
    bytesRead = read(fd, &LenMsg3, LENSIZE);
    if (bytesRead != LENSIZE)
        { fprintf(log, "Unable to read size of Encrypted Ticket\n"); return; }

    // 2) Read Encrypted Ticket
    uint8_t *tktCipher = (uint8_t *)malloc(LenMsg3);
    if ( !tktCipher )
        { fprintf(log, "Memory Allocation failed for tktCipher\n"); exit(-1); }
    bytesRead = read(fd, tktCipher, LenMsg3);
    if (bytesRead != LenMsg3)
        { fprintf(log, "Unable to read tktCipher\n"); return; }

    fprintf(log, "The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_reveive()\n", LenMsg3);
    BIO_dump_indent_fp(log, tktCipher, LenMsg3, 4); fprintf(log, "\n");

    // 3) Decrypt Encrypted Ticket
    uint8_t *decryptedTkt = (uint8_t *)malloc(LenMsg3);
    if ( !decryptedTkt )
        { fprintf(log, "Unbale to allocate memory for decrypted ticket\n"); return; }
    size_t decryptedLen = decrypt(tktCipher, LenMsg3, Kb->key, Kb->iv, decryptedTkt);
    free(tktCipher);

    fprintf(log, "Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n", decryptedLen);
    BIO_dump_indent_fp(log, decryptedTkt, decryptedLen, 4); fprintf(log, "\n");

    // 4) Parse Decrypted Ticket
    size_t offset = 0;
    memcpy(Ks, decryptedTkt + offset, KEYSIZE);
    offset += KEYSIZE;

    memcpy(&LenA, decryptedTkt + offset, LENSIZE);
    offset += LENSIZE;

    *IDa = NULL;
    *IDa = (char *)malloc(LenA);
    if (!IDa)
        { fprintf(log, "Memory Allocation failed for IDa\n"); return; }
    memcpy(*IDa, decryptedTkt + offset, LenA);
    (*IDa)[LenA] = '\0';
    offset += LenA;

    fprintf(log, "Basim received Message 3 from Amal with the following content:\n");
    fprintf(log, "    Ks { Key , IV } (%lu Bytes ) is:\n", KEYSIZE);
    BIO_dump_indent_fp(log, Ks, KEYSIZE, 4); fprintf(log, "\n");

    fprintf(log, "    IDa = '%s'\n", *IDa);

    // 5) Read Na2
    bytesRead = read(fd, Na2, NONCELEN);
    if (bytesRead != NONCELEN)
        { fprintf(log, "Unable to read Na2\n"); return; }
    
    fprintf(log, "    Na2 ( %lu Bytes ) is:\n", NONCELEN);
    BIO_dump_indent_fp(log, Na2, NONCELEN, 4); fprintf(log, "\n");
}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    size_t LenMsg4;
    size_t plaintext_len, ciphertext_len;

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values
    plaintext_len = fNa2->size + Nb->size;
    if (plaintext_len > sizeof(plaintext)) {
        fprintf(log, "Error: MSG4 plaintext too large for scratch buffer\n");
        return 0;
    }

    memcpy(plaintext, fNa2->data, fNa2->size);       // Copy f(Na2)
    memcpy(plaintext + fNa2->size, Nb->data, Nb->size); // Concatenate Nb

    // Now, encrypt MSG4 plaintext using the session key Ks;
    ciphertext_len = encrypt_with_key(Ks, plaintext, plaintext_len, ciphertext);
    if (ciphertext_len > sizeof(ciphertext)) {
        fprintf(log, "Error: MSG4 ciphertext too large for scratch buffer\n");
        return 0;
    }

    //****************CHECK THIS******************** */
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    // *msg4 = malloc( .... ) ;
    *msg4 = (uint8_t *)malloc(ciphertext_len);
    if (*msg4 == NULL) {
        fprintf(log, "Error: Memory allocation failed for MSG4\n");
        return 0;
    }

    memcpy(*msg4, ciphertext, ciphertext_len);
    LenMsg4 = ciphertext_len;

    fprintf( log , "The following Encrypted MSG4 ( %lu bytes ) has been"
                    " created by MSG4_new ():  \n" , LenMsg4 ) ;
    BIO_dump_indent_fp(log, (const char *)*msg4, LenMsg4, 4);

    return LenMsg4 ;
    

}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void MSG4_receive(FILE *log, int fd, const myKey_t *Ks, Nonce_t *rcvd_fNa2, Nonce_t *Nb)
{
    uint8_t *encrypted_msg4 = NULL;
    //uint8_t plaintext[SCRATCH_BUFFER_SIZE]; // ****** NEED TO: define SCRATCH_BUFFER_SIZE********
    size_t encrypted_len, plaintext_len;

    // step 1: read the encrypted MSG4 from fd
    if (read_fd(fd, &encrypted_msg4, &encrypted_len) == -1) { 
        fprintf(log, "Error: Failed to read encrypted MSG4 from fd\n");
        return;
    }

    fprintf(log, "Received encrypted MSG4 (%lu bytes):\n", encrypted_len);
    BIO_dump_indent_fp(log, (const char *)encrypted_msg4, encrypted_len, 4);

    // step 2: decrypt the encrypted MSG4 using session key Ks
    plaintext_len = decrypt_with_key(Ks, encrypted_msg4, encrypted_len, plaintext);
    if (plaintext_len == 0) {
        fprintf(log, "Error: Failed to decrypt MSG4\n");
        free(encrypted_msg4);
        return;
    }

    fprintf(log, "Decrypted MSG4 (%lu bytes):\n", plaintext_len);
    BIO_dump_indent_fp(log, (const char *)plaintext, plaintext_len, 4);

    // step 3: parse plaintext into rcvd_fNa2 + Nb
    if (plaintext_len < rcvd_fNa2->size + Nb->size) {
        fprintf(log, "Error: Decrypted MSG4 size mismatch\n");
        free(encrypted_msg4);
        return;
    }

    memcpy(rcvd_fNa2->data, plaintext, rcvd_fNa2->size);
    memcpy(Nb->data, plaintext + rcvd_fNa2->size, Nb->size);

    fprintf(log, "Parsed rcvd_fNa2 (size: %lu bytes):\n", rcvd_fNa2->size);
    BIO_dump_indent_fp(log, (const char *)rcvd_fNa2->data, rcvd_fNa2->size, 4);

    fprintf(log, "Parsed Nb (size: %lu bytes):\n", Nb->size);
    BIO_dump_indent_fp(log, (const char *)Nb->data, Nb->size, 4);

    // Step 4: Clean up
    free(encrypted_msg4);
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    size_t  LenMSG5cipher  ;

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 


    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.


    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    // *msg5 = malloc( ... ) ;


    // fprintf( log , "The following Encrypted MSG5 ( %lu bytes ) has been"
    //                " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    // BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    // fflush( log ) ;    

    return LenMSG5cipher ;

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    size_t    LenMSG5cipher ;
    
    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.


    fprintf( log ,"The following Encrypted MSG5 ( %lu bytes ) has been received:\n" , LenMSG5cipher );


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits


    // Parse MSG5 into its components f( Nb )



}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are store in Big-Endian byte order
    // This affects how you do arithmetice on the noces, e.g. when you add 1
}
