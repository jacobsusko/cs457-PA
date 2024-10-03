/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team # 8
     1- Jacob Susko
     2- Sydney 

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


/*

    Y O U R       P R E V I O U S      C O D E 

            G O E S        H E R E

*/

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
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        { printf("\nUnable to set the PADDING mode of the context for private key\n"); exit(-1); }

    // Determine how big the size of the signature could be
    size_t cipherLen ; 
    if (EVP_PKEY_sign(ctx, NULL, &cipherLen, inData, inLen) <= 0)
        { printf("\nUnable to determine output length of private key signature\n"); exit(-1); }
    // Next allocate memory for the ciphertext
    sig = malloc(cipherLen);
    if (!sig)
        { printf("\nInsufficient memory to Sign\n"); exit(-1); }

    // Now, actually sign the inData using EVP_PKEY_sign( )
    if (EVP_PKEY_sign(ctx, sig, &cipherLen, inData, inLen) <= 0)
        { printf("\nSignature of the data failed\n"); exit(-1); }

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
        { pritnf("\nUnable to initialize the context for signature verification\n"); exit(-1); }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        { printf("\nUnable to set the PADDING mode of the context for signature verification\n"); exit(-1); }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen) ;

    //  free any dynamically-allocated objects
    free(sig);
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
    unsigned int  mdLen ;

	// Use EVP_MD_CTX_create() to create new hashing context    
    // EVP_MD_CTX_new()
    
    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the HASH_ALGORITHM() hashing function 
    // EVP_DigestInit(  )

    while ( 1 )   // Loop until end-of input file
    {
        // Read a chund of input from fd_in. Exit the loop when End-of-File is reached

        // VP_DigestUpdate( )
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
            
    }

    // EVP_DigestFinal( )
    
    // EVP_MD_CTX_destroy( );

    return mdLen ;
}
