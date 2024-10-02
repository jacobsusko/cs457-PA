/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- MUST WRITE YOUR FULL NAME
     2- MUST WRITE YOUR FULL NAME

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

    // Create and Initialize a context for RSA private-key signing
    EVP_PKEY_CTX *ctx;
    // EVP_PKEY_CTX_new( );
    // EVP_PKEY_sign_init( )
    // EVP_PKEY_CTX_set_rsa_padding(  )

    // Determine how big the size of the signature could be
    size_t cipherLen ; 
    // EVP_PKEY_sign( )
    // Next allocate memory for the ciphertext

    // Now, actually sign the inData using EVP_PKEY_sign( )

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

    // EVP_PKEY_CTX_new( );
    // EVP_PKEY_verify_init( )
    // EVP_PKEY_CTX_set_rsa_padding(  )

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify( /* .... */ ) ;

    //  free any dynamically-allocated objects 

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

