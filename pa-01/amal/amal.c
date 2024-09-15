/*----------------------------------------------------------------------------
PA-01: Symmetric Encryption of Large Data

FILE:   basim.c

Written By: 
     1- Dr. Mohamed Aboutabl
     2- Jacob Susko
Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    //
    // Define any variable you need here
    //
    uint8_t key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned key_len = 32; // ie 256 bits
    unsigned iv_len = 16; // ie 128 bits
    uint8_t ciphertext[CIPHER_LEN_MAX];
    unsigned plaintext_len, ciphertext_len;

    int fd_ctrl, fd_data, fd_key, fd_iv, fd_decr;

    
    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if( argc < 3 )
    {
        printf("Amal is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    FILE *log = fopen("amal/logAmal.txt" , "w" );
    if ( ! log )
        { fprintf( stderr , "This is Amal. Could not create log file\n"); exit(-1) ; }
    fprintf( log , "This is Amal. Will write encrypted data to FD %d\n" , fd_data );
                   
    // Get the session symmetric key
    fd_key = open("key.bin" , O_RDONLY)  ;
    if ( fd_key == -1 )
        { fprintf( log , "\nCould not open Amal's key.bin\n"); exit(-1) ;}

    read ( fd_key , key, key_len) ;
    fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
    BIO_dump_fp ( log, (const char *) key, key_len );
    close( fd_key ) ;

    // Get the session Initial Vector 
    fd_iv = open( "iv.bin" , O_RDONLY )  ;
    if ( fd_iv == -1 )
        { fprintf( log, "\nCould not open Amal's iv.bin\n"); exit(-1); }
    
    read ( fd_iv, iv, iv_len);
    fprintf( log, "\nUsing this Initial Vector of Length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char *) iv, iv_len);
    close( fd_iv ) ;

    /* Encrypt plain text */

    /* Clean up */
    //
    // ... 
    //
    
}


