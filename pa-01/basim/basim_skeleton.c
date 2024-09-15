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
    int fd_ctrl, fd_data, fd_key, fd_iv, fd_decr;

    
    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if( argc < 3 )
    {
        printf("Basim is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    FILE *log = fopen("basim/logBasim.txt" , "w" );
    if ( ! log )
        { fprintf( stderr , "This is Basim. Could not create log file\n"); exit(-1) ; }
    fprintf( log , "This is Basim. Will read encrypted data from FD %d\n" , fd_data );
                   
    // Get the session symmetric key
    fd_key = open("basim/key.bin" , /* ... */ )  ;
    if ( fd_key == -1 )
        { fprintf( log , "\nCould not open Basim's key.bin\n"); exit(-1) ;}

    read ( fd_key , /* .. , .. */ ) ;
    fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
    BIO_dump_fp ( log, /* .. */ );
    close( fd_key ) ;

    // Get the session Initial Vector 
    fd_iv = open( "basim/iv.bin" , /* .. */ )  ;
    //
    // ... Similar to above 
    //
    close( fd_iv ) ;

    // Open the file for the output decrypted file
    fd_decr = open( decrypted , /* .. */  , /* .. */ );
    if( fd_decr == -1 )
        { fprintf( log , "\nCould not open '%s'\n" , decrypted ); exit(-1) ; }
   
	fflush( log ) ;
	
   /* Finally, decrypt the ciphertext file */
    decryptFile( /* .. */ );

    /* Clean up */
    //
    // ... 
    //
    
}



