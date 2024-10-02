/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   amal.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- MUST WRITE YOUR FULL NAME
     2- MUST WRITE YOUR FULL NAME

Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_in , fd_ctrl , fd_data  ;
    FILE    *log ;
    
    char *developerName = "code by MUST WRITE YOUR FULL NAME(S) HERE" ;  
    
    printf( "\nThis is Amal's    %s\n\n" , developerName ) ;

    // Get the FD arguments from the dispatcher & create  the log file

    fprintf( log , "\nThis is Amal's %s.\n\n" , developerName  ) ;

    fprintf( log , "Amal: I will send digest to FD %d and file to FD %d\n" ,
                   fd_ctrl , fd_data );

    // Open the bunny.mp4 file and call fileDigesr() to compute its hash value in the digest[]
    
    
    fprintf( log , "\nAmal: Here is the digest of the file:\n" );
    BIO_dump_fp( log , digest , mdLen ) ; 

    // Get Amal's RSA private key generated outside this program using the opessl tool 

    // Call privKeySign() to sign the digest using Amal's private key
    uint8_t *signature = NULL  ;
    size_t   signature_len ;

    if ( ! privKeySign( /* .... */ ) )
    {
        fprintf( log , "Unable to sign digest using Amal's Private key\n" ); 
        EVP_PKEY_free( rsa_privK );  exit(-1) ;
    }

    fprintf( log , "\nAmal: Here is my signature on the file:\n" );
    BIO_dump_fp( log , signature , signature_len ) ; 

    // send the signature to Basim via the Control Pipe as a stream of bytes
    // First its length, then the signature itself

    
    // Close all files & Free all dynamically allocated objects
    
    return 0 ;
}

