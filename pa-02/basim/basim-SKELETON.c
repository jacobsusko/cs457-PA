/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   basim.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- MUST WRITE YOUR FULL NAME
     2- MUST WRITE YOUR FULL NAME

Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_out , fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "code by MUST WRITE YOUR FULL NAME(S) HERE" ;  

    printf( "\nThis is Basim's   %s\n\n" ,  developerName ) ;

    // Get the FD arguments from the dispatcher & create  the log file

    fprintf( log , "\nThis is Basim's %s\n\n" , developerName ) ;

    fprintf( log , "Basim: I will receive digest from FD %d and file from FD %d\n" ,
                   fd_ctrl , fd_data );

 
    // Create a blank bunny.cpy file with the proper access privileges
    //    and call fileDigesr() to compute its hash value in the digest[]

    
    // Use the fileDigest() function to:
    //    1) Receive the incoming data from the Data Pipe, and store a copy in bunny.cpy
    //    2) compute the hash value in the 'digest' array.
    fprintf( log , "Basim: Starting to receive incoming file and compute its digest\n");


    fprintf( log , "\nBasim: Here is locally-computed the digest of the incoming file:\n" );
    BIO_dump_fp( log , digest , mdLen ) ; 
 
    // Get Amal's RSA public key from "basim/amal_pub_key.pem" which was generated 
    // outside this program using the opessl tool 

    // Receive Amal's signature on this incoming file from the Control Pipe as a stream of bytes
    // First its length to allocate enough memory, then the signature itself


    fprintf( log , "\nBasim: I received the following signature from Amal:\n" );
    BIO_dump_fp( log , signature , signature_len ) ; 


    // Verify, using Amal's public key, the incoming signature is valid given 
    // the locally-calculated digest

    fprintf( log , "\nBasim: I found that Amal's signature is ");
    if ( pubKeyVerify( /* ....  */ ) )
        fprintf( log , "VALID\n" );    
    else
        fprintf( log , "INVALID\n" );  

    // Close all files & Free all dynamically allocated objects

    return 0 ;
}

