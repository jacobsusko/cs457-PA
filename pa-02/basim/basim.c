/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   basim.c

Written By:  Team # 8
     1- Jacob Susko
     2- Sydney Nguyen

Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    EVP_PKEY *pub_key;
    int     i , fd_out , fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "code by Jacob Susko & Sydney Nguyen" ;  

    printf( "\nThis is Basim's   %s\n\n" ,  developerName ) ;

    // Get the FD arguments from the dispatcher & create  the log file
    fd_ctrl = atoi(argv[1]);
    fd_data = atoi(argv[2]);

    /* Open Clean Log File */
    log = fopen("basim/logBasim.txt" , "w" );
    if ( ! log )
        { fprintf( stderr , "This is Basim. Could not create log file\n"); exit(-1) ; }

    fprintf( log , "\nThis is Basim's %s\n\n" , developerName ) ;

    fprintf( log , "Basim: I will receive digest from FD %d and file from FD %d\n" ,
                   fd_ctrl , fd_data );

 
    // Create a blank bunny.cpy file with the proper access privileges
    fd_out = open("bunny.cpy", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd_out == -1)
        { fprintf(log, "\nBasim could not create bunny.cpy\n"); exit(-1); }
    //    and call fileDigest() to compute its hash value in the digest[]
    mdLen = fileDigest(fd_data, fd_out, digest);  // Size coming back as 0 => redo and figure out
    
    // Use the fileDigest() function to:
    //    1) Receive the incoming data from the Data Pipe, and store a copy in bunny.cpy
    //    2) compute the hash value in the 'digest' array.
    fprintf( log , "Basim: Starting to receive incoming file and compute its digest\n");

    fprintf( log , "\nBasim: Here is locally-computed the digest of the incoming file:\n" );
    BIO_dump_fp( log , digest , mdLen ) ; 
    
 
    // Get Amal's RSA public key from "basim/amal_pub_key.pem" which was generated 
    // outside this program using the opessl tool
    pub_key = getRSAfromFile("basim/amal_pub_key.pem", 1);
    if (! pub_key)
        { fprintf(log, "\nBasim could not open amal's public key\n"); exit(-1); }

    // Receive Amal's signature on this incoming file from the Control Pipe as a stream of bytes
    // First its length to allocate enough memory, then the signature itself
    size_t signature_len;
    read(fd_ctrl, &signature_len, sizeof(signature_len));
    
    uint8_t *signature;
    signature = (u_int8_t*)malloc(signature_len);
    if (!signature)
        { fprintf(log, "\nBasim failed to make memory for signature\n"); exit(-1); }
    read(fd_ctrl, signature, signature_len);

    fprintf( log , "\nBasim: I received the following signature from Amal:\n" );
    BIO_dump_fp( log , signature , signature_len ) ; 


    // Verify, using Amal's public key, the incoming signature is valid given 
    // the locally-calculated digest

    fprintf( log , "\nBasim: I found that Amal's signature is ");
    if ( pubKeyVerify(signature, signature_len, pub_key, digest, mdLen) > 0)  // Something wrong with what is being passed
        fprintf( log , "VALID\n" );    
    else
        fprintf( log , "INVALID\n" );  

    // Close all files & Free all dynamically allocated objects
    free(signature);
    fclose(log);
    close(fd_ctrl);
    close(fd_data);
    close(fd_out);

    return 0 ;
}

