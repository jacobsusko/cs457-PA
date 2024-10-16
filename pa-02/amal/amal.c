/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   amal.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- Sydney Nguyen 
     2- Jacob Susko

Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    // NOTE: buffer = temporary storage when data is being transferred between two places
    uint8_t digest[EVP_MAX_MD_SIZE] ; // buffer to store hash value (digest)
    int     i , fd_in , fd_ctrl , fd_data  ; // file descriptors for input + control pipe + data pipe
    FILE    *log ; // log file pointer
    size_t mdLen; // store length of computed hash 
    
    char *developerName = "code by Sydney Nguyen and Jacob Susko" ;  
    
    printf( "\nThis is Amal's    %s\n\n" , developerName ) ;

    // check for valid number of command line args
    if (argc < 3) {
        printf("invalid number of command-line arguments");
        exit(-1);
    }

    // <-- Get the FD arguments from the dispatcher & create the log file -->

    // SPECS: Gets the write-end file descriptors of both pipes from the command-line arguments
    fd_ctrl = atoi(argv[1]); 
    fd_data = atoi(argv[2]); 

    // open log file
    log = fopen("amal/logAmal.txt", "w");
    if (log == NULL) {
        perror("Error opening amal's log file");
        exit(EXIT_FAILURE);
    }

    fprintf( log , "\nThis is Amal's %s.\n\n" , developerName  ) ;

    fprintf( log , "Amal: I will send digest to FD %d and file to FD %d\n" ,
                   fd_ctrl , fd_data );

    // <-- Open the bunny.mp4 file and call fileDigest() to compute its hash value in the digest[] -->
    
    // open bunny.mp4 file
    fd_in = open("bunny.mp4", O_RDONLY);
    if (fd_in < 0) {
        fprintf(log, "\nAmal could not open bunny.mp4\n"); 
        exit(-1);
    }

    fprintf(log, "Amal: Starting to digest the input file\n"); 

    // call fileDigest() to compute the hash of bunny.mp4 and store it in the digest array
    mdLen = fileDigest( fd_in , fd_data , digest ) ;
    if (mdLen == 0) {
        fprintf(log, "Failed to compute file digest\n");
        fclose(log);
        close(fd_in);
        exit(-1);
    }

    // checkpoint: logging computed digest (hash value)
    fprintf( log , "\nAmal: Here is the digest of the file:\n" );
    BIO_dump_fp( log , digest , mdLen ) ; 

    // Get Amal's RSA private key generated outside this program using the opessl tool 
    EVP_PKEY  *priv_key = NULL  ;
    priv_key = getRSAfromFile("amal/amal_priv_key.pem", 0);
    if (! priv_key)
    { 
        fprintf(log, "\nAmal could not retrieve Amal's generated private key\n"); 
        exit(-1); 
    }

    // Call privKeySign() to sign the digest using Amal's private key
    uint8_t *signature = NULL  ;
    size_t   signature_len ;
    // privKeySign(priv_key, digest, mdLen, &signature, &signature_len)
    if (!privKeySign(&signature, &signature_len, priv_key, digest, mdLen)) 
    {
        fprintf(log, "Unable to sign digest using Amal's Private key\n");
        EVP_PKEY_free(priv_key);
        fclose(log);
        exit(-1);
    }

    fprintf( log , "\nAmal: Here is my signature on the file:\n" );
    BIO_dump_fp( log , signature , signature_len ) ; 

    // send the signature to Basim via the Control Pipe as a stream of bytes
    // First its length, then the signature itself
    write(fd_ctrl , &signature_len , sizeof(signature_len) ); // sending signature length
    write(fd_ctrl , signature , signature_len ); // send sginature itself
    // sending bunny.mp4 file to fd_data in fileDigest in myCrypo.c

    
    // Close all files & Free all dynamically allocated objects
    close(fd_ctrl);
    close(fd_data);
    close(fd_in);
    fclose(log);
    //free(developerName);
    EVP_PKEY_free(priv_key);
    free(signature);

    return 0 ;
}

