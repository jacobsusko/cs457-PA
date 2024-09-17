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
    unsigned ciphertext_len, decryptedtext_len;
    int fd_ctrl, fd_data, fd_key, fd_iv, fd_decr;
    uint8_t ciphertext[CIPHER_LEN_MAX], decryptedtext[PLAINTEXT_LEN_MAX];

    
    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if( argc < 3 )
    {
        printf("Basim is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl = atoi( argv[1] ) ; /* File Descriptor for A - B Control Channel */
    fd_data = atoi( argv[2] ) ; /* File Descriptor for A - B Data Channel */

    /* Open Clean Log File */
    FILE *log = fopen("basim/logBasim.txt" , "w" );
    if ( ! log )
        { fprintf( stderr , "This is Basim. Could not create log file\n"); exit(-1) ; }
    fprintf( log , "This is Basim. Will read encrypted data from FD %d\n" , fd_data );
                   
    /* Open Key File */
    fd_key = open("key.bin" , O_RDONLY)  ;
    if ( fd_key == -1 )
        { fprintf( log , "\nCould not open Basim's key.bin\n"); exit(-1) ;}

    read ( fd_key , key, key_len) ;
    fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
    BIO_dump_fp ( log, (const char *) key, key_len );
    close( fd_key ) ;

    /* Open IV File */
    fd_iv = open( "iv.bin" , O_RDONLY )  ;
    if ( fd_iv == -1 )
        { fprintf( log, "\nCould not open Basim's iv.bin\n"); exit(-1); }
    
    read ( fd_iv, iv, iv_len);
    fprintf( log, "\nUsing this Initial Vector of Length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char *) iv, iv_len);
    close( fd_iv ) ;

    /* Create empty pa-01/bunny.decr output file */
    int output = open("bunny.decr", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (output == -1)
        { fprintf(stderr, "This is Basim. Could not create bunny.decr file\n"); exit(-1); }

    fflush(log);
    /* Decrypt file recieved via fd_data and write results to output*/
    decryptedtext_len = decryptFile(fd_data, output, key, iv);

    /* Clean up */
    close(fd_data);
    close(output);
    fclose(log);
    EVP_cleanup();
    ERR_free_strings();
}



