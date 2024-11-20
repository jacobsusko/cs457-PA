/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   kdc.c    SKELETON

Written By: 
     1- Jacob Susko
	 2- Sydney Nyguen
Submitted on: 
    11/21/2024
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    // Your code from pa-04_PartOne
    int       fd_A2K , fd_K2A   ;
    FILE     *log ;
    
    char *developerName = "Susko & Nyugen" ;

    fprintf( stdout , "Starting the KDC's   %s\n"  , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <readFrom Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2K    = atoi(argv[1])  ;  // Read from Amal   File Descriptor
    fd_K2A    = atoi(argv[2])  ;  // Send to   Amal   File Descriptor

    log = fopen("kdc/logKDC.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "The KDC's   %s. Could not create log file\n"  , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting the KDC\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2K , fd_K2A );

    // Get Amal's master keys with the KDC and dump it to the log
    myKey_t  Ka ;    // Amal's master key with the KDC

    // Use  getKeyFromFile( "kdc/amalKey.bin" , ....  )
    if (getKeyFromFile( "kdc/amalKey.bin", &Ka) == 0) // failed
    {
        // On failure, print "\nCould not get Amal's Masker key & IV.\n" to both  stderr and the Log file
        // and exit(-1)
        fprintf(log , "\nCould not get Amal's Master key & IV.\n");
        fprintf(stderr , "\nCould not get Amal's Master key & IV.\n");
        exit(-1);
    }
	// On success, print "Amal has this Master Ka { key , IV }\n" to the Log file
    fprintf( log , "Amal has this Master Ka { key , IV }\n");
	// BIO_dump the Key IV indented 4 spaces to the righ
    BIO_dump_indent_fp( log, &Ka.key, SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ
    BIO_dump_indent_fp( log, &Ka.iv, INITVECTOR_LEN, 4);
    fprintf( log , "\n" );


    fflush( log ) ;
    
    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC

    // Use  getKeyFromFile( "kdc/basimKey.bin" , .... ) )
    if (getKeyFromFile( "kdc/basimKey.bin", &Kb) == 0) // failed    
    {
        // On failure, print "\nCould not get Basim's Masker key & IV.\n" to both  stderr and the Log file
        // and exit(-1)
        fprintf(log , "\nCould not get Basim's Master key & IV.\n");
        fprintf(stderr , "\nCould not get Basim's Master key & IV.\n");
        exit(-1);
    }
	// On success, print "Basim has this Master Ka { key , IV }\n" to the Log file
    fprintf( log , "Basim has this Master Kb { key , IV }\n");
	// BIO_dump the Key IV indented 4 spaces to the right
    BIO_dump_indent_fp( log, &Kb.key, SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ
    BIO_dump_indent_fp( log, &Kb.iv, INITVECTOR_LEN, 4);
    fprintf( log , "\n" );
    fflush( log ) ;

    //*************************************
    // Receive  & Display   Message 1
    //*************************************
    BANNER( log ) ;
    fprintf( log , "         MSG1 Receive\n");
    BANNER( log ) ;

    char *IDa , *IDb ;
    Nonce_t  Na ;
    
    // Get MSG1 from Amal
    MSG1_receive( log , fd_A2K , &IDa , &IDb , Na ) ;

    fprintf( log , "\nKDC received message 1 from Amal with:\n"
                   "    IDa = '%s'\n"
                   "    IDb = '%s'\n" , IDa , IDb ) ;

    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
    // BIO_dump the nonce Na
    BIO_dump_indent_fp( log, &Na, NONCELEN, 4);
    fprintf( log , "\n") ;
    fflush( log ) ;
    
    

    //*************************************   
    // Construct & Send    Message 2
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 New\n");
    BANNER( log ) ;
    // Get session key
    myKey_t   Ks ;
    if (getKeyFromFile( "kdc/sessionKey.bin", &Ks) == 0) // failed    
    {
        fprintf(log , "\nCould not get Session key & IV.\n");
        fprintf(stderr , "\nCould not get Session key & IV.\n");
        exit(-1);
    }
	// On success, print "Basim has this Master Ka { key , IV }\n" to the Log file
    fprintf( log , "KDC: created this session key Ks { Key , IV } (%lu Bytes ) is:\n", KEYSIZE);
	// BIO_dump the Key IV indented 4 spaces to the right
    BIO_dump_indent_fp( log, &Ks, KEYSIZE, 4);
    fprintf( log , "\n" );
    fflush( log ) ;

    uint8_t *msg2;
    size_t msg2_len = MSG2_new(log, &msg2, &Ka, &Kb, &Ks, IDa, IDb, &Na);

    write(fd_K2A, &msg2_len, LENSIZE);
    write(fd_K2A, msg2, msg2_len);
    fprintf(log, "The KDC sent the Encrypted MSG2 ( %lu bytes ) to Amal Successfully\n", msg2_len);
    free(msg2);

    //*************************************   
    // Final Clean-Up
    //*************************************   
end_:
    fprintf( log , "\nThe KDC has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  
    return 0 ;
}
