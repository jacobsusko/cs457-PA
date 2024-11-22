/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c     SKELETON

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

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    // Your code from pa-04_PartOne
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Susko & Nyguen" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    // Use  getKeyFromFile( "basim/basimKey.bin" , .... ) )
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
    // BIO_dump the Key IV indented 4 spaces to the righ
    BIO_dump_indent_fp( log, &Kb.key, SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ
    BIO_dump_indent_fp( log, &Kb.iv, INITVECTOR_LEN, 4);
    fprintf( log , "\n" );
    fflush( log ) ;

    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  

	// Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
    getNonce4Basim(1, Nb);
    fprintf( log , "Basim will use this Nonce:  Nb\n"  ) ;
	// BIO_dump Nb indented 4 spaces to the righ
    BIO_dump_indent_fp( log, &Nb, NONCELEN, 4);
    fprintf( log , "\n" );

    fflush( log ) ;
    
    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;
    fflush (log );
    myKey_t Ks;
    char *IDa2;
    Nonce_t Na_msg3;
    MSG3_receive(log, fd_A2B, &Kb, &Ks, &IDa2, &Na_msg3);

    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;
    Nonce_t fNa2;
    fNonce(fNa2, Na_msg3);
    fprintf(log, "Basim is sending this f( Na2 ) in MSG4:\n");
    BIO_dump_indent_fp(log, fNa2, NONCELEN, 4); fprintf(log, "\n");
    fprintf(log, "Basim is sending this nonce Nb in MSG4:\n");
    BIO_dump_indent_fp( log, Nb, NONCELEN, 4); fprintf(log, "\n");

    uint8_t *msg4;
    size_t LenMsg4 = MSG4_new(log, &msg4, &Ks, &fNa2, &Nb);

    // Send message to Amal
    write(fd_B2A, &LenMsg4, LENSIZE);
    write(fd_B2A, msg4, LenMsg4);
    fprintf(log, "Basim Sent the above MSG4 to Amal\n\n");
    fflush(log);
    free(msg4);

    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;
    Nonce_t fNb, rcvd_fNb;
    fNonce(fNb, Nb);
    fprintf(log, "Basim is expecting back this f( Nb ) in MSG5:\n");
    BIO_dump_indent_fp(log, fNb, NONCELEN, 4); fprintf(log, "\n");

    MSG5_receive(log, fd_A2B, &Ks, &rcvd_fNb);

    fprintf(log, "Basim received Message 5 from Amal with this f( Nb ): >>>> %s\n", (memcmp(fNb, rcvd_fNb, NONCELEN) == 0)? "VALID" : "INVALID");
    BIO_dump_indent_fp(log, rcvd_fNb, NONCELEN, 4); fprintf(log, "\n");

    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
