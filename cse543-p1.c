
/**********************************************************************

   File          : cse543-p1.c

   Description   : This is the main file.
                   (see .h for applications)

***********************************************************************/
/**********************************************************************
Copyright (c) 2006-2018 The Pennsylvania State University
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of The Pennsylvania State University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-proto.h"
#include "cse543-network.h"


/* Definitions */
#define ARGUMENTS "dr"
#define USAGE "USAGE: cse543-p1 <filename> <server  IP address> <command> <file_type>\n"
#define SERVER_USAGE "USAGE: cse543-p1-server <private_key_file> <public_key_file>\n"

/**********************************************************************

    Function    : main
    Description : this is the main function for project
    Inputs      : argc - number of command line parameters
                  argv - the text of the arguements
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

/* Functions */
int main( int argc, char **argv ) 
{
#ifndef CSE543_PROTOCOL_SERVER
	struct rm_cmd *r;
	int err;     

	/* Check for arguments */
	if ( argc < 5 ) 
	{
		/* Complain, explain, and exit */
		errorMessage( "missing or bad command line arguments\n" );
		printf( USAGE );
		exit( -1 );
	}

	/* make request data structure */
	/* with file, command, file_type */
	err = make_req_struct( &r, argv[1], argv[3], argv[4] );
	if (err) {
		errorMessage( "cannot process request line into command\n" );
		printf( USAGE );
		exit( -1 );
	}

	/* Check it exists and is readable */
	struct stat st;
	int status = stat( argv[1], &st ), 
		readable = ( ((st.st_uid == getuid()) && (st.st_mode&S_IRUSR)) || 
			     (st.st_mode&S_IROTH) );
	if  ( (status == -1) || (!readable) )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "non-existant or unreable file [%.64s]\n", argv[1] );
		errorMessage( msg );
		printf( USAGE );
		exit( -1 );
	}

	/* Check the address */
	if  ( inet_addr(argv[2]) == INADDR_NONE )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Bad server IP address [%.64s]\n", argv[2] );
		errorMessage( msg );
		printf( USAGE );
		exit( -1 );
	}


	/* Now print some preamble and get into the protocol, exit */
	printf( "Transfer beginning, file [%s]\n", argv[1] );
	return ( client_secure_transfer( r, argv[1], argv[2]) );

#else

	/* Check for arguments */
	if ( argc < 3 ) 
	{
		/* Complain, explain, and exit */
		errorMessage( "missing or bad command line arguments\n" );
		printf( SERVER_USAGE );
		exit( -1 );
	}

	/* Just run the server */
	/* argv1 - private key file, argv2 - public key file */
	server_secure_transfer( argv[1], argv[2] );
	return( 0 );

#endif
}
