/**********************************************************************

   File          : cse543-network.c

   Description   : This is the network interfaces for the crypto protocol connection.

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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"

/* Functional Prototypes */

/**********************************************************************

    Function    : connect_client
    Description : connnect a client to the server
    Inputs      : address - the address ("a.b.c.d")
    Outputs     : file handle if successful, -1 if failure

***********************************************************************/

int connect_client( char *address )
{
	/* Local variables */
	int sock;
	struct sockaddr_in inet;

	// Zero/Set the address
	memset( &inet, 0x0, sizeof(inet) );
	inet.sin_family = AF_INET;
	inet.sin_port = htons( PROTOCOL_PORT );
	inet.sin_addr.s_addr = inet_addr( (char *)address );

	/* Connect to the server */
	if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		errorMessage( "failed read on data file.\n" );
		exit( -1 );
	}

	// Call the connect
	if ( connect(sock, (struct sockaddr *)&inet, sizeof(inet)) != 0 )
	{
		/* Complain, explain, and return */
		char msg[128];
		sprintf( msg, "failed client socket connection [%.64s]\n", 
			 strerror(errno) );
		errorMessage( msg );
		exit( -1 );
	}

	/* Print a log message */
	printf( "Client connected to address [%s/%d], successful ...\n", 
		address, PROTOCOL_PORT );

	/* Return the file handle */
	return( sock );
}

/**********************************************************************

    Function    : server_connect
    Description : connnect a server socket to listen for
    Inputs      : none
    Outputs     : file handle if successful, -1 if failure

***********************************************************************/

int server_connect( void )
{
	/* Local variables */
	int sock;
	struct sockaddr_in inet;

	// Zero/Set the address
	memset( &inet, 0x0, sizeof(inet) );
	inet.sin_family = AF_INET;
	inet.sin_port = htons( PROTOCOL_PORT );
	inet.sin_addr.s_addr = INADDR_ANY;

	/* Connect to the server */
	if ( (sock = socket( AF_INET, SOCK_STREAM, 0)) == -1 )
	{
		/* Complain, explain, and return */
		char msg[128];
		sprintf( msg, "failed server socket create [%.64s]\n", 
			 strerror(errno) );
		errorMessage( msg );
		exit( -1 );
	}

	/* Setup the socket option to reuse */
	int on = 1;
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	// Call the connect
	if ( bind(sock, (struct sockaddr *)&inet, sizeof(inet)) != 0 )
	{
		/* Complain, explain, and return */
		char msg[128];
		sprintf( msg, "failed server socket bind [%.64s]\n", 
			 strerror(errno) );
		errorMessage( msg );
		exit( -1 );
	}

	// Do the listen
	if ( listen(sock, 5) != 0 )
	{
		/* Complain, explain, and return */
		char msg[128];
		sprintf( msg, "failed server socket listen [%.64s]\n", 
			 strerror(errno) );
		errorMessage( msg );
		exit( -1 );
	}

	/* Print a log message */
	printf( "Server binding to port [%d], successful ...\n", 
		PROTOCOL_PORT );

	/* Return the file handle */
	return( sock );
}

/**********************************************************************

    Function    : server_accept
    Description : get a new connection on the server socket
    Inputs      : sock - server socket
    Outputs     : file handle if successful, -1 if failure

***********************************************************************/

int server_accept( int sock )
{
	struct sockaddr_in inet;
	unsigned int inet_len = sizeof(inet), nsock;

	// Do the accept
	if ( (nsock = accept(sock, (struct sockaddr *)&inet, &inet_len)) == 0 )
	{
		/* Complain, explain, and return */
		char msg[128];
		sprintf( msg, "failed server socket accept [%.64s]\n", 
			 strerror(errno) );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return the new socket */
	return( nsock );
}

/**********************************************************************

    Function    : recv_data
    Description : receive data from the socket
    Inputs      : sock - server socket
                  blk - block to put data in
                  sz - maxmimum size of buffer
                  minsz - minimum bytes to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int recv_data( int sock, char *blk, int sz, int minsz )
{
	/* Keep reading until you have enough bytes */
	int rb = 0, ret;
	do 
	{
		/* Receive data from the socket */
		if ( (ret=recv(sock, &blk[rb], sz-rb, 0)) == -1 )
		{
			/* Complain, explain, and return */
			char msg[128];
			sprintf( msg, "failed read error [%.64s]\n", 
				 strerror(errno) );
			errorMessage( msg );
			exit( -1 );
		}

		/* Increment read bytes */
		rb += ret;
	}
	while ( rb < minsz );

	/* Return the new socket */
	/*printBuffer( "recv data : ", blk, sz );*/
	return( 0 );
}

/**********************************************************************

    Function    : send_data
    Description : send  data to the socket
    Inputs      : sock - server socket
                  blk - block to send
                  len - length of data to send
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int send_data( int sock, char *blk, int len )
{
	/* Send data using the socket */
	if ( send(sock, blk, len, 0) != len )
	{
		/* Complain, explain, and return */
		errorMessage( "Here, failed socket send [short send]\n" );
		printf("Val:%d\n",send(sock,blk,len,0));
		printf("Oh dear, something went wrong with read()! %s\n", strerror(errno));
		exit( -1 );
	}

	/*printBuffer( "sent data : ", blk, len );*/ 

	return( 0 );
}
