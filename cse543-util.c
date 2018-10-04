
/**********************************************************************

   File          : cse543-util.c

   Description   : This is a set of utility functions.

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
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cse543-util.h"

/* Functions */

/**********************************************************************

    Function    : errorMessage
    Description : prints an error mesage to stderr
    Inputs      : msg - pointer to string message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int errorMessage( char *msg ) 
{
	/* Print message and return */
	fprintf( stderr, "CSE543 Error: %s\n", msg );
	return( 0 );
}

/**********************************************************************

    Function    : warningMessage
    Description : prints an warning mesage to stderr
    Inputs      : msg - pointer to string message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int warningMessage( char *msg ) 
{
	/* Print message and return */
	fprintf( stderr, "CSE543 Warning: %s\n", msg );
	return( 0 );
}


/**********************************************************************

    Function    : printBuffer
    Description : prints buffer to stdout
    Inputs      : msg - header message
                  buf - the buffer
                  len - the length of the buffer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

void printBuffer( char *msg, char *buf, int len )
{
	/* Print message and return */
	int i;
	if ( msg != NULL ) printf( "%s : ", msg );
	if ( buf != NULL )
	{
		for ( i=0; i<len; i++ ) 
		{
			printf( "%2X ", (unsigned char)buf[i] );
		}
	}
	else
	{
		printf( "(null)" );
	}
	printf( "\n" );
	return;
}


/**********************************************************************

    Function    : buffer_from_file
    Description : reads file into buffer allocated to hold all file data
    Inputs      : filepath - location of file
                  buf - pointer to buffer to be allocated
    Outputs     : Number of bytes read 

***********************************************************************/


unsigned int buffer_from_file(char *filepath, unsigned char **buf)
{
	int err;
	struct stat *statbuf;
	FILE *fptr;
	size_t filesize;

	statbuf = (struct stat *)malloc(sizeof(struct stat));
	assert( statbuf != NULL );

	err = stat( filepath, statbuf );

	/* if file does not exist ... */
	if ( err != 0 ) {
		filesize = 0;
	}
	/* if file is there but empty */
	else if (!( filesize = statbuf->st_size ));
	/* else if file exists */
	else {
		/* Get file size */
		assert( filesize > 0 );

		/* Read file data into buf */
		*buf = (unsigned char *)malloc(filesize); 
		assert( *buf != NULL );
  
		fptr = fopen( filepath, "r" );
		if ( fptr != NULL ) {
			err = fread( *buf, 1, filesize, fptr );
			assert( err == filesize ); 
		}
		fclose( fptr );
	}

	free( statbuf );
  
	return filesize;
}


