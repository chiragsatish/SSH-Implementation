#ifndef CSE543_PROTO_INCLUDED

/**********************************************************************

   File          : cse543-proto.h

   Description   : This file contains the DH protocol definitions and
                   functions.

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

/* Defines */
#define MAX_BLOCK_SIZE 8096
#define BLOCKSIZE 128
#define KEYSIZE 32
#define TAGSIZE 16
#define PUBKEY_FILE "./pubkey.tmp" 

/* command and type */
#define CMD_CREATE 1
#define TYP_DATA_SHARED 1

/* Data Structures */

/* This is the message type */
typedef enum {
     CLIENT_INIT_EXCHANGE,   /* message 1 - start exchange */
     SERVER_INIT_RESPONSE,   /* message 2 - server response */ 
     CLIENT_INIT_ACK,        /* message 3 - client completed ack */
     SERVER_INIT_ACK,        /* message 4 - server ack */
     FILE_XFER_INIT,         /* initialize transfer */
     FILE_XFER_BLOCK,        /* transfer file block */
     EXIT,                   /* exit the protocol */
} ProtoMessageType;

/* This is the message header */
typedef struct {
     unsigned int    msgtype;  /* message type */
     unsigned int    length;   /* message length */
} ProtoMessageHdr;

/* Command header */
struct rm_cmd {
	char cmd;
	char type;
	unsigned short len;
	char fname[0];
};


/* Functional Prototypes */

/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
extern int client_secure_transfer( struct rm_cmd *r, char *fname, char *address );

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
extern int server_secure_transfer( char *privfile, char *pubfile );

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
extern int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type );


#define CSE543_PROTO_INCLUDED
#endif
