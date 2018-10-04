/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.

   Last Modified : 2018
   By            : Chirag Satish

***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"


/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Get message encrypted (by encrypt) and put ciphertext 
                   and metadata for decryption into buffer
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - place to put ciphertext and metadata for 
                   decryption on other end
                : len - length of the buffer after message is set 
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
	unsigned char *ciphertext, *tag;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0,bufferlen=0;
	ciphertext = (unsigned char *)malloc(plaintext_len);
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( plaintext, plaintext_len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	sprintf(buffer,"%d",clen);
	strcat(buffer," ");
	sprintf(buffer+strlen(buffer),"%lu",strlen(iv));
	strcat(buffer," ");
	bufferlen=strlen(buffer);
	memcpy(buffer+bufferlen,tag,TAGSIZE);
	bufferlen+=TAGSIZE;
	memcpy(buffer+bufferlen,ciphertext,clen);
	bufferlen+=clen;
	memcpy(buffer+bufferlen,iv,strlen(iv));
	*(len)=bufferlen+strlen(iv);
	return 0;
}



/**********************************************************************

    Function    : decrypt_message
    Description : Recover plaintext from ciphertext (by decrypt)
                   using metadata from buffer
    Inputs      : buffer - ciphertext and metadata - in format set by
                   encrypt_message
                : len - length of buffer containing ciphertext and metadata
                : key - symmetric key
                : plaintext - place to put decrypted message
                : plaintext_len - size of decrypted message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
	int plen=0,clen=0,i;
	unsigned long ivl=0;
	unsigned char* tag = (unsigned char *)malloc( TAGSIZE ); 
	unsigned char* ciphertext;
	unsigned char *iv = (unsigned char *)malloc(16);
	for(i=0;i<strlen(buffer);i++){
		if(buffer[i]==' '){
			sscanf(buffer,"%u",&clen);
			buffer+=(i+1);
			break;
		}
	}
	for(i=0;i<strlen(buffer);i++){
		if(buffer[i]==' '){
			sscanf(buffer,"%lu",&ivl);
			buffer+=(i+1);
			break;
		}
	}
	memset( plaintext, 0, clen+TAGSIZE );
	memcpy(tag,buffer,TAGSIZE);
	buffer+=TAGSIZE;
	ciphertext = (unsigned char*)malloc(clen);
	memcpy(ciphertext,buffer,clen);
	buffer+=clen;
	memcpy(iv,buffer,ivl);
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, tag, key, iv, plaintext);
	*(plaintext_len)=plen;
	return 0;
}


/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudorandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
  if(RAND_bytes(buffer,size))
    return 0;
  else
    return -1;
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using OpenSSL public key (call rsa_encrypt)
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted key and 
                     and metadata for decrypting in unseal
    Outputs     : len if successful, -1 if failure

***********************************************************************/

int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;
	int bufferlen=0;
	unsigned char* temp;
    //encrypt
    if((len=rsa_encrypt(key,keylen,&ciphertext, &ek, &ekl, &iv, &ivl, pubkey))!=-1){ 
		buffer = (char*)realloc(buffer,(len+ivl+ekl+sizeof(int)*3+sizeof(long)+10));
		sprintf(buffer,"%u",len);
		strcat(buffer," ");
		sprintf(buffer+strlen(buffer),"%u",ekl);
		strcat(buffer," ");
		sprintf(buffer+strlen(buffer),"%u",ivl);
		strcat(buffer," ");
		bufferlen=strlen(buffer);
		memcpy(buffer+bufferlen,ciphertext,len);
		bufferlen+=len;
		memcpy(buffer+bufferlen,ek,ekl);
		bufferlen+=ekl;
		memcpy(buffer+bufferlen,iv,ivl);
		temp=buffer;
		temp+=bufferlen;
		len+=ekl+ivl+100;
		return len;
	}
    else
		return -1;
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Decrypt symmetric key using OpenSSL private key (call rsa_decrypt)
    Inputs      : buffer - buffer containing the encrypted key and 
                     and metadata for decrypting in format determined
                     in seal_symmetric_key
                  len - length of buffer
                  privkey - private key 
                  key - symmetric key (plaintext from rsa_decrypt)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int unseal_symmetric_key(unsigned char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
   	unsigned char *ciphertext;
	unsigned int seal_len=0;
	unsigned long ciphertextlen;
	unsigned long eksize;
	unsigned long ivsize;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;
	int i;
	for(i=0;i<strlen(buffer);i++){
		if(buffer[i]==' '){
			sscanf(buffer,"%u",&seal_len);
			buffer+=(i+1);
			break;
		}
	}
	for(i=0;i<strlen(buffer);i++){
		if(buffer[i]==' '){
			sscanf(buffer,"%u",&ekl);
			buffer+=(i+1);
			break;
		}
	}
	for(i=0;i<strlen(buffer);i++){
		if(buffer[i]==' '){
			sscanf(buffer,"%u",&ivl);
			buffer+=(i+1);
			break;
		}
	}
	ciphertext = (unsigned char*)calloc(seal_len,sizeof(char));
	ek = (unsigned char*)calloc(ekl,sizeof(char));
	iv = (unsigned char*)calloc(ivl,sizeof(char));
	memcpy(ciphertext,buffer,seal_len);
	buffer+=seal_len;
	memcpy(ek,buffer,ekl);
	buffer+=ekl;
	memcpy(iv,buffer,ivl);
	if(rsa_decrypt(ciphertext,seal_len,ek,ekl,iv,ivl,key,privkey)!=-1){ 
		return 0;
	}
	else
		return -1;
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of your authentication protocol
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int client_authenticate( int sock, unsigned char **session_key )
{
	ProtoMessageHdr *hdr = (ProtoMessageHdr*)malloc(sizeof(ProtoMessageHdr));
	FILE* fp;
	int len=0;
	RSA *rsa_pubkey = NULL;
	EVP_PKEY *pubkey = EVP_PKEY_new();
	*session_key = (unsigned char*)malloc(32);
	int pseudo_random_size = 32;
	unsigned char *pseudo_random_string = (unsigned char*)malloc(pseudo_random_size);
	hdr->msgtype=0;
	hdr->length=1;
	char *block=(char*)malloc(1);
	char* encryptedMsg=(char*)calloc(MAX_BLOCK_SIZE,sizeof(char));
	send_message(sock,hdr,block);
	hdr->msgtype=1;
	block = (char*)malloc(500);
	wait_message(sock,hdr,block,SERVER_INIT_RESPONSE);
	fp = fopen("serverpublickey.pem","w");
	fprintf(fp,"%s",block);	
	fclose(fp);
	fp = fopen("serverpublickey.pem","r");
	assert( fp != NULL);
	if (!PEM_read_RSAPublicKey( fp , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fp );
	if(!generate_pseudorandom_bytes(*session_key,pseudo_random_size)){
		if((len=seal_symmetric_key( *session_key,pseudo_random_size,pubkey,encryptedMsg))!=-1){
			printf("Encrypted Session Key successfully\n");
			hdr->msgtype=2;
			hdr->length=len;
			send_message(sock,hdr,encryptedMsg);
			hdr->msgtype=3;
			wait_message(sock,hdr,block,SERVER_INIT_ACK);
		}
		else
			printf("Session Key Encrypt failed\n");
	}
	else{
		printf("Pseudorandom generate error\n");
		exit(0);
	}
}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh,len=0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];
	/* Read the next block */
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}
	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );
	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			memset(outblock,0,MAX_BLOCK_SIZE);
			if(encrypt_message(block,readBytes,key,outblock,&len)!=-1){
				printf("Encrypted Block successfully\n");
				hdr.msgtype = FILE_XFER_BLOCK;
				hdr.length = len;
				send_message(sock,&hdr,outblock);
				len=0;		
			}
			else
				printf("ENCRYPT FAILED\n");	
		}
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}

/* 

  SERVER FUNCTIONS 

*/


/**********************************************************************

    Function    : server_protocol
    Description : server side of crypto protocol
    Inputs      : sock - server socket
                  pubfile - public key file name
                  privkey - private key value
                  enckey - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

/*** YOUR_CODE ***/
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
	FILE* fp;
	long lSize;
	char* block = (char*)malloc(BLOCKSIZE);
	unsigned char* key;
	unsigned char* sessionkey = (unsigned char*)calloc(32,sizeof(char));
	ProtoMessageHdr *hdr = (ProtoMessageHdr*)malloc(sizeof(ProtoMessageHdr));
	*enckey = (unsigned char*)malloc(32);
	hdr->msgtype=0;
	hdr->length=1;
	wait_message(sock,hdr,block,CLIENT_INIT_EXCHANGE);
	if ( (fp=fopen(pubfile,"rb")) == NULL )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", pubfile );
		errorMessage( msg );
		exit( -1 );
	}	
	fseek( fp , 0L , SEEK_END);
	lSize = ftell( fp );
	rewind( fp );
	block = (char*)realloc(block,lSize+1);
	if( 1!=fread( block , lSize, 1 , fp) )
 		fclose(fp),free(block),fputs("entire read fails",stderr),exit(1);
	hdr->msgtype=1;
	hdr->length=(int)lSize;
	send_message(sock,hdr,block);
	hdr->msgtype=2;
	free(block);
	block=(char*)malloc(MAX_BLOCK_SIZE);
	wait_message(sock,hdr,block,CLIENT_INIT_ACK);
	if(unseal_symmetric_key(block,strlen(block),privkey,&key)!=-1){
		printf("Session Key decryption successful\n");
		memcpy(*enckey,key,32);
		free(key);
		hdr->msgtype=3;
		hdr->length=1;
		free(block);
		block=(char*)malloc(1);
		send_message(sock,hdr,block);
	}
	else{
		printf("Session Key Decryption failed\n");
		exit(0);
	}
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the AES session key used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	char *fname = NULL;
	int rc = 0;
	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );

	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
		if ( (fh=open( fname, O_WRONLY|O_CREAT, 0700)) > 0 );
		else assert( 0 );
	}
	else assert( 0 );
	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				
				//printf("PT\n%s\n",plaintext);				
				//assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}

