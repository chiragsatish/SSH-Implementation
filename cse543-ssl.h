/* Library use functions */
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
		   int aad_len, unsigned char *key, unsigned char *iv,
		   unsigned char *ciphertext, unsigned char *tag);
extern int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
		   int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
		   unsigned char *plaintext);
extern void digest_message(const unsigned char *message, size_t message_len, 
		    unsigned char **digest, unsigned int *digest_len);
extern int hmac_message(unsigned char* msg, size_t mlen, unsigned char** val, size_t* vlen, 
			 unsigned char *key);
extern int rsa_encrypt(unsigned char *msg, unsigned int msgLen, unsigned char **encMsg, unsigned char **ek,
		       unsigned int *ekl, unsigned char **iv, unsigned int *ivl, EVP_PKEY *pubkey);
extern int rsa_decrypt(unsigned char *encMsg, unsigned int encMsgLen, unsigned char *ek, unsigned int ekl,
		       unsigned char *iv, unsigned int ivl, unsigned char **decMsg, EVP_PKEY *privkey); 
extern ENGINE *engine_init( void );
extern int engine_cleanup( ENGINE *eng );
extern int crypto_init( void );
extern int crypto_cleanup( void );
extern void handleErrors(void);
