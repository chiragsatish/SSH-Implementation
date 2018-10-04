# SSH-Implementation
Implementation of SSH protocol to ensure secure file transfer between client and server.
# File Description
cse543-network.c, cse543-network.h: Takes care of networking between client and server. <br /><br />
cse543-p1.c: Contains the main function <br /><br />
cse543-proto.c, cse543-proto.h: Implements the SSH protocol <br /><br />
cse543-ssl.c, cse543-ssl.h: Performs cryptographic operations as required by the SSH protocol <br /><br />
cse543-util.c, cse543-util.h: Contains utility functions <br /><br />
SSH_Specification.pdf: Describes the protocol as implemented <br /><br />
I have only contributed to "cse543-proto.c and cse543-ssl.c". The other files have been developed by PSU. Please refer to the copyrights which can be found at the beginning of the files <br /><br />
# Key Generation
1. generate key pair - mykey.pem holds private key <br /> 
openssl genrsa -out mykey.pem 2048<br />
2. extract public key in basic format - pubkey.pem is in PKCS#8 format<br />
openssl rsa -in mykey.pem -pubout -out pubkey.pem<br />
3. convert public key to RSA format - rsapub.pem holds public key<br />
openssl rsa -pubin -in pubkey.pem -RSAPublicKey_out > rsapub.pem
# Execution
After make, start the server first, followed by the client <br />
Server: cse543-p1-server \<private-key-file> \<public-key-file> <br />
Client: cse543-p1 \<file-to-transfer> \<server-ip-address> 1 1
# Result
The file sent by the client is recieved by the server and stored in ./shared/\<file-to-transfer>
