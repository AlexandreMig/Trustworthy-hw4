#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <zmq.h>
#include <sys/stat.h>
#include <sys/types.h>


typedef unsigned char u8;
typedef unsigned int u32;




/* Function prototypes */
char* Read_File (char fileName[], int *fileLen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Write_File(char fileName[], char input[]);
void Send_via_ZMQ(unsigned char send[], int sendlen);
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit);



int main(int argc,char **argv){


	/* Parameters */
	u8 * ecdhPrivKey;
	u32 ecdhPrivKeySize;
	u8 * ecdhPubKey;
	u32 ecdhPubKeySize;

	u8 * ecdsaPrivKey;
	u32 ecdsaPrivKeySize;
	u8 * ecdsaPubKey;
	u32 ecdsaPubKeySize;

	/* comPairPubKey is the Bob's ECDSA public key which is read from the file */
	u8 * comPairPubKey;
	u32 comPairPubKeySize;



	/* Reading the keys from the files */
	ecdhPrivKey = Read_File(argv[3],&ecdhPrivKeySize);
	ecdhPubKey = Read_File(argv[4],&ecdhPubKeySize);
	ecdsaPrivKey = Read_File(argv[1],&ecdsaPrivKeySize);
	ecdsaPubKey = Read_File(argv[2],&ecdsaPubKeySize);
	comPairPubKey = Read_File(argv[5],&comPairPubKeySize);

	/* Creating the keys for DH and ECDSA */
	EC_KEY * ecdsaKey = EC_KEY_new_by_curve_name(NID_secp192k1);
	EC_KEY * dhKey = EC_KEY_new_by_curve_name(NID_secp192k1);

	/* Getting the groups of the generated keys */
	EC_GROUP * ecdsaKeyGroup = EC_KEY_get0_group(ecdsaKey);
	EC_GROUP * dhKeyGroup = EC_KEY_get0_group(dhKey);

	/* Converting private keys from hex to bignums */
	BIGNUM * ecdhPrivBigNum = BN_new();
	BIGNUM * ecdsaPrivBigNum = BN_new();
	BN_hex2bn(&ecdhPrivBigNum,ecdhPrivKey);
	BN_hex2bn(&ecdsaPrivBigNum,ecdsaPrivKey);
	
	/* Generating points for the public keys */
	EC_POINT * ecdsaPubKeyPoint = EC_POINT_new(ecdsaKeyGroup);
	EC_POINT * ecdhPubKeyPoint = EC_POINT_new(dhKeyGroup);
	EC_POINT * comPairPubKeyPoint = EC_POINT_new(ecdsaKeyGroup);

	/* Converting public keys from hex to points */
	ecdsaPubKeyPoint = EC_POINT_hex2point(ecdsaKeyGroup,ecdsaPubKey, ecdsaPubKeyPoint , NULL);
	comPairPubKeyPoint = EC_POINT_hex2point(ecdsaKeyGroup,comPairPubKey, comPairPubKeyPoint ,NULL);
	ecdhPubKeyPoint = EC_POINT_hex2point(dhKeyGroup,ecdhPubKey, ecdhPubKeyPoint , NULL);

	/* Setting the public and private keys */
	EC_KEY_set_public_key(ecdsaKey,ecdsaPubKeyPoint);
	EC_KEY_set_public_key(dhKey,ecdhPubKeyPoint);
	EC_KEY_set_private_key(ecdsaKey,ecdsaPrivBigNum);
	EC_KEY_set_private_key(dhKey,ecdhPrivBigNum);


	/*


			Signature operations


	*/

	/* Computing signature on ECDH public key */
	u32 signatureLen = ECDSA_size(ecdsaKey);
	u8 * signature = OPENSSL_malloc(signatureLen);
	u8 digestBuff[SHA256_DIGEST_LENGTH];
	u8 * digest = SHA256(ecdhPubKey,strlen(ecdhPubKey), digestBuff);

	/* Signing the ECDH public key using the ECDSA */
	ECDSA_sign(0, digest , SHA256_DIGEST_LENGTH , signature, &signatureLen , ecdsaKey );


	/* Writing the signature to the file */
	u8 * signHex = malloc(signatureLen*2+1);
	signHex[signatureLen*2]=0;
	Convert_to_Hex(signHex, signature , signatureLen);
	Write_File("Signature_Alice.txt",signHex);



	/*
	
		Network operations

	*/

	/* Sending the ECDH public key and the signature*/
	u8 * buffer2send = malloc(ecdhPubKeySize+signatureLen);
	memcpy(buffer2send,ecdhPubKey,ecdhPubKeySize);
	memcpy(buffer2send+ecdhPubKeySize , signature , signatureLen);
	Send_via_ZMQ(buffer2send,ecdhPubKeySize+signatureLen);


	/* Receiving */

	u8 receivBuff[1000];
	u32 recvLen;
    u8 * recPacket = Receive_via_ZMQ(receivBuff, &recvLen , 1000);
	
    // Since the signatue length is variable and there is no structure for sending,
    // we use the fact that the public key is constant. 
	u32 recvSignatureLen = recvLen - ecdhPubKeySize;

    u8 * recevidPublicKey = malloc(ecdhPubKeySize);
    u8 * receivedSignature = malloc(recvSignatureLen);
    memcpy(recevidPublicKey, recPacket,ecdhPubKeySize);
	memcpy(receivedSignature , recPacket + ecdhPubKeySize, recvSignatureLen);


	/* Verifying */
	digest = SHA256(recevidPublicKey,ecdhPubKeySize, digestBuff);

	/* Verification is done via the Bob's public key */
	EC_KEY_set_public_key(ecdsaKey,comPairPubKeyPoint);


	if (ECDSA_verify(0, digest , SHA256_DIGEST_LENGTH , receivedSignature, recvSignatureLen , ecdsaKey )==1){

		Write_File("Verification_Result_Alice.txt","Successful Verification on Alice Side");

		/* Creating DH key agreement */
	
		/* Converting the received public key to a point */
		BN_CTX * comPairRecvPubKeyCtx = BN_CTX_new();
		comPairPubKeyPoint = EC_POINT_hex2point(ecdsaKeyGroup,recevidPublicKey, comPairPubKeyPoint ,NULL);
		EC_POINT * multPoint = EC_POINT_new(dhKeyGroup) ; 
		EC_POINT_mul(dhKeyGroup, multPoint , NULL, comPairPubKeyPoint, ecdhPrivBigNum , NULL);

		/* Converting the received public key to a point */
		u8 * dhKeyAgreement = EC_POINT_point2hex(dhKeyGroup, multPoint, POINT_CONVERSION_UNCOMPRESSED, NULL); 
		Write_File("DH_Key_Agreement_Alice.txt",dhKeyAgreement);
	}
	else
		Write_File("Verification_Result_Alice.txt","Verification Failed on Alice Side");

	
}





char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    char *output = (char*) malloc(temp_size);

	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;

    // output[*fileLen]=0;
	return output;
}


void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}


void Write_File(char fileName[], char input[]){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}



void Send_via_ZMQ(unsigned char send[], int sendlen)
{
	void *context = zmq_ctx_new ();					            //creates a socket to talk to Bob
    void *requester = zmq_socket (context, ZMQ_REQ);		    //creates requester that sends the messages
   	printf("Connecting to Bob and sending the message...\n");
    zmq_connect (requester, "tcp://localhost:5555");		    //make outgoing connection from socket
    zmq_send (requester, send, sendlen, 0);			    	    //send msg to Bob
    zmq_close (requester);						                //closes the requester socket
    zmq_ctx_destroy (context);					                //destroys the context & terminates all 0MQ processes
}



unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit) 
{
	void *context = zmq_ctx_new ();			        	                                 //creates a socket to talk to Alice
    void *responder = zmq_socket (context, ZMQ_REP);                                   	//creates responder that receives the messages
   	int rc = zmq_bind (responder, "tcp://*:6666");	                                	//make outgoing connection from socket
    int received_length = zmq_recv (responder, receive, limit, 0);	                  	//receive message from Alice
    unsigned char *temp = (unsigned char*) malloc(received_length);
    for(int i=0; i<received_length; i++){
        temp[i] = receive[i];
    }
    *receivelen = received_length;
    printf("Received Message: %s\n", receive);
    printf("Size is %d\n", received_length);
    return temp;
}