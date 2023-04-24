/**************************
 *      Homework 5        *
 ************************** 
 *
 *Compile:          gcc alice.c -lssl -lcrypto -lzmq -o alice
 *                  gcc bob.c -lssl -lcrypto -lzmq -o bob
 * 
 *Run:              ./alice Alice_DSA_SK.txt Alice_DSA_PK.txt Alice_DH_SK.txt Alice_DH_PK.txt Bob_DSA_PK.txt
 *                  ./bob Bob_DSA_SK.txt Bob_DSA_PK.txt Bob_DH_SK.txt Bob_DH_PK.txt Alice_DSA_PK.txt
 *
 *Documentation:    SSL Documentation: https://www.openssl.org/docs/manmaster/man3/
 *
 *   OpenSSL Doc on SHA256: https:  //www.openssl.org/docs/manmaster/man3/SHA256.html
 *   OpenSSL Doc on BN Context: https:   //www.openssl.org/docs/manmaster/man3/BN_CTX_new_ex.html
 *   OpenSSL Doc on BIGNUM conversions:  https://www.openssl.org/docs/manmaster/man3/BN_hex2bn.html
 *   OpenSSL Doc on ECDSA_SIG:  https://www.openssl.org/docs/manmaster/man3/ECDSA_sign.html
 *   OpenSSL Doc on EC_GROUP:  https://www.openssl.org/docs/manmaster/man3/EC_GROUP_get_point_conversion_form.html
 *   OpenSSL Doc on EC_KEY: https://www.openssl.org/docs/manmaster/man3/EC_KEY_get0_private_key.html
 *   OpenSSL Doc on EC_POINT: https://www.openssl.org/docs/manmaster/man3/EC_POINT_bn2point.html
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/

//Header Files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <zmq.h>

/*************************************************************
					F u n c t i o n s
**************************************************************/

/*******************************
        BIGNUM Functions
********************************/
/*================================
    Creating Context for BIGNUM
==================================*/
//BN_CTX *bn_ctx;
//bn_ctx = BN_CTX_new();

/*============================
    Convert BIGNUM to HEX
==============================*/
char *BN_bn2hex(const BIGNUM *a);

/*============================
    Convert HEX to BIGNUM
==============================*/
int BN_hex2bn(BIGNUM **a, const char *str);

//==============================================================================================================================

/*******************************
      EC_POINT Functions
********************************/
/*==============================================
    Creating EC_POINT and Freeing it at the end
================================================*/
EC_POINT *EC_POINT_new(const EC_GROUP *group);
void EC_POINT_free(EC_POINT *point);

/*==============================================
    Getting the conversion form from group
================================================*/
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *group);

/*============================
    Convert EC_POINT to HEX
==============================*/
char *EC_POINT_point2hex(const EC_GROUP *group, const EC_POINT *p, point_conversion_form_t form, BN_CTX *ctx);

/*============================
    Convert HEX to EC point
==============================*/
EC_POINT *EC_POINT_hex2point(const EC_GROUP *group, const char *hex, EC_POINT *p, BN_CTX *ctx);

/*============================
    EC Point Multiplication
==============================*/
/*--- Description:
*   EC_POINT_mul calculates the value generator * n + q * m and stores the result in r. 
*   The value n may be NULL in which case the result is just q * m (variable point multiplication). 
*   Alternatively, both q and m may be NULL, and n non-NULL, in which case the result is 
*   just generator * n (fixed point multiplication). When performing a single fixed or 
*   variable point multiplication, the underlying implementation uses a constant time algorithm, 
*   when the input scalar (either n or m) is in the range [0, ec_group_order).
*/
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

//==============================================================================================================================

/*******************************
      EC_KEY Functions
********************************/
/*============================
    EC_KEY creation
==============================*/
/*--- Description:
*   A new EC_KEY can be constructed by calling EC_KEY_new_by_curve_name() and supplying the nid of the associated curve
*   EC_KEY_new_by_curve_name() returns a pointer to the newly created EC_KEY object, or NULL on error.
*/
EC_KEY *EC_KEY_new_by_curve_name(int nid);
 //For DSA and DH, use the following curve:
 //eckey_DSA = EC_KEY_new_by_curve_name(NID_secp192k1);
 //eckey_DH = EC_KEY_new_by_curve_name(NID_secp192k1);

 /*================================
    Getting the group from EC_KEY
===================================*/
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);

 /*========================================
    Getting the convert_form from EC_KEY
===========================================*/
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);

/*============================
    EC_KEY setting SK
==============================*/
/*--- Description:
*   EC_KEY_set_private_key() returns 1 on success or 0 on error except when 
*   the priv_key argument is NULL, in that case it returns 0, for legacy compatibility, 
*   and should not be treated as an error.
*/
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key);

/*============================
    EC_KEY setting PK
==============================*/
/*--- Description:
*   EC_KEY_set_public_key() returns 1 on success or 0 on error.
*/
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

//==============================================================================================================================

/*============================
            E C D S A
==============================
*  OpenSSL Website that has example on ECDSA 
*  https://www.openssl.org/docs/manmaster/man3/ECDSA_do_sign_ex.html
*/

/*============================
    SHA256 Hash Function
==============================*/
/*--- Description:
*   SHA256() computes the SHA-256 message digest of the "count" bytes at data and places it in md.
*   SHA256() returns a pointer to the hash value.
*/
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);

/*============================
        ECDSA Signature Size
==============================*/
/*--- Description:
*   ECDSA_size() returns the maximum length of a DER encoded ECDSA signature created with the private EC key eckey
*   ECDSA_size() returns the maximum length signature or 0 on error.
*/
int ECDSA_size(const EC_KEY *eckey);

/*============================
        ECDSA Signature
==============================*/
/*--- Description:
*   ECDSA_sign() computes a digital signature of the dgstlen bytes hash value dgst 
*   using the private EC key eckey. The DER encoded signatures is stored in sig and 
*   its length is returned in sig_len. Note: sig must point to ECDSA_size(eckey) bytes of memory. 
*   The parameter type is currently ignored. 
*   ECDSA_sign() returns 1 if successful or 0 on error.
*/
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*============================
        ECDSA Verification
==============================*/
/*--- Description:
*   ECDSA_verify() verifies that the signature in sig of size siglen is a valid ECDSA signature 
*   of the hash value dgst of size dgstlen using the public key eckey. The parameter type is ignored.
*   ECDSA_verify() returns 1 for a valid signature, 0 for an invalid signature and -1 on error. 
*/
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *eckey);

//==============================================================================================================================
//==============================================================================================================================

/*============================
        Read from File
==============================*/
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
	return output;
}

/*============================
        Write to File
==============================*/
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
/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

/*============================
        Convert to Hex 
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}

/*============================
        Sending via ZeroMQ 
==============================*/
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

/*============================
        Receiving via ZeroMQ 
==============================*/
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

/*************************************************************
						M A I N
**************************************************************/

int main(int argc,char *argv[]){

    //BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM * A = BN_new();
    BIGNUM * Y = BN_new();
    EC_KEY *eckey_DSA = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_KEY *eckey_DH = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_GROUP * DSA_G = EC_KEY_get0_group(eckey_DSA);
    EC_GROUP * DH_G = EC_KEY_get0_group(eckey_DH);

    EC_POINT * ecdsaPubKeyPoint = EC_POINT_new(DSA_G);
    EC_POINT * ecdhPubKeyPoint = EC_POINT_new(DH_G);
    EC_POINT * comPairPubKeyPoint = EC_POINT_new(DSA_G);


    // 1. Alice reads all her keys (ECDSA and ECDH keys) from the files
    int fileLen_Alice_DH_SK, fileLen_Alice_DH_PK, fileLen_Alice_DSA_SK, fileLen_Alice_DSA_PK;

    unsigned char * Alice_DH_SK_hex = Read_File(argv[3], &fileLen_Alice_DH_SK);
    unsigned char * Alice_DH_PK = Read_File(argv[4], &fileLen_Alice_DH_PK);
    unsigned char * Alice_DSA_SK = Read_File(argv[1], &fileLen_Alice_DSA_SK);
    unsigned char * Alice_DSA_PK = Read_File(argv[2], &fileLen_Alice_DSA_PK);

    BN_hex2bn(&A, Alice_DH_SK_hex);
    BN_hex2bn(&Y, Alice_DSA_SK);

    // 2. Alice reads Bob's ECDSA public key from the files
    int fileLen_Bob_DSA_PK;
    unsigned char * Bob_DSA_PK;

    Bob_DSA_PK = Read_File(argv[5], &fileLen_Bob_DSA_PK);


    /* Converting public keys from hex to points */
    ecdsaPubKeyPoint = EC_POINT_hex2point(DSA_G, Alice_DSA_PK, ecdsaPubKeyPoint , NULL);
    comPairPubKeyPoint = EC_POINT_hex2point(DSA_G, Bob_DSA_PK, comPairPubKeyPoint ,NULL);
    ecdhPubKeyPoint = EC_POINT_hex2point(DH_G, Alice_DH_PK, ecdhPubKeyPoint , NULL);

    /* Setting the public and private keys */
    EC_KEY_set_public_key(eckey_DSA,ecdsaPubKeyPoint);
    EC_KEY_set_public_key(eckey_DH,ecdhPubKeyPoint);
    EC_KEY_set_private_key(eckey_DSA, Y);
    EC_KEY_set_private_key(eckey_DH, A);

    /* Computing signature on ECDH public key */
    unsigned int signatureLen = ECDSA_size(eckey_DSA);
    unsigned char * signature = OPENSSL_malloc(signatureLen);
    unsigned char digestBuff[SHA256_DIGEST_LENGTH];
    unsigned char * digest = SHA256(Alice_DH_PK, strlen(Alice_DH_PK), digestBuff);

    /* Signing the ECDH public key using the ECDSA */
    ECDSA_sign(0, digest , SHA256_DIGEST_LENGTH , signature, &signatureLen , eckey_DSA );


    /* Writing the signature to the file */
    unsigned char * signHex = malloc(signatureLen*2+1);
    signHex[signatureLen*2]=0;
    Convert_to_Hex(signHex, signature , signatureLen);
    Write_File("Signature_Alice.txt",signHex);


    /* Sending the ECDH public key and the signature*/
    unsigned char * buffer2send = malloc(fileLen_Alice_DH_PK+signatureLen);
    memcpy(buffer2send,Alice_DH_PK,fileLen_Alice_DH_PK);
    memcpy(buffer2send+fileLen_Alice_DH_PK , signature , signatureLen);
    Send_via_ZMQ(buffer2send,fileLen_Alice_DH_PK+signatureLen);

    unsigned char receivBuff[1000];
    unsigned int recvLen;
    unsigned char * recPacket = Receive_via_ZMQ(receivBuff, &recvLen , 1000);
	
    // Since the signatue length is variable and there is no structure for sending,
    // we use the fact that the public key is constant. 
    unsigned int recvSignatureLen = recvLen - fileLen_Alice_DH_PK;

    unsigned char * recevidPublicKey = malloc(fileLen_Alice_DH_PK);
    unsigned char * receivedSignature = malloc(recvSignatureLen);
    memcpy(recevidPublicKey, recPacket,fileLen_Alice_DH_PK);
    memcpy(receivedSignature , recPacket + fileLen_Alice_DH_PK, recvSignatureLen);


    /* Verifying */
    digest = SHA256(recevidPublicKey,fileLen_Alice_DH_PK, digestBuff);

    /* Verification is done via the Bob's public key */
    EC_KEY_set_public_key(eckey_DSA, comPairPubKeyPoint);


    if (ECDSA_verify(0, digest , SHA256_DIGEST_LENGTH , receivedSignature, recvSignatureLen , eckey_DSA)==1){

        Write_File("Verification_Result_Alice.txt","Successful Verification on Alice Side");

        /* Creating DH key agreement */

        /* Converting the received public key to a point */
        BN_CTX * comPairRecvPubKeyCtx = BN_CTX_new();
        comPairPubKeyPoint = EC_POINT_hex2point(DSA_G,recevidPublicKey, comPairPubKeyPoint ,NULL);
        EC_POINT * multPoint = EC_POINT_new(DH_G) ; 
        EC_POINT_mul(DH_G, multPoint , NULL, comPairPubKeyPoint, A, NULL);

        /* Converting the received public key to a point */
        unsigned char * dhKeyAgreement = EC_POINT_point2hex(DH_G, multPoint, POINT_CONVERSION_UNCOMPRESSED, NULL); 
        Write_File("DH_Key_Agreement_Alice.txt",dhKeyAgreement);
    }
    else {
        Write_File("Verification_Result_Alice.txt","Verification Failed on Alice Side");
    }

    return 0;
}
//__________________________________________________________________________________________________________________________
