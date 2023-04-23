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
// BN_CTX *bn_ctx;
// bn_ctx = BN_CTX_new();

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
//  eckey_DSA = EC_KEY_new_by_curve_name(NID_secp192k1);
//  eckey_DH = EC_KEY_new_by_curve_name(NID_secp192k1);

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
void Send_via_ZMQ(unsigned char send1[], int sendlen1, unsigned char send2[], int sendlen2) {
    void *context = zmq_ctx_new();
    void *requester = zmq_socket(context, ZMQ_REQ);
    printf("Connecting to Bob and sending the messages...\n");
    zmq_connect(requester, "tcp://localhost:5555");
    zmq_send(requester, send1, sendlen1, ZMQ_SNDMORE);
    zmq_send(requester, send2, sendlen2, 0);
    zmq_close(requester);
    zmq_ctx_destroy(context);
}

/*============================
        Receiving via ZeroMQ 
==============================*/
void Receive_via_ZMQ(unsigned char *receive1, int *receivelen1, unsigned char *receive2, int *receivelen2, int limit) {
    void *context = zmq_ctx_new();
    void *responder = zmq_socket(context, ZMQ_REP);
    int rc = zmq_bind(responder, "tcp://*:5555");
    int received_length1 = zmq_recv(responder, receive1, limit, 0);
    *receivelen1 = received_length1;
    int received_length2 = zmq_recv(responder, receive2, limit, 0);
    *receivelen2 = received_length2;
    zmq_close(responder);
    zmq_ctx_destroy(context);
}

void Save_Signature(char filename[], unsigned char sig[], int sig_len) {
    char sig_hex[2 * sig_len + 1];
    Convert_to_Hex(sig_hex, sig, sig_len);
    Write_File(filename, sig_hex);
}

void Convert_Hex_to_Point(char hex[], EC_POINT *point, const EC_GROUP *group) {
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_hex2point(group, hex, point, ctx);
    BN_CTX_free(ctx);
}

void Save_DH_Key_Agreement(char filename[], EC_POINT *point, const EC_GROUP *group) {
    char *hex = EC_POINT_point2hex(group, point, EC_GROUP_get_point_conversion_form(group), NULL);
    Write_File(filename, hex);
    OPENSSL_free(hex);
}

/*************************************************************
						M A I N
**************************************************************/
int main (int argc, char* argv[])
{   

    // 1. Bob reads all his keys (ECDSA and ECDH keys) from the files
    int fileLen;
    char *bob_dsa_sk_hex = Read_File("test/Bob_DSA_SK.txt", &fileLen);
    char *bob_dsa_pk_hex = Read_File("test/Bob_DSA_PK.txt", &fileLen);
    char *bob_dh_sk_hex = Read_File("test/Bob_DH_SK.txt", &fileLen);
    char *bob_dh_pk_hex = Read_File("test/Bob_DH_PK.txt", &fileLen);

    // Load ECDSA keys
    EC_KEY *bob_dsa = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *dsa_sk_bn = BN_new();
    BN_hex2bn(&dsa_sk_bn, bob_dsa_sk_hex);
    EC_KEY_set_private_key(bob_dsa, dsa_sk_bn);

    EC_POINT *dsa_pk_point = EC_POINT_new(EC_KEY_get0_group(bob_dsa));
    EC_POINT_hex2point(EC_KEY_get0_group(bob_dsa), bob_dsa_pk_hex, dsa_pk_point, NULL);
    EC_KEY_set_public_key(bob_dsa, dsa_pk_point);

    // Load ECDH keys
    EC_KEY *bob_dh = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *dh_sk_bn = BN_new();
    BN_hex2bn(&dh_sk_bn, bob_dh_sk_hex);
    EC_KEY_set_private_key(bob_dh, dh_sk_bn);

    EC_POINT *dh_pk_point = EC_POINT_new(EC_KEY_get0_group(bob_dh));
    EC_POINT_hex2point(EC_KEY_get0_group(bob_dh), bob_dh_pk_hex, dh_pk_point, NULL);
    EC_KEY_set_public_key(bob_dh, dh_pk_point);
    
    // 2. Bob reads Alice's ECDSA public key from the files
    char *alice_dsa_pk_hex = Read_File("test/Alice_DSA_PK.txt", &fileLen);
    EC_KEY *alice_dsa_pk = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_POINT *alice_dsa_pk_point = EC_POINT_new(EC_KEY_get0_group(alice_dsa_pk));
    EC_POINT_hex2point(EC_KEY_get0_group(alice_dsa_pk), alice_dsa_pk_hex, alice_dsa_pk_point, NULL);
    EC_KEY_set_public_key(alice_dsa_pk, alice_dsa_pk_point);

    // 3. Sign Bob's ECDH public key
    unsigned char sig_b[ECDSA_size(bob_dsa)];
    unsigned int sig_b_len;
    int ecdh_pub_b_oct_len = EC_POINT_point2oct(EC_KEY_get0_group(bob_dh), EC_KEY_get0_public_key(bob_dh), EC_KEY_get_conv_form(bob_dh), NULL, 0, NULL);
    unsigned char ecdh_pub_b_oct[ecdh_pub_b_oct_len];
    EC_POINT_point2oct(EC_KEY_get0_group(bob_dh), EC_KEY_get0_public_key(bob_dh), EC_KEY_get_conv_form(bob_dh), ecdh_pub_b_oct, ecdh_pub_b_oct_len, NULL);
    char ecdh_pub_b_hex[2 * ecdh_pub_b_oct_len + 1];
    Convert_to_Hex(ecdh_pub_b_hex, ecdh_pub_b_oct, ecdh_pub_b_oct_len);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(ecdh_pub_b_hex, strlen((const char *)ecdh_pub_b_hex), hash);
    ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig_b, &sig_b_len, bob_dsa);

    // Save Bob's signature to a file
    Save_Signature("Signature_Bob.txt", sig_b, sig_b_len);

    // 4. Send ECDH public key and signature to Alice
    Send_via_ZMQ((unsigned char *)ecdh_pub_b_hex, strlen((const char *)ecdh_pub_b_hex), sig_b, sig_b_len);

    // 5. Receive Alice's ECDH public key and signature
    char ecdh_pub_a_hex[131];
    unsigned char sig_a[ECDSA_size(alice_dsa_pk)];
    int sig_a_len;
    Receive_via_ZMQ((unsigned char *)ecdh_pub_a_hex, &sig_a_len, sig_a, &sig_a_len, 131);
    ecdh_pub_a_hex[130] = '\0';

    // 5. Verify Alice's signature on her ECDH public key
    unsigned char hash_a[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)ecdh_pub_a_hex, strlen(ecdh_pub_a_hex), hash_a);
    int verification_result = ECDSA_verify(0, hash_a, SHA256_DIGEST_LENGTH, sig_a, sig_a_len, alice_dsa_pk);

    // Save verification result to a file
    if (verification_result == 1) {
        Write_File("Verification_Result_Bob.txt", "Successful Verification on Bob Side\n");
    } else {
        Write_File("Verification_Result_Bob.txt", "Verification Failed on Bob Side\n");
        return 0;
    }

    // 6. If the signature is verified, then Alice continues. Otherwise, it aborts.
    EC_POINT *Q_A = EC_POINT_new(EC_KEY_get0_group(bob_dh));
    Convert_Hex_to_Point(ecdh_pub_a_hex, Q_A, EC_KEY_get0_group(bob_dh));

    EC_POINT *K_AB_B = EC_POINT_new(EC_KEY_get0_group(bob_dh));
    if (!EC_POINT_mul(EC_KEY_get0_group(bob_dh), K_AB_B, NULL, Q_A, EC_KEY_get0_private_key(bob_dh), NULL)) {
        printf("Error in ECDH key agreement calculation\n");
        return 1;
    }

    // Save the DH key agreement result
    Save_DH_Key_Agreement("DH_Key_Agreement_Bob.txt", K_AB_B, EC_KEY_get0_group(bob_dh));

    // Clean up
    EC_KEY_free(bob_dsa);
    EC_KEY_free(bob_dh);
    EC_KEY_free(alice_dsa_pk);
    EC_POINT_free(Q_A);
    EC_POINT_free(K_AB_B);
    zmq_close(socket);
    zmq_ctx_destroy(context);

    return 0;
}
//__________________________________________________________________________________________________________________________