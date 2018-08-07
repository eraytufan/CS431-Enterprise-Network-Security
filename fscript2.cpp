#include <stdlib.h>
#include <string.h>
#include <vector>
#include <iostream>
#include "fscrypt.h"
#include "openssl/blowfish.h"


using namespace std;


void* fs_encrypt(void* plaintext, int bufsize, char* keystr, int *resultlen){
    BF_KEY mykey;
    
    unsigned char iv[9]="0";
    unsigned char * text=(unsigned char *) plaintext; 
    BF_set_key(&mykey, 16, (const unsigned char *)keystr);
    unsigned char *result = (unsigned char *)malloc(bufsize * sizeof(char));
    unsigned char *internalcipher = result; 
    BF_cbc_encrypt(text, result, bufsize, &mykey, iv, BF_ENCRYPT);
    *resultlen=strlen((const char *)result);
    return (void *) result;
}

void* fs_decrypt(void* ciphertext, int bufsize, char* keystr, int* resultlen){
    BF_KEY mykey;
    unsigned char *result = (unsigned char *)malloc(bufsize * sizeof(char));
    unsigned char *text=(unsigned char*) ciphertext;
    unsigned char *finalplain = result;    
    unsigned char iv[9]="0";    
    BF_set_key(&mykey, 16, (const unsigned char *)keystr);
    BF_cbc_encrypt(text, result, bufsize, &mykey, iv, BF_DECRYPT);      
    *resultlen=strlen((const char*) result) + 1;
    return (void *) result;
}
