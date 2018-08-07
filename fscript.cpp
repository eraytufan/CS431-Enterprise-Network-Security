#include "fscrypt.h"
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include "openssl/blowfish.h"

using namespace std;



void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
	char iv[]="00000000";
	BF_KEY key;
	unsigned char *result = (unsigned char *)malloc(bufsize * sizeof(char));
	BF_set_key(&key, 16, (const unsigned char *)keystr);
	unsigned char array[bufsize];
    unsigned char *final_text = result;
	unsigned char * mytext=(unsigned char *) plaintext; 

 	
    //do xor
    int i = 0;
    while(i<8){
		array[i]=(*mytext) ^ iv[i];  
		mytext = mytext + 1;
		i = i + 1;
	
	}
	
	i = 0;	
	bufsize = bufsize - 8;
	BF_ecb_encrypt(&array[i], result, &key, BF_ENCRYPT);
	int j = 8;

	while(bufsize > 0){
		int counter = 0;
		while(counter < 8){
			array[j++]= (*result) ^ (*mytext); 
			result = result + 1;
			mytext = mytext + 1; 
			counter = counter + 1;
 		}
		i=i+8;  	
		BF_ecb_encrypt(&array[i], result, &key, BF_ENCRYPT);
	  	bufsize = bufsize - 8;
	}
	
    //return result
	*resultlen=strlen((const char *)final_text);
	return (void *) final_text;
	
}
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	char iv[]="00000000";
	BF_KEY key;
	BF_set_key(&key, 16, (const unsigned char *)keystr);
	unsigned char *result = (unsigned char *)malloc(bufsize * sizeof(char));
    unsigned char myChar[bufsize+1];
	unsigned char *p = myChar;
    unsigned char *text = (unsigned char *) ciphertext;
	
 
   	   	          
    BF_ecb_encrypt(text, result, &key, BF_DECRYPT);

    //do xor
    int counter = 0;
    while(counter < 8){
      	myChar[counter]= (*result)^iv[counter]; 
	  	result = result + 1;
	  	counter = counter + 1;        
	}

 	unsigned char *mytext=(unsigned char *) ciphertext;
 	int i=8; 
 	bufsize = bufsize - 8;
 	while(bufsize>0){              
		text = text + 8;
		BF_ecb_encrypt(text, result, &key, BF_DECRYPT);
		int counter = 0;
       	while(counter<8){
      		myChar[i]=(*mytext) ^ (*result);
	  		result = result + 1;
	  		mytext = mytext + 1;
	  		i = i + 1;
	  		counter = counter + 1;
        }  
		bufsize = bufsize - 8;
	}
	//return result
 	*resultlen=strlen((const char*) myChar) + 1;
	return (void *) p;
}


