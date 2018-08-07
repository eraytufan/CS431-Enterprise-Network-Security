#include "openssl/blowfish.h"

const int BLOCKSIZE = 8;          
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);
