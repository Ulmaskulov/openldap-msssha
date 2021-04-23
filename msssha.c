#include "msssha.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <assert.h>
#include <iconv.h>

size_t calcDecodeLength(const char* b64input) {
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=')
		padding = 2;
	else if (b64input[len-1] == '=')
		padding = 1;

	return (len*3)/4 - padding;
}

int Base64Decode(const char* b64message, unsigned char** buffer, size_t* length)
{
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen);
	BIO_free_all(bio);

	return (0);
}

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
    *b64text=(char*)calloc(bufferPtr->length + 1, sizeof(char));
    memcpy(*b64text, bufferPtr->data, bufferPtr->length);
    (*b64text)[bufferPtr->length] = '\0';
	BIO_free_all(bio);

	return (0);
}


char * mssshaFunction(const char * pass, const char * salt)
{
    unsigned char *saltDecoded;
    char *retVal;
    char sha1digest[21] = {0};
    size_t saltLen;
    Base64Decode(salt, &saltDecoded, &saltLen); 
    iconv_t cd = iconv_open("UTF-16LE","ASCII");
    char * utf16le = (char*)calloc(strlen(pass) * 4 + 3, sizeof(char));
    memset(utf16le, 0, strlen(pass) * 4 + 3);
    size_t lenIn = strlen(pass);
    size_t lenOut = lenIn * 4 + 3;
    char *pass_old = pass;
    char *outPtr = utf16le;
    size_t r = iconv(cd, &pass, &lenIn, &outPtr, &lenOut);
    if (r < 0) {
        int e = errno;
        fprintf(stderr, "erorr is %s", strerror(e));
        return NULL;
    }

    lenIn = strlen(pass_old);
    int convertedLen = (lenIn * 4 + 3 - lenOut);
    size_t total_len = saltLen + convertedLen;
    char *composed = (char*) calloc(total_len, sizeof(char));
    memcpy(composed, saltDecoded, saltLen);
    memcpy(composed + saltLen, utf16le, convertedLen);
    free(utf16le);

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, composed, total_len);
    SHA1_Final(sha1digest, &ctx);

    free(composed);
    free(saltDecoded);
    iconv_close(cd);

    Base64Encode(sha1digest, SHA_DIGEST_LENGTH, &retVal);
    return retVal;
}
