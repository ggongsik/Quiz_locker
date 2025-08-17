#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 output size in bytes

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
// 'WORD' -> 'SHA256_WORD'로 이름 변경하여 windows.h와의 충돌 해결
typedef unsigned int  SHA256_WORD;      // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	SHA256_WORD datalen;
	unsigned long long bitlen;
	SHA256_WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

// Helper function to hash a string directly
void sha256_string(const char* str, BYTE hash[SHA256_BLOCK_SIZE]);

#endif   // SHA256_H
