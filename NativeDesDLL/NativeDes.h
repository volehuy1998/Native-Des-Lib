// MathLibrary.h - Contains declarations of math functions
#pragma once

#include <stdio.h>
#include <openssl/des.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef DESLIBRARY_EXPORTS
#define DESLIBRARY_API __declspec(dllexport)
#else
#define DESLIBRARY_API __declspec(dllimport)
#endif

//extern "C" DESLIBRARY_API void DES_CBC();
//extern "C" DESLIBRARY_API void DES_ECB();

union _DES_cblock
{
	DES_cblock des_block;
	unsigned long long des_ull;
};

/*
	Get random key type DES_cblock
 */
extern "C" DESLIBRARY_API unsigned long long des_random_key();

/*
	Encrypt/decrypt with key type DES_cblock
 */
extern "C" DESLIBRARY_API int perform(unsigned char* input, int input_len, unsigned long long des_key, unsigned long long des_iv, unsigned char* output, int* output_len, 
	int operate_mode, int crypto_category, int crypto_mode, unsigned long* error);

/*
	Encrypt/decrypt with key which as human message will be converted to key type DES_cbblock
 */
extern "C" DESLIBRARY_API int des_ecb_with_str_key(unsigned char* input, int input_len, const char* str_key, unsigned char* output, int* output_len, int des_operate_mode, unsigned long* error);

/*
	Check key weak or parity bit
*/
extern "C" DESLIBRARY_API int des_check_key(unsigned long long des_key);