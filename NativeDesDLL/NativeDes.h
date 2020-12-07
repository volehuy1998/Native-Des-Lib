// MathLibrary.h - Contains declarations of math functions
#pragma once

#include <stdio.h>
#include <openssl/des.h>
#include <openssl/crypto.h>

#ifdef DESLIBRARY_EXPORTS
#define DESLIBRARY_API __declspec(dllexport)
#else
#define DESLIBRARY_API __declspec(dllimport)
#endif

//extern "C" DESLIBRARY_API void DES_CBC();
//extern "C" DESLIBRARY_API void DES_ECB();

/*
	Get random key type DES_cblock
 */
extern "C" DESLIBRARY_API unsigned long long des_random_key();

/*
	Encrypt/decrypt with key type DES_cblock
 */
extern "C" DESLIBRARY_API int des_ecb(unsigned char* input, unsigned long long des_key, unsigned char* output, int des_operate_mode);

/*
	Encrypt/decrypt with key which as human message will be converted to key type DES_cbblock
 */
extern "C" DESLIBRARY_API int des_ecb_with_str_key(unsigned char* input, const char* str_key, unsigned char* output, int des_operate_mode);