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

/*
	Encrypt/decrypt with key type DES_cblock
 */
extern "C" DESLIBRARY_API int perform_des(unsigned char* input, int input_len, DES_cblock des_key, DES_cblock des_iv, unsigned char* output, int* output_len, int operate_mode, int crypto_category, int crypto_mode, unsigned long* error);