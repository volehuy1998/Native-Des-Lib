#include "pch.h"

#include "NativeDes.h"

int perform_des(unsigned char* input, int input_len, DES_cblock des_key, DES_cblock des_iv, unsigned char* output, int* output_len, int operate_mode, int crypto_category, int crypto_mode, unsigned long* error)
{
	int ret = 0;
	int remain_len = 0;
	EVP_CIPHER_CTX* ctx = NULL;
	EVP_CIPHER* cipher = NULL;

	if (crypto_mode == 1)	   cipher = (EVP_CIPHER*)EVP_des_ecb();
	else if (crypto_mode == 2) cipher = (EVP_CIPHER*)EVP_des_cbc();
	else if (crypto_mode == 3) cipher = (EVP_CIPHER*)EVP_des_ofb();
	else if (crypto_mode == 4) cipher = (EVP_CIPHER*)EVP_des_cfb();
	else if (crypto_mode == 5) cipher = (EVP_CIPHER*)EVP_des_ede();

	do
	{
		
		ctx = EVP_CIPHER_CTX_new();
		if (ctx == NULL)
		{
			*error = ERR_get_error();
			break;
		}

		ret = EVP_CipherInit_ex(ctx, cipher, NULL, des_key, des_iv, operate_mode);
		if (ret != 1)
		{
			*error = ERR_get_error();
			break;
		}

		ret = EVP_CipherUpdate(ctx, output, output_len, input, input_len);
		if (ret != 1)
		{
			*error = ERR_get_error();
			break;
		}

		ret = EVP_CipherFinal_ex(ctx, output + *output_len, &remain_len);
		if (ret != 1)
		{
			*error = ERR_get_error();
			break;
		}

		*output_len = *output_len + remain_len;
	} while (false);

	if (ctx != NULL)
	{
		EVP_CIPHER_CTX_free(ctx);
	}

	return ret;
}