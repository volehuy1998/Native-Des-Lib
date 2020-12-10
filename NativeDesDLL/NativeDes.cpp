#include "pch.h"

#include "NativeDes.h"

static int des_ecb_standard(unsigned char* input, int input_len, DES_cblock des_key, unsigned char* output, int* output_len, int des_operate_mode);

//void DES_CBC()
//{
//	DES_cblock key;// = { 0x29, 0xab, 0x9d, 0x18, 0xb2, 0x44, 0x9e, 0x31 };
//	DES_cblock iv = { 0x5e, 0x72, 0xd7, 0x9a, 0x11, 0xb3, 0x4f, 0xee };
//	DES_cblock iv2 = { 0x5e, 0x72, 0xd7, 0x9a, 0x11, 0xb3, 0x4f, 0xee };
//	DES_key_schedule schedule;
//	DES_key_schedule schedule1;
//	unsigned char input[] = "huyvo";
//	unsigned char decrypted[sizeof input];
//	unsigned char encrypted[sizeof input];
//
//	DES_string_to_key("like", &key);
//	//DES_random_key(&key);
//	if (-2 == DES_set_key_checked(&key, &schedule))
//	{
//		// weak key
//	}
//
//	DES_ecb_encrypt((const_DES_cblock*)input, (DES_cblock*)encrypted, &schedule, DES_ENCRYPT);
//	//DES_ncbc_encrypt(input, (unsigned char*)encrypted, sizeof input, &schedule, &iv, DES_ENCRYPT);
//
//	DES_string_to_key("like1", &key);
//	DES_set_key_checked(&key, &schedule1);
//	//schedule.ks->cblock[0] = 0x17;
//	DES_ecb_encrypt((const_DES_cblock*)encrypted, (DES_cblock*)decrypted, &schedule1, DES_DECRYPT);
//	//DES_ncbc_encrypt((unsigned char*)encrypted, (unsigned char*)decrypted, sizeof input, &schedule, &iv2, DES_DECRYPT);
//	
//	/* Printing and Verifying */
//	print_data("\n Original ", input, sizeof(input));
//	print_data("\n Encrypted", encrypted, sizeof(input));
//	print_data("\n Decrypted", decrypted, sizeof(input));
//}
//
//void DES_ECB()
//{
//	unsigned char input[] = "huyvo";
//	DES_cblock key = { 0x12, 0x56,0x12, 0x56,0x12, 0x56,0x12, 0x56 };
//	DES_key_schedule schedule;
//	unsigned char decrypted[sizeof input];
//	unsigned char encrypted[sizeof input];
//
//	memset(encrypted, 0, sizeof input);
//	memset(decrypted, 0, sizeof input);
//
//	int a = DES_set_key_checked(&key, &schedule);
//	{
//		// weak key
//	}
//
//	DES_ecb_encrypt((const_DES_cblock *)input, (DES_cblock *)encrypted, &schedule, DES_ENCRYPT);
//
//	key[1] = 0x15;
//	DES_set_key_checked(&key, &schedule);
//	DES_ecb_encrypt((const_DES_cblock*)encrypted, (DES_cblock*)decrypted, &schedule, DES_DECRYPT);
//
//	/* Printing and Verifying */
//	print_data("\n Original ", input, sizeof(input));
//	print_data("\n Encrypted", encrypted, sizeof(input));
//	print_data("\n Decrypted", decrypted, sizeof(input));
//}

union _DES_cblock
{
	DES_cblock des_block;
	unsigned long long des_ull;
};

unsigned long long des_random_key()
{
	_DES_cblock des_key;
	DES_random_key(&des_key.des_block);
	return des_key.des_ull;
}

int des_ecb_with_str_key(unsigned char* input, int input_len, const char* str_key, unsigned char* output, int* output_len, int des_operate_mode)
{
	DES_cblock des_key;
	DES_key_schedule des_key_schedule;

	DES_string_to_key((const char *)str_key, &des_key);
	if (0 != DES_is_weak_key((const_DES_cblock *)&des_key))
	{
		return -1;
	}

	DES_set_key_unchecked((const_DES_cblock*)&des_key, &des_key_schedule);

	int ret = des_ecb_standard(input, input_len, des_key, output, output_len, des_operate_mode);

	return 0;
}

int des_ecb(unsigned char* input, int input_len, unsigned long long key_ll, unsigned char* output, int* output_len, int des_operate_mode)
{
	int ret = 0;
	int remain_len = 0;
	_DES_cblock _des_key;
	_des_key.des_ull = key_ll;
	DES_cblock des_key;
	memcpy_s(des_key, DES_KEY_SZ, _des_key.des_block, DES_KEY_SZ);
	DES_key_schedule des_key_schedule;
	int check = DES_set_key_checked((const_DES_cblock*)&des_key, &des_key_schedule);
	if (0 != check)
	{
		return check;
	}

	ret = des_ecb_standard(input, input_len, des_key, output, output_len, des_operate_mode);

	return ret;
}

static int des_ecb_standard(unsigned char* input, int input_len, DES_cblock des_key, unsigned char* output, int* output_len, int des_operate_mode)
{
	int ret = 0;
	int remain_len = 0;
	EVP_CIPHER_CTX* ctx = NULL;

	do
	{
		
		ctx = EVP_CIPHER_CTX_new();
		if (ctx == NULL)
		{
			break;
		}

		ret = EVP_CipherInit_ex(ctx, EVP_des_ecb(), NULL, NULL, NULL, des_operate_mode);
		if (ret != 1)
		{
			break;
		}

		ret = EVP_CipherInit_ex(ctx, NULL, NULL, des_key, NULL, des_operate_mode);
		if (ret != 1)
		{
			break;
		}

		ret = EVP_CipherUpdate(ctx, output, output_len, input, input_len);
		if (ret != 1)
		{
			break;
		}

		ret = EVP_CipherFinal_ex(ctx, output + *output_len, &remain_len);
		if (ret != 1)
		{
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