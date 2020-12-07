#include "pch.h"

#include "NativeDes.h"

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
	for (int i = 0; i < DES_KEY_SZ / 2; i++)
	{
		unsigned char temp = des_key.des_block[i];
		des_key.des_block[i] = des_key.des_block[DES_KEY_SZ - 1 - i];
		des_key.des_block[DES_KEY_SZ - 1 - i] = temp;
	}
	
	return des_key.des_ull;
}

int des_ecb_with_str_key(unsigned char* input, const char* str_key, unsigned char* output, int des_operate_mode)
{
	DES_cblock des_key;
	DES_key_schedule des_key_schedule;

	DES_string_to_key((const char *)str_key, &des_key);
	if (0 != DES_is_weak_key((const_DES_cblock *)&des_key))
	{
		return -1;
	}

	DES_set_key_unchecked((const_DES_cblock*)&des_key, &des_key_schedule);
	DES_ecb_encrypt((DES_cblock*)input, (DES_cblock*)output, &des_key_schedule, des_operate_mode);

	return 0;
}

int des_ecb(unsigned char* input, unsigned long long key_ll, unsigned char* output, int des_operate_mode)
{
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

	DES_ecb_encrypt((DES_cblock*)input, (DES_cblock*)output, &des_key_schedule, des_operate_mode);

	return 0;
}