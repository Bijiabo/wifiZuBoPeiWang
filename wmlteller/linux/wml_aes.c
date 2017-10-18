/*
 * AES encryption interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#include <stdlib.h>
#include <openssl/aes.h>

/**
 * wml_aes_ecb_encrypt_128 - aes ecb 128 encrypt
 * @plain: cipher text to be encrypted
 * @plainlen: Length of the data to encrypted
 * @cipher: cipher text buffer
 * @cipherlen:cipher text buffer length
 * @key:128 bits aes key
 */
int wml_aes_ecb_encrypt_128(
        const unsigned char *plain,
        const int plainlen,
        unsigned char *cipher,
        const int cipherlen,
        const unsigned char * key
		)
{
	AES_KEY aeskey;
    unsigned long len = plainlen;

    if(AES_set_encrypt_key(key,128,&aeskey)||plainlen%AES_BLOCK_SIZE!=0||plainlen!=cipherlen)
		return -1;

    while (len >= AES_BLOCK_SIZE)
    {
        AES_encrypt(plain, cipher, &aeskey);
		len -= AES_BLOCK_SIZE;
        plain += AES_BLOCK_SIZE;
        cipher += AES_BLOCK_SIZE;
	}
	return 0;
}
