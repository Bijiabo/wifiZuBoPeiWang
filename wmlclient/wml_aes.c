/*
 * AES Decryption interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#include <openssl/aes.h>

/**
 * wml_aes_ecb_decrypt_128 - aes ecb 128 decrypt
 * @cipher: cipher text to be decrypted
 * @cipherlen: Length of the data to decrypted
 * @plain: plain text buffer
 * @plainlen:plain text buffer length
 * @key:128 bits aes key
 */

void wml_aes_ecb_decrypt_128(unsigned char * cipher,int cipherlen,unsigned char * plain,int plainlen,unsigned char * key)
{
    AES_KEY aeskey;
    int offset;

    AES_set_decrypt_key(key,128,&aeskey);

    if(cipherlen%16!=0||cipherlen!=plainlen)
        return;

    offset = 0;
    while(offset<cipherlen)
    {
        AES_ecb_encrypt(cipher+offset,plain+offset,&aeskey,AES_DECRYPT);
        offset+=16;
    }
}

