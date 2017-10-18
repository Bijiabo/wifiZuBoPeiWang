/*
 * AES Decryption interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#ifndef WML_AES_H
#define WML_AES_H

void wml_aes_ecb_decrypt_128(unsigned char * cipher,int cipherlen,unsigned char * plain,int plainlen,unsigned char * key);
#endif // WML_AES_H
