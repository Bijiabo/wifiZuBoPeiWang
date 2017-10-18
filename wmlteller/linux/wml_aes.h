/*
 * AES encryption interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#ifndef __WML_AES_H__
#define __WML_AES_H__

#include <openssl/aes.h>
int wml_aes_ecb_encrypt_128(
        const unsigned char *plain,
        const int plainlen,
        unsigned char *cipher,
        const int cipherlen,
        const unsigned char * key
        );

#endif
