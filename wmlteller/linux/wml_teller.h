/*
 * WML Teller implementation and interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#ifndef __WMLCFGTELLER_H__
#define __WMLCFGTELLER_H__
#include <pthread.h>


typedef struct t_WMLContext{
    char SSID[33];
    char passPhrase[64];
    char AESKey[16];
    char * *groupList;
    pthread_t ntid;
    unsigned char running;
}WMLContext;

void stopWMLConfig(WMLContext * wmlctx);
int startWMLCfg(WMLContext * wmlctx);
void printMcastAddressGroupTestData(unsigned char * mcastdata,int length);
void genMcastGroupList(unsigned char *  mcastdata, int length,char *** grouplist);
void prepareWMLConfigData(WMLContext * wmlctx,unsigned char * * mdata,int * length );
int initWMLCfgTeller(WMLContext * wmlctx,char * passphrase,char * ssid, unsigned char * key);

#endif
