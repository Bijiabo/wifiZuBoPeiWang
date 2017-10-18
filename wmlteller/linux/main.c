/*
 * for WML Teller Testing
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#include <stdio.h>
#include "wml_teller.h"


#define AES_KEY "someoneunlikeyou"

int main(int argc, char *argv[])
{
    WMLContext wmlctx;
    unsigned char * mdata;
    int i,length;

    initWMLCfgTeller(&wmlctx,"88888888","mgd",AES_KEY);
    prepareWMLConfigData(&wmlctx,&mdata,&length);
    printMcastAddressGroupTestData(mdata,length);

    genMcastGroupList(mdata,length,&wmlctx.groupList);
    free(mdata);
    if(wmlctx.groupList)
    {
        for(i=0;wmlctx.groupList[i]!=NULL;i++)
        {
            printf("%s\n",wmlctx.groupList[i]);
            free(wmlctx.groupList[i]);
        }
        printf("group list length:%d!!!\n",i);
        free(wmlctx.groupList);
    }
    else
    {
        printf("group list is error!!!\n");
    }

    printf("Hello World!\n");
    return 0;
}
