/*
 * for WML client Testing
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */

#include <stdio.h>
#include "wml_client.h"
#include "wml_crc8.h"

void hexCode(char * code, int length, unsigned char * data)
{
    int i,j;
    unsigned char b;
    char c;

    if(code == NULL)
        return ;

    j = 0;
    b = 0;
    for(i=0;i<length;i++){
        c = code[i];
        if(c>='0'&&c<='9'){
            b += c-'0';
        }else if(c>='A'&&c<='F'){
            b += c-'A'+10;
        }else if(c>='a'&&c<='f'){
            b += c-'a'+10;
        }

        if(j==0){
            j++;
            b <<= 4;
        }else{
            data[i/2] = b;
            b = 0;
            j = 0;
        }
    }
}

int main(int argc, char *argv[])
{
    int i;
    unsigned char dest[6],src[6];
    unsigned char aaa = 0x13;

    for(aaa = 0;aaa<0xFF;aaa++)
    {
        printf("%02x,",crc8(&aaa,1));
        if(aaa%8==0)
            printf("\n");
    }
    aaa = 0xff;
    printf("%02x,",crc8(&aaa,1));
    char * wmlinfo[38][2] =
    {
        {"01005e017788","d81d72df3866"},
        {"01005e026d92","d81d72df3866"},
        {"01005e036c93","d81d72df3866"},
        {"01005e040101","d81d72df3866"},
        {"01005e050001","d81d72df3866"},
        {"01005e06be20","d81d72df3866"},
        {"01005e077361","d81d72df3866"},
        {"01005e086146","d81d72df3866"},
        {"01005e095257","d81d72df3866"},
        {"01005e0a476e","d81d72df3866"},
        {"01005e0b4346","d81d72df3866"},
        {"01005e0c4931","d81d72df3866"},
        {"01005e0d7144","d81d72df3866"},
        {"01005e0e2b5a","d81d72df3866"},
        {"01005e0f6775","d81d72df3866"},
        {"01005e103152","d81d72df3866"},
        {"01005e113852","d81d72df3866"},
        {"01005e12694a","d81d72df3866"},
        {"01005e13764d","d81d72df3866"},
        {"01005e14556d","d81d72df3866"},
        {"01005e154e41","d81d72df3866"},
        {"01005e166f61","d81d72df3866"},
        {"01005e173457","d81d72df3866"},
        {"01005e184a79","d81d72df3866"},
        {"01005e195763","d81d72df3866"},
        {"01005e1a4130","d81d72df3866"},
        {"01005e1b4761","d81d72df3866"},
        {"01005e1c7665","d81d72df3866"},
        {"01005e1d7869","d81d72df3866"},
        {"01005e1e3472","d81d72df3866"},
        {"01005e1f3553","d81d72df3866"},
        {"01005e207945","d81d72df3866"},
        {"01005e214962","d81d72df3866"},
        {"01005e223932","d81d72df3866"},
        {"01005e236735","d81d72df3866"},
        {"01005e24324f","d81d72df3866"},
        {"01005e255336","d81d72df3866"},
        {"01005e264c46","d81d72df3866"}
    };

    wml_init("someoneunlikeyou");

    for(i=0;i<38;i++)
    {
        printf("%s from %s\n",wmlinfo[i][0],wmlinfo[i][1]);
        hexCode(wmlinfo[i][0],12,dest);
        hexCode(wmlinfo[i][1],12,src);
        printf("dest %02x:%02x:%02x:%02x:%02x:%02x\n",dest[0],dest[1],dest[2],dest[3],dest[4],dest[5]);
        printf("src %02x:%02x:%02x:%02x:%02x:%02x\n",src[0],src[1],src[2],src[3],src[4],src[5]);
        wml_parsing(dest,src);
    }
    return 0;
}
