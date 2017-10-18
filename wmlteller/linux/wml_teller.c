/*
 * WML Teller implementation and interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "wml_aes.h"
#include "wpa_supplicant/base64.h"
#include "wpa_supplicant/sha1.h"
#include "netdb.h"
#include "arpa/inet.h"
#include "wml_teller.h"


#define HEADERLEN           12
#define PROTOCOL            0x01
#define VER                 0x01
#define WPA_PMK_LEN         32
#define IPv4_MAX_LEN        16
#define MCASTGROUPADDR0     227
#define MCASTGROUPADDR1_START  1
#define MCASTGROUPPORT      2003


const char PREAMBLE[]={'w','m','l'};
char const * INFO = "wcfg";


int  wpaPassphrase(char * salt,int saltlen,char * passwd,int passwdlen,unsigned char * psk)
{
    if(salt==NULL||passwd==NULL)
		return -1;

    if(passwdlen<8||passwdlen>63)
		return -2;

    memset(salt+saltlen,0,strlen(salt)-saltlen);
    memset(passwd+passwdlen,0,strlen(passwd)-passwdlen);

    pbkdf2_sha1(passwd, salt, saltlen, 4096, psk, 32);

	return 0;
}


void *wmlCfgThread(void *arg)
{
    WMLContext * wmlctx;
	unsigned int sockdest;
    struct sockaddr_in dest;
    int ret,i,	enable=1;

	sockdest = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockdest < 0)
	{
        WML_Printf("Device search socket setsockopt error!\n");
		goto end;
	}

    wmlctx = (WMLContext *)arg;

    while(wmlctx->running)
    {
        for(i=0;wmlctx->groupList[i]!=NULL;i++)
        {
            dest.sin_family      = AF_INET;
            dest.sin_addr.s_addr = inet_addr(wmlctx->groupList[i]);
            dest.sin_port        = htons(7879);

            ret = sendto(sockdest, INFO, strlen(INFO), 0,(struct sockaddr *)&dest,sizeof(struct sockaddr_in));

            if (ret < 0)
			{
                wmlctx->running = 0;
                WML_Printf("write error.\n");
			}
		}

		usleep(200000);
	}

end:
    for(i=0;wmlctx->groupList[i]!=NULL;i++)
        free(wmlctx->groupList[i]);
    free(wmlctx->groupList);
    wmlctx->groupList=NULL;

	setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int));
	close(socket);

	return NULL;
}

int initWMLCfgTeller(WMLContext * wmlctx,char * passphrase,char * ssid, unsigned char * key)
{
    if(wmlctx == NULL || ssid == NULL || key == NULL)
        return -1;

    memset(wmlctx->SSID,0,sizeof(wmlctx->SSID));
    strcpy(wmlctx->SSID,ssid);


    memset(wmlctx->passPhrase,0,sizeof(wmlctx->passPhrase));
    if(passphrase)
        strcpy(wmlctx->passPhrase,passphrase);

    memcpy(wmlctx->AESKey,key,16);

    wmlctx->groupList = NULL;
    wmlctx->ntid = 0;
    wmlctx->running = 0;
    return 0;
}

void prepareWMLConfigData(WMLContext * wmlctx,unsigned char * * mdata,int * length )
{
    unsigned char * mcastdata = NULL;
    unsigned char * passwd = NULL;
    unsigned char * salt;
    unsigned char pmk[32];
    unsigned char * info = NULL,* aescipher = NULL,* base64code = NULL;
    int infolen,offset,base64length;

    if(wmlctx == NULL)
        return;

    salt = wmlctx->SSID;
    infolen = 1;
    infolen += strlen(salt);
    if(wmlctx->passPhrase != NULL)
    {
        passwd = wmlctx->passPhrase;
        infolen += strlen(passwd);
    }
    infolen += 1;

    wpaPassphrase(salt,strlen(salt),passwd,strlen(passwd),pmk);
    infolen += WPA_PMK_LEN ;
    infolen += 1;

    infolen += 16-(infolen%16);
    info = (unsigned char *)malloc(infolen);

    if(info)
    {
        memset(info,0,infolen);
        offset = 0;
        info[offset] = (strlen(salt)&0xFF);
        offset += 1;
        memcpy(info+offset,salt,strlen(salt));
        offset += strlen(salt);
        if(passwd != NULL){
            info[offset] = (strlen(passwd)&0xFF);
            offset += 1;
            memcpy(info+offset,passwd,strlen(passwd));
            offset += strlen(passwd);
        }else{
            info[offset] = 0;
            offset += 1;
        }

        info[offset] = WPA_PMK_LEN;
        offset += 1;
        memcpy(info+offset,pmk,WPA_PMK_LEN);

        aescipher = (unsigned char *)malloc(info);

        if(aescipher)
        {
            wml_aes_ecb_encrypt_128(info,infolen,aescipher,infolen,wmlctx->AESKey);

            base64code = base64_encode(aescipher,infolen,&base64length);
            printf("base64 length:%d\n",base64length);
            if(base64code)
            {
                mcastdata = (unsigned char *)malloc(HEADERLEN+base64length);
                if(mcastdata)
                {
                    //PREABLE
                    mcastdata[0] = PREAMBLE[0];
                    mcastdata[1] = (unsigned char)~PREAMBLE[0];
                    mcastdata[2] = PREAMBLE[1];
                    mcastdata[3] = (unsigned char)~PREAMBLE[1];
                    mcastdata[4] = PREAMBLE[2];
                    mcastdata[5] = (unsigned char)~PREAMBLE[2];
                    //PROTOCOL
                    mcastdata[6] = PROTOCOL;
                    //PROTO VERSION
                    mcastdata[7] = VER;
                    //Group Index
                    mcastdata[8] = 0;
                    //Groups total
                    mcastdata[9] = 1;
                    //CRC8
                    mcastdata[10] = crc8(base64code,base64length);
                    //Packets double rate
                    mcastdata[11] = (unsigned char)((base64length/2)&0xFF);

                    memcpy(mcastdata+HEADERLEN,base64code,base64length);
                    *mdata = mcastdata;
                    *length = HEADERLEN+base64length;
                }
                free(base64code);
            }
            free(aescipher);
        }
        free(info);
    }
}


void genMcastGroupList(unsigned char *  mcastdata, int length,char *** grouplist)
{
    int i;
    char ** gp;

    gp = (char **)malloc(sizeof(char *)*(length/2+1));//double rate

    if(gp)
    {
        memset(gp,0,sizeof(char *)*(length/2+1));
        for(i=0;i<length;i+=2)
        {
            gp[i/2] = (char *)malloc(IPv4_MAX_LEN);

           if(gp[i/2])
            {
                memset(gp[i/2],0,IPv4_MAX_LEN);
                    sprintf(gp[i/2],"%u.%u.%u.%u",
                    MCASTGROUPADDR0,
                    MCASTGROUPADDR1_START+i/2,
                    mcastdata[i]&0xFF,
                    mcastdata[i+1]&0xFF);
            }
            else
            {
                for(i=0;i<length/2;i++)
                {
                    if(gp[i] != NULL)
                        free(gp[i]);
                }
                free(gp);
                gp = NULL;
            }
        }
    }

    *grouplist = gp;
}

void printMcastAddressGroupTestData(unsigned char * mcastdata,int length)
{
    int i;

    for(i=0;i<length;i+=2)
    {
        printf("{\"01005e%02x%02x%02x\",\"d81d72df3866\"},\n",MCASTGROUPADDR1_START+i/2,
               mcastdata[i]&0xFF,
               mcastdata[i+1]&0xFF);
    }
}

int startWMLCfg(WMLContext * wmlctx)
{
    int ret = 1;
    unsigned char * mdata;
    int length;

    if(wmlctx == NULL)
        return ret;

    if(wmlctx->running)
        return ret;

    wmlctx->running=1;

    prepareWMLConfigData(wmlctx,&mdata,&length);

    genMcastGroupList(mdata,length,&wmlctx->groupList);
    if(mdata)
    {
        ret = pthread_create(&wmlctx->ntid, NULL, wmlCfgThread, wmlctx);
        if (0 != ret)
        {
            WML_Printf("pthread_create error.");
            wmlctx->running = 0;
        }
        free(mdata);
    }

    return ret;
}

void  stopWMLConfig(WMLContext * wmlctx)
{
    wmlctx->running = 0;
}
