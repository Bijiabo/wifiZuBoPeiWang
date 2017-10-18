/*
 * WML Client implementation and interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */

#include <stdio.h>
#include <stdlib.h>

#include "wml_platform.h"
#include "wml_client.h"
#include "wml_timer.h"
#include "wpa_supplicant/base64.h"
#include "wml_aes.h"
#include "wml_crc8.h"


static wmlCtx gwmlContext;
static u8 wmlbuf[WML_BUFF_LEN];

static const s8 WML_MAGIC[WML_PREAMBLE_LEN]={'w','m','l'};
static const u8 ALL_ZERO_MAC[WML_ETH_MAC_LEN]={0};
//default key "0123456789abcdef"
static u8 WML_AES_KEY[16]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

#define pwmlheader    ((wmlHeader *)&wmlbuf[0])
#define pwmlpayload   (&wmlbuf[WML_HEADER_LEN])

/**
 * wml_channelswitch - 802.11 channel switch
 */

static void wml_channelswitch(void)
{
    gwmlContext.chIdx %= WML_CH_VECTOR_LEN;
    __ToBeDo_Start("switch wifi channel");
    __ToBeDo_End("switch wifi channel");
    gwmlContext.chIdx++;
}

/**
 * wml_recvcheck - receive completion check
 * @len: total data length to be receive
 * @Returns:0-not completed, otherwise completed
 */
static u8 wml_recvcheck(u8 len)
{
    if(len>=96){
        return (gwmlContext.rxFlag.plflg1==0xFFFFFFFF&&gwmlContext.rxFlag.plflg2==0xFFFFFFFF&&gwmlContext.rxFlag.plflg3==0xFFFFFFFF&&CHECK_RIGHT_BITSET(gwmlContext.rxFlag.plflg4,len-96));
    }else if(len>=64){
        return (gwmlContext.rxFlag.plflg1==0xFFFFFFFF&&gwmlContext.rxFlag.plflg2==0xFFFFFFFF&&CHECK_RIGHT_BITSET(gwmlContext.rxFlag.plflg3,len-64));
    }else if(len>=32){
        return (gwmlContext.rxFlag.plflg1==0xFFFFFFFF&&CHECK_RIGHT_BITSET(gwmlContext.rxFlag.plflg2,len-32));
    }else if(len<32){
        return (CHECK_RIGHT_BITSET(gwmlContext.rxFlag.plflg1,len));
    }
}


/**
 * wml_init - wml client init
 * @key: 128 bits aes key
 */
void wml_init(u8 * key)
{
    if(key != NULL) memcpy(WML_AES_KEY,key,16);
    memset(wmlbuf,0,WML_BUFF_LEN);
    memset(&gwmlContext,0,sizeof(wmlCtx));
    wml_timer_init(&gwmlContext.wmltimer,wml_reset,0,WML_CHANNEL_LISTEN_TIME);
    wml_timer_start(&gwmlContext.wmltimer);
}

/**
 * wml_reset - reset wml client status/rxBuffer/rxFlag/Timer/, switch channel
 */
void wml_reset(void)
{
    gwmlContext.wmlStat = WML_STATE_SYNC;
    wml_channelswitch();
    memset(&gwmlContext.rxFlag,0,sizeof(wmlRxFlag));
    memset(wmlbuf,0,WML_BUFF_LEN);
    wml_timer_reset(&gwmlContext.wmltimer);
}

/**
 * hexText - transform binary data into hex text
 * @dat: data to be transform
 * @length:length of data to be transfromed
 * @text: ascii hex code buffer
 */
void hexText(unsigned char * dat,int length,char * text)
{
    int i;
    char c;

    if(dat == NULL||text == NULL)
        return ;

    for(i=0;i<length;i++)
    {
        c = (char)((dat[i]>>4)&0x0F);
        if(c>9)
            text[i*2]=((char)(c-10+'a'));
        else
            text[i*2]=((char)(c+'0'));
        c = (char)(dat[i]&0x0F);
        if(c>9)
            text[i*2+1]=((char)(c-10+'a'));
        else
            text[i*2+1]=((char)(c+'0'));
    }
    text[i*2] = 0;
}

/**
 * wml_decode - decode wml packet payload
 * @header: packet header
 * @payload:packet payload
 */
void wml_decode(wmlHeader * header,u8 * payload)
{
    u8 crc;
    u32 plain_len;
    u32 cipher_len;
    u8 * plain_buffer = NULL;
    u8 * cipher_buff = NULL;
    u8 ssidlen,passwdlen,pmklen;
    u8 * ssid = NULL,* passwd = NULL, * pmk = NULL;

    WML_Printf("Try to decode, payload length:%d\n",header->pllength);
    crc = crc8(payload,header->pllength*2);

    if(crc == header->crc)
    {
        cipher_buff = (u8 *)malloc(header->pllength*2/4*3);
        if(cipher_buff)
        {
            cipher_buff = base64_decode(payload,header->pllength*2,&cipher_len);
            plain_len = cipher_len;

            WML_Printf("cipher length:%d\n",cipher_len);
            plain_buffer = (u8 *)malloc(plain_len);
            if(plain_buffer)
            {
                memset(plain_buffer,0,plain_len);

                wml_aes_ecb_decrypt_128(
                    cipher_buff,
                    cipher_len,
                    plain_buffer,
                    plain_len,
                    WML_AES_KEY);

                ssidlen = plain_buffer[0];
                passwdlen = plain_buffer[ssidlen+1];
                pmklen = plain_buffer[ssidlen+1+passwdlen+1];

                plain_buffer[ssidlen+1] = 0;
                plain_buffer[ssidlen+1+passwdlen+1] = 0;

                ssid = &plain_buffer[1];
                if(passwdlen)
                    passwd = &plain_buffer[1+ssidlen+1];

                WML_Printf("ssid:%s,passwd:%s\n",ssid,passwd);
                if(pmklen)
                {
                    char * pmktxt ;

                    pmk = &plain_buffer[1+ssidlen+1+passwdlen+1];
                    pmktxt =(char *)malloc(pmklen*2+1);
                    hexText(pmk,pmklen,pmktxt);
                    WML_Printf("pmk:%s\n",pmktxt);
                    free(pmktxt);
                }

                free(plain_buffer);
            }
            free(cipher_buff);
        }
        gwmlContext.wmlStat = WML_STATE_DONE;
        wml_timer_stop(&gwmlContext.wmltimer);
    }
    else
    {
        WML_Printf("crc8 error: %02x<--->%02x\n",crc,header->crc);
        wml_reset();
    }
}

/**
 * wml_parsing - parsing destination and source mac
 * @dest: destination mac
 * @src: source mac
 */
void wml_parsing(u8 * dest, u8 *src)
{
    u8 index,offset;

    if(dest == NULL || src == NULL)
        return ;

    index=dest[3];

    switch(gwmlContext.wmlStat)
    {
        case WML_STATE_SYNC:
            switch(index)
            {
                case WML_INDEX_W:
                case WML_INDEX_M:
                case WML_INDEX_L:
                    if(dest[4]==WML_MAGIC[index-WML_INDEX_W]&&dest[4]==(u8)~dest[5])
                    {
                        WML_Printf("Got Preamlbe\n");
                        if(!memcmp(src,pwmlheader->macsrc,WML_ETH_MAC_LEN)||!memcmp(ALL_ZERO_MAC,pwmlheader->macsrc,WML_ETH_MAC_LEN))
                        {//from wifi addr
                            pwmlheader->magic[index-WML_INDEX_W] = dest[4];
                            memcpy(pwmlheader->macsrc,src,WML_ETH_MAC_LEN);
                            if(!memcmp(pwmlheader->magic,WML_MAGIC,WML_PREAMBLE_LEN))
                            {
                                WML_Printf("Go Sync\n\n");
                                gwmlContext.wmlStat = WML_STATE_LISTEN;
                                gwmlContext.rxFlag.hdrflg = (WML_SYNC_GOT_PREAMBLE);
                            }
                            wml_timer_stop(&gwmlContext.wmltimer);
                            if(gwmlContext.wmlStat == WML_STATE_LISTEN)
                                wml_timer_init(&gwmlContext.wmltimer,wml_reset,0,WML_CHANNEL_SYNC_TIME);
                            else
                                wml_timer_init(&gwmlContext.wmltimer,wml_reset,0,WML_CHANNEL_LISTEN_TIME);
                            wml_timer_start(&gwmlContext.wmltimer);
                        }
                    }
                break;
            }
        break;
        case WML_STATE_LISTEN:
            if(memcmp(src,pwmlheader->macsrc,WML_ETH_MAC_LEN)){//from wifi addr
                WML_Printf("src %02x:%02x:%02x:%02x:%02x:%02x\n",src[0],src[1],src[2],src[3],src[4],src[5]);
                WML_Printf("orgsrc %02x:%02x:%02x:%02x:%02x:%02x\n",pwmlheader->macsrc[0],
                        pwmlheader->macsrc[1],
                        pwmlheader->macsrc[2],
                        pwmlheader->macsrc[3],
                        pwmlheader->macsrc[4],
                        pwmlheader->macsrc[5]);
                break;
            }
            wml_timer_reset(&gwmlContext.wmltimer);

            switch(index)
            {
                case WML_INDEX_PRO_VER:
                    if(!(gwmlContext.rxFlag.hdrflg&WML_SYNC_GOT_PRO_VER))
                    {
                        pwmlheader->pro = dest[4];
                        pwmlheader->ver = dest[5];

                        gwmlContext.rxFlag.hdrflg |= WML_SYNC_GOT_PRO_VER;
                    }
                break;
                case WML_INDEX_GP_IDXCNT:
                    if(!(gwmlContext.rxFlag.hdrflg&WML_SYNC_GOT_GP_INXCNT))
                    {
                        pwmlheader->gpidx = dest[4];
                        pwmlheader->gpcnt = dest[5];
                        gwmlContext.rxFlag.hdrflg |= WML_SYNC_GOT_GP_INXCNT;
                    }
                break;
                case WML_INDEX_CRC_PKTS:
                    if(!(gwmlContext.rxFlag.hdrflg&WML_SYNC_GOT_CRC_PLEN))
                    {
                        pwmlheader->crc = dest[4];
                        pwmlheader->pllength = dest[5];
                        gwmlContext.rxFlag.hdrflg |= WML_SYNC_GOT_CRC_PLEN;
                    }
                break;
            }
            if((gwmlContext.rxFlag.hdrflg&WML_SYNC_GOT_ALL)==WML_SYNC_GOT_ALL)
            {
                gwmlContext.wmlStat = WML_STATE_RECV;
            }
        break;
        case WML_STATE_RECV:
        {
            if(memcmp(src,pwmlheader->macsrc,WML_ETH_MAC_LEN)){//from wifi addr
                WML_Printf("src %02x:%02x:%02x:%02x:%02x:%02x\n",src[0],src[1],src[2],src[3],src[4],src[5]);
                WML_Printf("orgsrc %02x:%02x:%02x:%02x:%02x:%02x\n",pwmlheader->macsrc[0],
                        pwmlheader->macsrc[1],
                        pwmlheader->macsrc[2],
                        pwmlheader->macsrc[3],
                        pwmlheader->macsrc[4],
                        pwmlheader->macsrc[5]);
                break;
            }
            wml_timer_reset(&gwmlContext.wmltimer);

            if(index>=WML_INDEX_PKT&&index<=WML_INDEX_MAX)
            {
                WML_Printf("Receive...\n");
                offset = index - WML_INDEX_PKT;
                pwmlpayload[offset*2] = dest[4];
                pwmlpayload[offset*2+1] = dest[5];

                if(offset>=96){
                    gwmlContext.rxFlag.plflg4|=(1<<(offset-96));
                }else if(offset>=64){
                    gwmlContext.rxFlag.plflg3|=(1<<(offset-64));
                }else if(offset>=32){
                    gwmlContext.rxFlag.plflg2|=(1<<(offset-32));
                }else{
                    gwmlContext.rxFlag.plflg1|=(1<<offset);
                }
            }

            if(wml_recvcheck(pwmlheader->pllength))
            {
                wml_decode(pwmlheader,pwmlpayload);
            }
        }
        break;
    }
}

/**
 * wml_rxhandle - 802_11 frame handle
 * @pHeader: 802_11 Header
 */
void wml_rxhandle(WML_HEADER_802_11 * pHeader)
{
    u8 *src=NULL,*dest=NULL;

    if(pHeader->FC.FrDs==1&&pHeader->FC.ToDs==0){
        dest=pHeader->Addr1;
        src=pHeader->Addr3;
    }else if(pHeader->FC.FrDs==0&&pHeader->FC.ToDs==1){
        src=pHeader->Addr2;
        dest=pHeader->Addr3;
    }
    if(dest&&IS_MULTICAT_MAC(dest))
    {
        wml_parsing(dest,src);
    }
}

/**
 * wml_stop - stop wml
 */
void wml_stop(void)
{
    gwmlContext.wmlStat = WML_STATE_SYNC;
    wml_timer_stop(&gwmlContext.wmltimer);
}
