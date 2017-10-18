/*
 * WML Client implementation and interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#ifndef WML_CLIENT_H
#define WML_CLIENT_H

#include "wml_types.h"
#include "wml_timer.h"

#define WML_PREAMBLE_LEN    3

#define WML_SYNC_GOT_PREAMBLE   0x01
#define WML_SYNC_GOT_PRO_VER    0x02
#define WML_SYNC_GOT_GP_INXCNT  0x04
#define WML_SYNC_GOT_CRC_PLEN   0x08
#define WML_SYNC_GOT_ALL        0x0F


#define IS_MULTICAT_MAC(mac) ((mac[0]&0x03)==0x01&&(mac[3]&0x80)==0&&mac[0]!=0xFF)


#define CHECK_RIGHT_BITSET(n,bits)    (((1<<bits)-1)==n)
#define WML_CHANNEL_LISTEN_TIME    255
#define WML_CHANNEL_SYNC_TIME       (255*4)

#define WML_ATTR_PACKED __attribute((packed))
#define WML_ATTR_ALIGNED_4 __attribute((aligned(4)))

#define WML_ETH_MAC_LEN 6

#define WML_CH_VECTOR_LEN    20

enum {
    WML_INDEX_W = 1,
    WML_INDEX_M,//2
    WML_INDEX_L,//3
    WML_INDEX_PRO_VER,//4
    WML_INDEX_GP_IDXCNT,//5
    WML_INDEX_CRC_PKTS,//6
    WML_INDEX_PKT,//7
    WML_INDEX_MAX = 127
};

typedef enum{
    WML_STATE_SYNC,
    WML_STATE_LISTEN,
    WML_STATE_RECV,
    WML_STATE_DONE
}WML_STATE;

typedef struct t_wmlRxFlag{
    u32 hdrflg;
    u32 plflg1;
    u32 plflg2;
    u32 plflg3;
    u32 plflg4;
}wmlRxFlag;

typedef struct t_wmlContext{
    wmlRxFlag rxFlag;
    WML_STATE wmlStat;
    u8 chIdx;
    wmlTimer wmltimer;
}wmlCtx;

typedef struct WML_ATTR_PACKED t_wmlHeader{
u8 macsrc[WML_ETH_MAC_LEN];
u8 magic[WML_PREAMBLE_LEN];
u8 pro;
u8 ver;
u8 gpidx;
u8 gpcnt;
u8 crc;
u8 pllength;
}wmlHeader;

#define WML_HEADER_LEN  sizeof(wmlHeader)
#define SSID_MAX_LENGTH 32
#define PASSPHRASE_MAX_LENGTH   63
#define PMK_LENGTH  32

#define WML_CFG_PAYLOAD_MAX_LEN ((1+SSID_MAX_LENGTH+1+PASSPHRASE_MAX_LENGTH+1+PMK_LENGTH+2)/3*4+1)
#define WML_BUFF_LEN    (WML_HEADER_LEN+WML_CFG_PAYLOAD_MAX_LEN)

typedef struct WML_ATTR_PACKED t_WML_FRAME_CONTROL{
    u16        Ver:2;                // Protocol version
    u16        Type:2;                // MSDU type
    u16        SubType:4;            // MSDU subtype
    u16        ToDs:1;                // To DS indication
    u16        FrDs:1;                // From DS indication
    u16        MoreFrag:1;            // More fragment bit
    u16        Retry:1;            // Retry status bit
    u16        PwrMgmt:1;            // Power management bit
    u16        MoreData:1;            // More data bit
    u16        Wep:1;                // Wep data
    u16        Order:1;            // Strict order expected
} WML_FRAME_CONTROL;

typedef struct WML_ATTR_PACKED t_WML_HEADER_802_11{
    WML_FRAME_CONTROL   FC;
    u16  Duration;
    u8   Addr1[WML_ETH_MAC_LEN];
    u8   Addr2[WML_ETH_MAC_LEN];
    u8   Addr3[WML_ETH_MAC_LEN];
    u16  Frag:4;
    u16  Sequence:12;
    u8   Octet[0];
}WML_HEADER_802_11;


void wml_init(u8 * key);
void wml_rxhandle(WML_HEADER_802_11 * header_802_11);
void wml_reset(void);
void wml_stop(void);


void wml_parsing(u8 * dest, u8 *src);
#endif // WMCFG_CLIENT_H
