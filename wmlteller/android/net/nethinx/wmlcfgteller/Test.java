/*
 * package test functions
 * Copyright (c) 2016, Gavin Hsu <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README and COPYING for more details.
 */
package net.nethinx.wmlcfgteller;

import android.util.Log;


public class Test {

    public static void pbkdf2_test(){
        byte [] pmk = null;
        final String TAG = "PBKDF2_TEST";

        pmk = Crypto.wpa_passphrase_pmk_generate("88888888".toCharArray(),"123456".getBytes());

        if(pmk == null)
            Log.d(TAG,"pmk hash error");
        else
            Log.d(TAG,Utils.hexText(pmk));
    }

    public static void aesecb128_test(){
        final String TAG = "AESECB128_TEST";
        byte [] cipher = null;

        cipher =  Crypto.aes_ecb128_encrypt("1234567890abcdef".getBytes(),"1234567890abcdef".getBytes());
        Log.d(TAG,Utils.hexText(cipher));
    }

    public static void base64_test(){
        final String TAG = "BASE64_TEST";
        byte [] code = null;

        code = Crypto.base64_encode("123".getBytes());

        Log.d(TAG,new String(code));
    }

    public static void crc8_test(){
        final String TAG = "CRC8_TEST";
        byte [] test = new byte[1];
        byte [] crc8 = new byte[256];
        int i=0;

        for(i=0;i<0xff;i++) {
            test[0] = (byte)(i&0xff);
            crc8[i] = Crypto.crc8(test,1);
        }
        test[0] = (byte)0xff;
        crc8[0xff] = Crypto.crc8(test,1);
        Log.d(TAG, Utils.hexText(crc8));
    }

    public static void wml_data_test(){
        final String TAG="WML_TEST";


        byte [] mcastdata = WMLTeller.prepareWMLConfigData("88888888","mgd","someoneunlikeyou".getBytes());
        Log.d(TAG,"mcastdata: "+Utils.hexText(mcastdata));

        String [][] groupaddr = WMLTeller.genMcastAddressGroupTestData(mcastdata);
        Log.d("TAG","group address length: "+groupaddr.length);
        String wmlinfo = "";
        for(int i=0;i<groupaddr.length;i++) {
            wmlinfo += "{\"" + groupaddr[i][0]+"\",\""+groupaddr[i][1]+"\"},\n";
        }

        Log.d("TAG",wmlinfo);
    }

}
