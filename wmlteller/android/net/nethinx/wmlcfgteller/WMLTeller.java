/*
 * WML Teller implementation and interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
package net.nethinx.wmlcfgteller;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;


public class WMLTeller {
    private static final byte PREAMBLE[]={'w','m','l'};
    private static final String INFO = "wcfg";
    private static final int HEADERLEN = 12;
    private static final byte PROTOCOL = 0x01;
    private static final byte VER = 0x01;
    private static final int MCASTGROUPADDR0 = 227;
    private static final int MCASTGROUPADDR1_START = 1;
    private static final int MCASTGROUPPORT = 2017;

    private WifiManager wifiManager;
    private WifiManager.MulticastLock multicastLock;
    private WMLCfgThread wmlcfgtread;
    private String SSID;
    private String PassPhrase;
    private byte[] Key;

    /**
     * WMLTeller - constructor
     *
     * @param context: app context
     * @param passphrase: passphrase of wifi
     * @param ssid: ssid of wifi
     * @param key:  aes encrypt key
     */
    public WMLTeller(Context context, String passphrase, String ssid, byte [] key){
        if(ssid == null || key == null || key.length !=16)
            throw new IllegalArgumentException();

        wifiManager = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);
        SSID = ssid;
        PassPhrase = passphrase;
        Key = key;
    }

    /**
     * prepareWMLConfigData - prepare WML packet data
     *
     * @param passphrase: passphrase of wifi
     * @param ssid: ssid of wifi
     * @param key:  aes encrypt key
     */
    public static byte [] prepareWMLConfigData(String passphrase,String ssid, byte [] key){
        byte [] mcastdata = null;
        byte [] passwd = null;
        byte [] salt;
        byte [] pmk;
        byte [] info,aescipher,base64code;
        int infolen,offset,base64length;

        salt = ssid.getBytes();
        infolen = salt.length + 1;
        if(passphrase != null) {
            passwd = passphrase.getBytes();
            infolen += passwd.length;
        }
        infolen += 1;
        pmk = Crypto.wpa_passphrase_pmk_generate(passphrase.toCharArray(),salt);
        infolen += pmk.length + 1;

        infolen += 16-(infolen%16);
        info = new byte[infolen];

        offset = 0;
        info[offset] = (byte)(salt.length&0xFF);
        offset += 1;
        System.arraycopy(salt,0,info,offset,salt.length);
        offset += salt.length;
        if(passwd != null){
            info[offset] = (byte) (passwd.length&0xFF);
            offset += 1;
            System.arraycopy(passwd,0,info,offset,passwd.length);
            offset += passwd.length;
        }else{
            info[offset] = 0;
            offset += 1;
        }

        info[offset] = (byte)(pmk.length&0xFF);
        offset += 1;
        System.arraycopy(pmk,0,info,offset,pmk.length);
        aescipher = Crypto.aes_ecb128_encrypt(info,key);
        base64code = Crypto.base64_encode(aescipher);

        Log.d("prepareWMLConfigData",Utils.hexText(base64code));
        base64length = base64code.length;
        if(base64code[base64length-1]==0x0a)
            base64length -= 1;

        mcastdata = new byte[HEADERLEN+base64length];
        //PREABLE
        mcastdata[0] = PREAMBLE[0];
        mcastdata[1] = (byte)~PREAMBLE[0];
        mcastdata[2] = PREAMBLE[1];
        mcastdata[3] = (byte)~PREAMBLE[1];
        mcastdata[4] = PREAMBLE[2];
        mcastdata[5] = (byte)~PREAMBLE[2];
        //PROTOCOL
        mcastdata[6] = PROTOCOL;
        //PROTO VERSION
        mcastdata[7] = VER;
        //Group Index
        mcastdata[8] = 0;
        //Groups total
        mcastdata[9] = 1;
        //CRC8
        mcastdata[10] = Crypto.crc8(base64code,base64length);
        //Packets double rate
        mcastdata[11] = (byte)((base64length/2)&0xFF);

        System.arraycopy(base64code,0,mcastdata,HEADERLEN,base64length);

        return mcastdata;
    }

    /**
     * genMcastGroupList - generate multicast group address list
     *
     * @param mcastdata: data to be multicast addr2 and addr3
     */
    public static String[] genMcastGroupList(byte [] mcastdata){
        String [] grouplist;
        int length;

        length = mcastdata.length;
        grouplist = new String[length/2];//double rate
        for(int i=0;i<length;i+=2){
            grouplist[i/2] = String.format("%d.%d.%d.%d",
                    MCASTGROUPADDR0,
                    MCASTGROUPADDR1_START+i/2,
                    Utils.safecast(mcastdata[i]),
                    Utils.safecast(mcastdata[i+1]));
        }

        return grouplist;
    }

    /**
     * genMcastAddressGroupTestData - generate multicast group address test data for "wml_client"
     *
     * @param mcastdata: data to be multicast addr2 and addr3
     */
    public static String[][] genMcastAddressGroupTestData(byte [] mcastdata){
        String [][] grouplist;
        int length;

        length = mcastdata.length;
        grouplist = new String[length/2][2];//double rate
        for(int i=0;i<length;i+=2){
            grouplist[i/2][0] = String.format("01005e%02x%02x%02x",
                    MCASTGROUPADDR1_START+i/2,
                    Utils.safecast(mcastdata[i]),
                    Utils.safecast(mcastdata[i+1]));
            grouplist[i/2][1] = "d81d72df3866";
        }

        return grouplist;
    }

    /**
     * WMLCfgThread - Thread to send data
     *
     */
    private class  WMLCfgThread extends Thread {
        private String[] grouplist;
        private boolean exit = false;

        /**
         * WMLCfgThread - constructor
         *
         * @param gplst: multicast destination group address list
         */
        WMLCfgThread(String[] gplst) {
            grouplist = gplst;
        }

        public void terminate(){
            exit = true;
            WMLCfgThread.interrupted();
        }

        @Override
        public void run() {
            DatagramSocket datagramsocket;
            InetAddress address;
            DatagramPacket datagramPacket;

            while(!exit) {
                try {
                    for (int i = 0; i < grouplist.length; i++) {
                        datagramsocket = new DatagramSocket();
                        address = InetAddress.getByName(grouplist[i]);
                        datagramPacket = new DatagramPacket(INFO.toString().getBytes(), INFO.length(), address, MCASTGROUPPORT);
                        datagramsocket.send(datagramPacket);
                    }
                    sleep(200);
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (SocketException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };
    }

    /**
     * startWMLConfig - start wml config
     *
     */
    public void startWMLConfig(){
        byte [] mcastdata;
        String [] grouplist;

        if(wifiManager.isWifiEnabled()) {
            multicastLock = wifiManager.createMulticastLock("wmlcfg");
            multicastLock.setReferenceCounted(true);
            multicastLock.acquire();
            mcastdata = prepareWMLConfigData(PassPhrase,SSID,Key);

            grouplist = genMcastGroupList(mcastdata);
            wmlcfgtread = new WMLCfgThread(grouplist);
            wmlcfgtread.start();
        }
    }

    /**
     * stop - start wml config
     *
     */
    public void stopWMLConfig(){
        if(wmlcfgtread!=null) {
            wmlcfgtread.terminate();
            wmlcfgtread = null;
        }
        if (multicastLock != null) {
            multicastLock.release();
            multicastLock = null;
        }
    }
}
