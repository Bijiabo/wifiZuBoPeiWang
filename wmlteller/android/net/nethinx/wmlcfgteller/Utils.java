/*
 * code transform
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README and COPYING for more details.
 */
package net.nethinx.wmlcfgteller;


public class Utils {
    public static final int DEFAULT_HEXBUF_LENGTH = 128;

    /**
     * safecast - cast a byte value to int
     *
     * @param c: data to be cast
     */
    public static int safecast(byte c){
        return (int)c&0xFF;
    }

    /**
     * hexCode - transform a hex string into binary stream
     *
     * @param code: data to be transform
     */
    public static byte [] hexCode(String code){
        byte [] dat;
        int length ;
        int i,j;
        byte b;
        char c;

        if(code == null)
            return null;

        length = code.length();
        dat = new byte[length/2];

        j = 0;
        b = 0;
        for(i=0;i<length;i++){
            c = code.charAt(i);
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
                dat[i/2] = b;
                b = 0;
                j = 0;
            }
        }

        return dat;
    }

    /**
     * hexText - transform a byte value into a ２-hex-char string
     *
     * @param dat: data to be transform
     */
    public static String hexText(byte  dat){
        StringBuffer sbuf ;
        char c;

        sbuf =  new StringBuffer(DEFAULT_HEXBUF_LENGTH);

        c = (char)((dat>>4)&0x0F);
        if(c>9)
            sbuf.append((char)(c-10+'a'));
        else
            sbuf.append((char)(c+'0'));
        c = (char)(dat&0x0F);
        if(c>9)
            sbuf.append((char)(c-10+'a'));
        else
            sbuf.append((char)(c+'0'));


        return sbuf.toString();
    }

    /**
     * hexText - transform binary code into a hex string
     *
     * @param dat: data to be transform
     */
    public static String hexText(byte [] dat){
        StringBuffer sbuf ;
        int i,length;
        char c;

        if(dat == null)
            return null;

        length = dat.length;
        sbuf =  new StringBuffer(DEFAULT_HEXBUF_LENGTH);

        for(i=0;i<length;i++){

            c = (char)((dat[i]>>4)&0x0F);
            if(c>9)
                sbuf.append((char)(c-10+'a'));
            else
                sbuf.append((char)(c+'0'));
            c = (char)(dat[i]&0x0F);
            if(c>9)
                sbuf.append((char)(c-10+'a'));
            else
                sbuf.append((char)(c+'0'));
        }

        return sbuf.toString();
    }
}
