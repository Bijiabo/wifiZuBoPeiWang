/*
 * AES encryption interface function
 * Base64 encode interface function
 * CRC8 implementation
 * PBKDF2 With Hmac-SHA1 interface function
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README and COPYING for more details.
 */
package net.nethinx.wmlcfgteller;
import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class Crypto {

    /**
     * base64_encode - base64 encode and return a newly allocated
     * byte[] with the result.
     *
     * @param data: data to be encode
     */
    public static byte [] base64_encode(byte [] data){
        return Base64.encode(data,Base64.NO_WRAP);
    }

    /**
     * base64_decode - base64 decode and return a newly allocated
     * byte[] with the result.
     *
     * @param code: base64 code to be decode
     */
    public static byte [] base64_decode(byte [] code){
        return Base64.decode(code,Base64.DEFAULT);
    }

    /**
     * aes_ecb128_encrypt - aes ecb 128-bis encrypt and return a newly allocated
     * byte[] with the result.
     *
     * @param plain: plain text to be encrypt
     * @param key: aes 128 bits key
     */
    public static byte [] aes_ecb128_encrypt(byte [] plain, byte [] key){
        try {
            Cipher cipher;
            SecretKeySpec keyspec;

            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            keyspec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keyspec);
            return cipher.doFinal(plain);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * wpa_passphrase_pmk_generate - wpa passphrase pbkdef2 with HMAC-SHA1,return a newly allocated
     * byte[] with the result.
     *
     * @param passphrase: password of wifi
     * @param ssid: ssid of wifi
     */
    public static byte [] wpa_passphrase_pmk_generate(char [] passphrase,byte [] ssid){
        String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
        PBEKeySpec spec = new PBEKeySpec(passphrase, ssid, 4096, 32*8);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return f.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * crc8 - Cyclic Redundancy Check calculate,returns the result.
     *
     * @param dat: data to be check
     * @param length: length of data
     */

    public static byte crc8(byte [] dat, int length){
        final byte CRC8_POLY = 0x1D;
        byte crc8 = 0;
        byte bit;

        for(int i=0;i<length;i++)
        {
            crc8 ^= dat[i];
            for (bit = 0; bit < 8; bit++)
            {
                if ((crc8 & 0x80)==0x80)
                {
                    crc8 <<= 1;
                    crc8 ^= CRC8_POLY;
                }
                else
                {
                    crc8 <<= 1;
                }
            }
        }
        return crc8;
    }
}
