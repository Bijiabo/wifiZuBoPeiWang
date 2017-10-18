/*
 * CRC8 implementation
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#include "stdlib.h"

#define CRC8_POLY   0x1D

/**
 * crc8 - crc8 calculation
 * @data: data to be check
 * @size: Length of the data to check
 * @Returns:crc8 value
 */

unsigned char crc8(unsigned char* data, int  size)
{
    int i;
    unsigned char crc = 0;
    unsigned char bit = 0;

    for (i=0;i<size;i++)
    {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++)
        {
            if (crc & 0x80)
            {
                crc <<= 1;
                crc ^= CRC8_POLY;
            }
            else
            {
                crc <<= 1;
            }
        }
    }

    return crc;
}
