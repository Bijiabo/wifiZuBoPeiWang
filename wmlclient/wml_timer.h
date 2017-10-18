/*
 * WML timer interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#ifndef WML_TIMER_H
#define WML_TIMER_H

#include "wml_platform.h"
#include "wml_types.h"

typedef void (* wmlTimerCallback)(void);

typedef struct t_wml_timer{
    __ToBeDo("put a timer according to the platform")
    wmlTimerCallback cb;
    u32 schedule;//milisecond
    u32 timeout;//milisecond
}wmlTimer;

void wml_timer_init(wmlTimer * wmltimer,wmlTimerCallback cb,u32 schedule,u32 timeout);
void wml_timer_start(wmlTimer * wmltimer);
void wml_timer_reset(wmlTimer * wmltimer);
void wml_timer_stop(wmlTimer * wmltimer);
void wml_timer_process(void);

#endif
