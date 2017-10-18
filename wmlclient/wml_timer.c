/*
 * WML timer interface functions
 * Copyright (c) 2016, Shoowing <420260138@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Apache License Version 2.0
 *
 * See README for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include "time.h"

#include "wml_timer.h"

void wml_timer_init(wmlTimer * wmltimer,wmlTimerCallback cb,u32 schedule,u32 timeout)
{
    if(NULL == wmltimer)
        return ;

    __ToBeDo_Start("init the platform's timer");
    __ToBeDo_End("init the platform's timer");
    wmltimer->cb = cb;
    wmltimer->schedule = schedule;
    wmltimer->timeout = timeout;
}

void wml_timer_reset(wmlTimer * wmltimer)
{
    // make the timer count again from now
    __ToBeDo_Start("reset the platform's timer");
    __ToBeDo_End("reset the platform's timer");
}

void wml_timer_start(wmlTimer * wmltimer)
{
    __ToBeDo_Start("start the platform's timer");
    __ToBeDo_End("start the platform's timer");
}

void wml_timer_stop(wmlTimer * wmltimer)
{
    __ToBeDo_Start("stop the platform's timer");
    __ToBeDo_End("stop the platform's timer");
}

void wml_timer_process(void)
{
    __ToBeDo_Start("count the timer if neccessary");
    __ToBeDo_End("count the timer if neccessary");
}
