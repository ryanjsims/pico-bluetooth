#pragma once
#include <pico/time.h>

#define LOG_LEVEL_TRACE    0
#define LOG_LEVEL_DEBUG    1
#define LOG_LEVEL_INFO     2
#define LOG_LEVEL_WARN     3
#define LOG_LEVEL_CRITICAL 4
#define LOG_LEVEL_ERROR    5
#define LOG_LEVEL_DISABLE  6

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

#if LOG_LEVEL<=0
#define trace(message, ...) printf("[trace %d] " message, to_ms_since_boot(get_absolute_time()), __VA_ARGS__)
#define trace1(message) printf("[trace %d] " message, to_ms_since_boot(get_absolute_time()))
#define trace_cont(message, ...) printf(message, __VA_ARGS__)
#define trace_cont1(message) printf(message)
#else
#define trace(message, ...) (void)0
#define trace1(message) (void)0
#define trace_cont(message, ...) (void)0
#define trace_cont1(message) (void)0
#endif

#if LOG_LEVEL<=1
#define debug(message, ...) printf("[debug %d] " message, to_ms_since_boot(get_absolute_time()), __VA_ARGS__)
#define debug1(message) printf("[debug %d] " message, to_ms_since_boot(get_absolute_time()))
#define debug_cont(message, ...) printf(message, __VA_ARGS__)
#define debug_cont1(message) printf(message)
#else
#define debug(message, ...) (void)0
#define debug1(message) (void)0
#define debug_cont(message, ...) (void)0
#define debug_cont1(message) (void)0
#endif

#if LOG_LEVEL<=2
#define info(message, ...) printf("[info %d] " message, to_ms_since_boot(get_absolute_time()), __VA_ARGS__)
#define info1(message) printf("[info %d] " message, to_ms_since_boot(get_absolute_time()))
#define info_cont(message, ...) printf(message, __VA_ARGS__)
#define info_cont1(message) printf(message)
#else
#define info(message, ...) (void)0
#define info1(message) (void)0
#define info_cont(message, ...) (void)0
#define info_cont1(message) (void)0
#endif

#if LOG_LEVEL<=3
#define warn(message, ...) printf("[warn %d] " message, to_ms_since_boot(get_absolute_time()), __VA_ARGS__)
#define warn1(message) printf("[warn %d] " message, to_ms_since_boot(get_absolute_time()))
#define warn_cont(message, ...) printf(message, __VA_ARGS__)
#define warn_cont1(message) printf(message)
#else
#define warn(message, ...) (void)0
#define warn1(message) (void)0
#define warn_cont(message, ...) (void)0
#define warn_cont1(message) (void)0
#endif

#if LOG_LEVEL<=4
#define critical(message, ...) printf("[critical %d] " message, to_ms_since_boot(get_absolute_time()), __VA_ARGS__)
#define critical1(message) printf("[critical %d] " message, to_ms_since_boot(get_absolute_time()))
#define critical_cont(message, ...) printf(message, __VA_ARGS__)
#define critical_cont1(message) printf(message)
#else
#define critical(message, ...) (void)0
#define critical1(message) (void)0
#define critical_cont(message, ...) (void)0
#define critical_cont1(message) (void)0
#endif

#if LOG_LEVEL<=5
#define error(message, ...) printf("[error %d] " message, to_ms_since_boot(get_absolute_time()), __VA_ARGS__)
#define error1(message) printf("[error %d] " message, to_ms_since_boot(get_absolute_time()))
#define error_cont(message, ...) printf(message, __VA_ARGS__)
#define error_cont1(message) printf(message)
#else
#define error(message, ...) (void)0
#define error1(message) (void)0
#define error_cont(message, ...) (void)0
#define error_cont1(message) (void)0
#endif