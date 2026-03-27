/**
 * @file logger.h
 * @brief Compile-time configurable logging macros for peconv.
 *
 * Verbosity is controlled at compile time via the @c LOG_VERBOSITY preprocessor
 * symbol. Any message whose level exceeds @c LOG_VERBOSITY is compiled out
 * entirely — no runtime overhead, no branch, no string literal in the binary.
 *
 * By default messages are written to @c stderr. Define @c LOG_USE_DEBUGOUT
 * before including this header (or via the build system) to redirect output
 * to the Windows debugger via @c OutputDebugStringA instead.
 *
 * **Typical build-system usage:**
 * @code
 * // Errors only (default):
 * #define LOG_VERBOSITY LOG_LEVEL_ERROR
 *
 * // Full tracing:
 * #define LOG_VERBOSITY LOG_LEVEL_DEBUG
 *
 * // Redirect to debugger output:
 * #define LOG_USE_DEBUGOUT
 * @endcode
 */
#pragma once
#include <stdio.h>

// Verbosity levels
#define LOG_LEVEL_NONE    0 // silent
#define LOG_LEVEL_ERROR   1 // something broke
#define LOG_LEVEL_WARNING 2 // something looks wrong
#define LOG_LEVEL_INFO    3 // notable operational events
#define LOG_LEVEL_DEBUG   4 // detailed tracing, noisy

#ifndef LOG_VERBOSITY
#  define LOG_VERBOSITY LOG_LEVEL_ERROR
#endif

// Output sink selection
#ifdef LOG_USE_DEBUGOUT
#  include <windows.h>
#  include <stdio.h>
   // Format into a local buffer, then hand off to OutputDebugStringA
#  define _LOG(tag, fmt, ...)                                          \
       do {                                                            \
           char _log_buf[512];                                         \
           snprintf(_log_buf, sizeof(_log_buf),                        \
                    "[" tag "] %s:%d: " fmt "\n",                      \
                    __FILE__, __LINE__, ##__VA_ARGS__);                 \
           OutputDebugStringA(_log_buf);                               \
       } while(0)
#else
#  define _LOG(tag, fmt, ...)                                          \
       fprintf(stderr, "[" tag "] %s:%d: " fmt "\n",                  \
               __FILE__, __LINE__, ##__VA_ARGS__)
#endif

// Public macros
#if LOG_VERBOSITY >= LOG_LEVEL_ERROR
#  define LOG_ERROR(fmt, ...)   _LOG("ERROR",   fmt, ##__VA_ARGS__)
#else
#  define LOG_ERROR(fmt, ...)   do {} while(0)
#endif

#if LOG_VERBOSITY >= LOG_LEVEL_WARNING
#  define LOG_WARNING(fmt, ...) _LOG("WARNING", fmt, ##__VA_ARGS__)
#else
#  define LOG_WARNING(fmt, ...) do {} while(0)
#endif

#if LOG_VERBOSITY >= LOG_LEVEL_INFO
#  define LOG_INFO(fmt, ...)    _LOG("INFO",    fmt, ##__VA_ARGS__)
#else
#  define LOG_INFO(fmt, ...)    do {} while(0)
#endif

#if LOG_VERBOSITY >= LOG_LEVEL_DEBUG
#  define LOG_DEBUG(fmt, ...)   _LOG("DEBUG",   fmt, ##__VA_ARGS__)
#else
#  define LOG_DEBUG(fmt, ...)   do {} while(0)
#endif
