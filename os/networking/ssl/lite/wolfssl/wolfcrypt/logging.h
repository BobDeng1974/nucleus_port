/* logging.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


/* submitted by eof */


#ifndef WOLFSSL_LOGGING_H
#define WOLFSSL_LOGGING_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum  CYA_Log_Levels {
    ERROR_LOG = 0,
    INFO_LOG,
    ENTER_LOG,
    LEAVE_LOG,
    OTHER_LOG
};

typedef void (*wolfSSL_Logging_cb)(const int logLevel,
                                  const char *const logMessage);

WOLFSSL_API int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);

#ifdef DEBUG_WOLFSSL

    void WOLFSSL_ENTER(const char* msg);
    void WOLFSSL_LEAVE(const char* msg, int ret);

    void WOLFSSL_ERROR(int);
    void WOLFSSL_MSG(const char* msg);

#else /* DEBUG_WOLFSSL   */

    #define WOLFSSL_ENTER(m)
    #define WOLFSSL_LEAVE(m, r)

    #define WOLFSSL_ERROR(e)
    #define WOLFSSL_MSG(m)

#endif /* DEBUG_WOLFSSL  */

#ifdef __cplusplus
}
#endif
#endif /* WOLFSSL_LOGGING_H */

