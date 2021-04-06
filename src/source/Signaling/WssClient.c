/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#define LOG_CLASS "WssClient"
#include "../Include_i.h"

#define WSS_CLIENT_ENTER() //DLOGD("enter")
#define WSS_CLIENT_EXIT() //DLOGD("exit")

//#include "json_helper.h"
//#include "http_helper.h"
//#include "parson.h"
//#include "wslay/wslay.h"
//mbedtls
//#include <mbedtls/base64.h>
//#include <mbedtls/sha1.h>
//#include "mbedtls/entropy.h"
//#include "mbedtls/ctr_drbg.h"

// platform
//#include <errno.h> // #YC_TBD.
//#include <sys/epoll.h>// #YC_TBD.
//#include <pthread.h>
// time

#define CLIENT_LOCK(pCtx) MUTEX_LOCK(pCtx->client_lock)
#define CLIENT_UNLOCK(pCtx) MUTEX_UNLOCK(pCtx->client_lock)

/*-----------------------------------------------------------*/
STATUS wssClientGenerateRandomNumber(PCHAR num, UINT32 len)
{
    WSS_CLIENT_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    retStatus = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy, NULL, 0);
    if( retStatus != 0 )
    {
        DLOGD("setup ctr_drbg failed(%d)", retStatus);
        return -1;
    }
    retStatus = mbedtls_ctr_drbg_random( &ctr_drbg, (UINT8*)num, len);
    if( retStatus != 0 )
    {
        DLOGD("access ctr_drbg failed(%d)", retStatus);
        return -1;
    }

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    WSS_CLIENT_EXIT();
    return 0;
}

STATUS wssClientGenerateClientKey(PCHAR buf, UINT32 bufLen)
{
    WSS_CLIENT_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 olen = 0;
    CHAR randomNum[WSS_CLIENT_RANDOM_SEED_LEN+1];
    MEMSET(randomNum, 0, WSS_CLIENT_RANDOM_SEED_LEN+1);
    // get random value.
    retStatus = wssClientGenerateRandomNumber(randomNum, WSS_CLIENT_RANDOM_SEED_LEN);
    if( retStatus != 0 )
    {
        DLOGD("generate the random value failed(%d)", retStatus);
        return -1;
    }
    // base64 the random value.
    retStatus = mbedtls_base64_encode((UINT8*)buf, bufLen, (VOID*)&olen, (UINT8*)randomNum, WSS_CLIENT_RANDOM_SEED_LEN );
    if( retStatus != 0 )
    {
        DLOGD("base64-encode the random value failed(%d)", retStatus);
        return -1;
    }
    if(olen != WSS_CLIENT_BASED64_RANDOM_SEED_LEN){
        DLOGD("the invalid length of the base64-encoded random value%d)", retStatus);
        return -1;
    }
    WSS_CLIENT_EXIT();
    return retStatus;
}

/**
 * @brief create accept key according to the client key.
 *        #YC_TBD,
 * @return
*/
STATUS wssClientGenerateAcceptKey(PCHAR clientKey, UINT32 clientKeyLen, PCHAR acceptKey, UINT32 acceptKeyLen)
{
    WSS_CLIENT_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 bufLen = WSS_CLIENT_BASED64_RANDOM_SEED_LEN+WSS_CLIENT_RFC6455_UUID_LEN+1;
    UINT8 buf[bufLen];
    UINT8 obuf[WSS_CLIENT_SHA1_RANDOM_SEED_W_UUID_LEN+1];
    UINT32 olen = 0;
    MEMSET(buf, 0, bufLen);
    MEMSET(obuf, 0, WSS_CLIENT_SHA1_RANDOM_SEED_W_UUID_LEN+1);
    MEMCPY(buf, clientKey, STRLEN(clientKey));
    MEMCPY(buf+STRLEN(clientKey), WSS_CLIENT_RFC6455_UUID, STRLEN(WSS_CLIENT_RFC6455_UUID));
    mbedtls_sha1( buf, STRLEN((PCHAR)buf), obuf );
    retStatus = mbedtls_base64_encode((UINT8*)acceptKey, acceptKeyLen, (VOID*)&olen, (UINT8*)obuf, 20);

    if( retStatus!=0 || olen != WSS_CLIENT_ACCEPT_KEY_LEN){
        DLOGD("base64-encode accept key failed");
    }

    WSS_CLIENT_EXIT();
    return retStatus;
}

STATUS wssClientValidateAcceptKey(PCHAR clientKey, UINT32 clientKeyLen, PCHAR acceptKey, UINT32 acceptKeyLen)
{
    WSS_CLIENT_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    UINT8 tmpKey[WSS_CLIENT_ACCEPT_KEY_LEN+1];
    MEMSET(tmpKey, 0, WSS_CLIENT_ACCEPT_KEY_LEN+1);
    retStatus = wssClientGenerateAcceptKey(clientKey, clientKeyLen, (PCHAR)tmpKey, WSS_CLIENT_ACCEPT_KEY_LEN+1);
    if( retStatus != STATUS_SUCCESS ){
        DLOGD("generating accept key failed");
    }
    //wssClientGenerateAcceptKey(clientKey, clientKeyLen, buf, WSS_CLIENT_ACCEPT_KEY_LEN);
    if(MEMCMP(tmpKey, acceptKey, WSS_CLIENT_ACCEPT_KEY_LEN)!=0){
        DLOGD("validate accept key failed");
        return -1;
    }
    WSS_CLIENT_EXIT();
    return 0;
}

/**
 * @brief   send data to the socket layer.
 * 
 * @param[in]
 * 
 * @return
*/
INT32 wssClientSocketSend(WssClientContext* pCtx, const UINT8* data, SIZE_T len, INT32 flags)
{
    //DLOGD("S ==>");
    return networkSend( pCtx->pNetworkContext, data, len );
}
/**
 * @brief   receive data from the socket layer.
 * 
 * @param[in]
 * @return
*/
INT32 wssClientSocketRead(WssClientContext* pCtx, UINT8* data, SIZE_T len, INT32 flags)
{
    //DLOGD("R <==");
    return networkRecv( pCtx->pNetworkContext, data, len );
}

SSIZE_T wssClientFeedBody(WssClientContext* pCtx, UINT8 *data, SIZE_T len) 
{
  DLOGD("feed body callback****");
  return 0;
}
/**
 * @brief   the callback for wslay.
 * 
 * @param[in]
 * 
 * @return
*/
SSIZE_T wslay_send_callback(wslay_event_context_ptr ctx,
                      const UINT8 *data,
                      SIZE_T len,
                      INT32 flags,
                      VOID *user_data) 
{
    WssClientContext *pCtx = (WssClientContext *)user_data;
    SSIZE_T r = wssClientSocketSend(pCtx, data, len, flags);
    if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    }
    return r;
}

SSIZE_T wslay_recv_callback(wslay_event_context_ptr ctx,
                      UINT8 *data,
                      SIZE_T len,
                      INT32 flags,
                      VOID *user_data) 
{
    WssClientContext *pCtx = (WssClientContext *)user_data;
    SSIZE_T r = wssClientSocketRead(pCtx, data, len, flags);
    if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    } else if (r == 0) {
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        r = -1;
    }
    return r;
}


INT32 wslay_genmask_callback(wslay_event_context_ptr ctx, UINT8 *buf, SIZE_T len,
                     VOID *user_data) 
{
    WssClientContext *ws = (WssClientContext *)user_data;
    wssClientGenerateRandomNumber((PCHAR)buf, len);
    return 0;
}

VOID wslay_msg_recv_callback(wslay_event_context_ptr ctx,
                          const struct wslay_event_on_msg_recv_arg *arg,
                          VOID *user_data) 
{
    WssClientContext *ws = (WssClientContext *)user_data;
    if (!wslay_is_ctrl_frame(arg->opcode)) {
        //struct wslay_event_msg msgarg = {arg->opcode, arg->msg, arg->msg_length};
        //wslay_event_queue_msg(ctx, &msgarg);
        //DLOGD("<== (%d): %s", arg->opcode, arg->msg);
        // #YC_TBD, 
        ws->messageHandler(ws->pUserData, arg->msg, arg->msg_length);
    }else{
        if(arg->opcode==WSLAY_PONG){
            DLOGD("<== pong, len: %ld", arg->msg_length);
        }else if(arg->opcode==WSLAY_PING){
            DLOGD("<== ping, len: %ld", arg->msg_length);
        }else if(arg->opcode==WSLAY_CONNECTION_CLOSE){
            DLOGD("<== connection close, len: %ld, reason:%s", arg->msg_length, arg->msg);
        }else{
            DLOGD("<== ctrl msg(%d), len: %ld", arg->opcode, arg->msg_length);
        }
    }
}

SSIZE_T wslay_feed_body_callback(wslay_event_context_ptr ctx, UINT8 *data,
                           SIZE_T len, INT32 flags, VOID *user_data)
{
    WssClientContext *pCtx = (WssClientContext *)user_data;
    return wssClientFeedBody(pCtx, data, len);
}


/*-----------------------------------------------------------*/
/**
 * @brief the following APIs need to be protected by client mutex.
*/
/*-----------------------------------------------------------*/


INT32 wssClientWantRead(WssClientContext* pCtx)
{
    WSS_CLIENT_ENTER();
    INT32 retStatus = TRUE;
    CLIENT_LOCK(pCtx);
    retStatus = wslay_event_want_read(pCtx->event_ctx);
    CLIENT_UNLOCK(pCtx);
    WSS_CLIENT_EXIT();
    return retStatus;
}

INT32 wssClientWantWrite(WssClientContext* pCtx)
{
    WSS_CLIENT_ENTER();
    INT32 retStatus = 0;
    CLIENT_LOCK(pCtx);
    retStatus = wslay_event_want_write(pCtx->event_ctx);
    CLIENT_UNLOCK(pCtx);
    WSS_CLIENT_EXIT();
    return retStatus;
}

INT32 wssClientOnReadEvent(WssClientContext* pCtx)
{
    WSS_CLIENT_ENTER();
    INT32 retStatus = 0;
    CLIENT_LOCK(pCtx);
    retStatus = wslay_event_recv(pCtx->event_ctx);
    CLIENT_UNLOCK(pCtx);
    WSS_CLIENT_EXIT();
    return retStatus;
}

INT32 wssClientOnWriteEvent(WssClientContext* pCtx)
{
    WSS_CLIENT_ENTER();
    INT32 retStatus = 0;
    CLIENT_LOCK(pCtx);
    //DLOGD("transmitted");
    retStatus = wslay_event_send(pCtx->event_ctx);
    //DLOGD("transmission handled");
    CLIENT_UNLOCK(pCtx);
    WSS_CLIENT_EXIT();
    return retStatus;
}

static INT32 wssClientSend(WssClientContext* pCtx, struct wslay_event_msg* arg)
{
    WSS_CLIENT_ENTER();
    INT32 retStatus = 0;
    CLIENT_LOCK(pCtx);
    
    retStatus = wslay_event_queue_msg(pCtx->event_ctx, arg);
    CLIENT_UNLOCK(pCtx);
    WSS_CLIENT_EXIT();
    return retStatus;
}

INT32 wssClientSendText(WssClientContext* pCtx, UINT8* buf, UINT32 len)
{
    struct wslay_event_msg arg;
    arg.opcode = WSLAY_TEXT_FRAME;
    arg.msg = buf;
    arg.msg_length = len;
    return wssClientSend(pCtx, &arg);
}

INT32 wssClientSendBinary(WssClientContext* pCtx, UINT8* buf, UINT32 len)
{
    struct wslay_event_msg arg;
    arg.opcode = WSLAY_BINARY_FRAME;
    arg.msg = buf;
    arg.msg_length = len;
    return wssClientSend(pCtx, &arg);
}

INT32 wssClientSendPing(WssClientContext* pCtx)
{
    struct wslay_event_msg arg;
    MEMSET(&arg, 0, sizeof(arg));
    arg.opcode = WSLAY_PING;
    arg.msg_length = 0;
    DLOGD("ping ==>");
    return wssClientSend(pCtx, &arg);
}



/**
 * @brief create the context of wss client and initialize the wss client.
 * 
 * @param[in, out]
 * @param[in] pNetworkContext
 * 
 * @return
*/
VOID wssClientCreate(WssClientContext** ppWssClientCtx, NetworkContext_t * pNetworkContext, PVOID arg, MessageHandlerFunc pFunc)
{
    WSS_CLIENT_ENTER();
    INT32 retStatus = 0;
    WssClientContext* pCtx = malloc(sizeof(WssClientContext));
    MEMSET(pCtx, 0, sizeof(WssClientContext));

    struct wslay_event_callbacks callbacks = {
                                    wslay_recv_callback, /* wslay_event_recv_callback */
                                    wslay_send_callback, /* wslay_event_send_callback */
                                    wslay_genmask_callback, /* wslay_event_genmask_callback */
                                    NULL, /* wslay_event_on_frame_recv_start_callback */
                                    NULL, /* wslay_event_on_frame_recv_chunk_callback */
                                    NULL, /* wslay_event_on_frame_recv_end_callback */
                                    wslay_msg_recv_callback /* wslay_event_on_msg_recv_callback */
                                    };

    pCtx->event_callbacks = callbacks;
    pCtx->pNetworkContext = pNetworkContext;
    pCtx->pUserData = arg;
    pCtx->messageHandler = pFunc;

    // the initialization of the mutex 
    pCtx->client_lock = MUTEX_CREATE(FALSE);
    wslay_event_context_client_init(&pCtx->event_ctx, &pCtx->event_callbacks, pCtx);;
    *ppWssClientCtx = pCtx;
    WSS_CLIENT_EXIT();
    return;
}
/**
 * @brief 
 * 
 * @param[in]
 * 
 * @return
*/
INT32 wssClientStart(WssClientContext* pWssClientCtx)
{
    WSS_CLIENT_ENTER();
    BOOL ok = TRUE;
    // for the inteface of socket.
    INT32 nfds = 0;
    INT32 retval;
    fd_set rfds;
    struct timeval tv;
    // for ping-pong.
    UINT32 counter = 0;

    wslay_event_config_set_callbacks(pWssClientCtx->event_ctx, &pWssClientCtx->event_callbacks);
    mbedtls_ssl_conf_read_timeout(&(pWssClientCtx->pNetworkContext->conf), WSS_CLIENT_POLLING_INTERVAL);

    nfds = pWssClientCtx->pNetworkContext->server_fd.fd;
    FD_ZERO(&rfds);

    // check the wss client want to read or write or not.
    DLOGD("wss client start");
    while (wssClientWantRead(pWssClientCtx) || wssClientWantWrite(pWssClientCtx)) {
        // need to setup the timeout of epoll in order to let the wss cleint thread to write the buffer out.
	    FD_SET(nfds, &rfds);
        // #YC_TBD, this may need to be modified.
        tv.tv_sec = 0;
        tv.tv_usec = WSS_CLIENT_POLLING_INTERVAL*1000;
        retval = select(nfds+1, &rfds, NULL, NULL, &tv);
        
        if (retval == -1) {
            DLOGE("select() failed with errno %s", getErrorString(getErrorCode()));
            continue;
        }
        if(FD_ISSET(nfds, &rfds))
        {
            wssClientOnReadEvent(pWssClientCtx);
        }
        // for ping-pong
        counter++;
        if(counter == WSS_CLIENT_PING_PONG_COUNTER)
        {  
            wssClientSendPing(pWssClientCtx);
            counter = 0;
        }
        
        wssClientOnWriteEvent(pWssClientCtx);
    }


    DLOGD("wss client end");
    WSS_CLIENT_EXIT();
    return ok ? 0 : -1;
}


VOID wssClientClose(WssClientContext* pWssClientCtx)
{
    INT32 retStatus = 0;
    CLIENT_LOCK(pWssClientCtx);
    wslay_event_shutdown_read(pWssClientCtx->event_ctx);
    wslay_event_shutdown_write(pWssClientCtx->event_ctx);

    if (IS_VALID_MUTEX_VALUE(pWssClientCtx->client_lock)) {
        MUTEX_FREE(pWssClientCtx->client_lock);
    }
    free(pWssClientCtx);
    return;
}
/*-----------------------------------------------------------*/



