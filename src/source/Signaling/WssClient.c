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

#define LOG_CLASS "wss_client"
#include "../Include_i.h"

#include "json_helper.h"
#include "http_helper.h"
#include "parson.h"
#include "wslay/wslay.h"
//mbedtls
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// platform
#include <errno.h> // #YC_TBD.
#include <sys/epoll.h>// #YC_TBD.
#include <pthread.h>
// time
#include <unistd.h>
#define CLIENT_LOCK(pCtx) pthread_mutex_lock(&pCtx->client_lock)
#define CLIENT_UNLOCK(pCtx) pthread_mutex_unlock(&pCtx->client_lock)

/*-----------------------------------------------------------*/
INT32 wss_client_generate_random_number(CHAR* num, UINT32 len)
{
  INT32 retStatus = 0;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );

  retStatus = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy, NULL, 0);
  if( retStatus != 0 )
  {
    DLOGD("setup ctr_drbg failed(%d)\n", retStatus);
    return -1;
  }
  retStatus = mbedtls_ctr_drbg_random( &ctr_drbg, num, len);
  if( retStatus != 0 )
  {
    DLOGD("access ctr_drbg failed(%d)\n", retStatus);
    return -1;
  }

  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  return 0;
}

INT32 wss_client_generate_client_key(CHAR* buf, UINT32 bufLen)
{
  INT32 retStatus = 0;
  UINT32 olen = 0;
  CHAR randomNum[WSS_CLIENT_RANDOM_SEED_LEN+1];
  memset(randomNum, 0, WSS_CLIENT_RANDOM_SEED_LEN+1);
  // get random value.
  retStatus = wss_client_generate_random_number(randomNum, WSS_CLIENT_RANDOM_SEED_LEN);
  if( retStatus != 0 )
  {
    DLOGD("generate the random value failed(%d)\n", retStatus);
    return -1;
  }
  // base64 the random value.
  retStatus = mbedtls_base64_encode(buf, bufLen, (VOID*)&olen, randomNum, WSS_CLIENT_RANDOM_SEED_LEN );
  if( retStatus != 0 )
  {
    DLOGD("base64-encode the random value failed(%d)\n", retStatus);
    return -1;
  }
  if(olen != WSS_CLIENT_BASED64_RANDOM_SEED_LEN){
    DLOGD("the invalid length of the base64-encoded random value%d)\n", retStatus);
    return -1;
  }

  return 0;
}

/**
 * @brief create accept key according to the client key.
 *        #YC_TBD,
 * @return
*/
INT32 wss_client_generate_accept_key(CHAR* clientKey, UINT32 clientKeyLen, CHAR* acceptKey, UINT32 acceptKeyLen)
{
  UINT32 retStatus = 0;
  UINT32 bufLen = WSS_CLIENT_BASED64_RANDOM_SEED_LEN+WSS_CLIENT_RFC6455_UUID_LEN+1;
  UINT8 buf[bufLen];
  UINT8 obuf[WSS_CLIENT_SHA1_RANDOM_SEED_W_UUID_LEN+1];
  UINT32 olen = 0;

  memset(buf, 0, bufLen);
  memset(obuf, 0, WSS_CLIENT_SHA1_RANDOM_SEED_W_UUID_LEN+1);

  memcpy(buf, clientKey, STRLEN(clientKey));
  memcpy(buf+STRLEN(clientKey), WSS_CLIENT_RFC6455_UUID, STRLEN(WSS_CLIENT_RFC6455_UUID));
  DLOGD("combined string(%ld):%s\n", STRLEN(buf), buf);

  mbedtls_sha1( buf, STRLEN(buf), obuf );
  retStatus = mbedtls_base64_encode(acceptKey, acceptKeyLen, (VOID*)&olen, obuf, 20);

  if( retStatus!=0 || olen != WSS_CLIENT_ACCEPT_KEY_LEN){
    DLOGD("base64-encode accept key failed\\n");
  }
  DLOGD("output(%ld):%s\n", STRLEN(acceptKey), acceptKey);

  return 0;
}

INT32 wss_client_validate_accept_key(CHAR* clientKey, UINT32 clientKeyLen, CHAR* acceptKey, UINT32 acceptKeyLen)
{
  INT32 retStatus = 0;
  UINT8 tmpKey[WSS_CLIENT_ACCEPT_KEY_LEN+1];
  memset(tmpKey, 0, WSS_CLIENT_ACCEPT_KEY_LEN+1);
  DLOGD("clientKey:%s\n", clientKey);
  retStatus = wss_client_generate_accept_key(clientKey, clientKeyLen, tmpKey, WSS_CLIENT_ACCEPT_KEY_LEN+1);
  if( retStatus!=0 ){
    DLOGD("generating accept key failed\\n");
  }
  //wss_client_generate_accept_key(clientKey, clientKeyLen, buf, WSS_CLIENT_ACCEPT_KEY_LEN);
  if(memcmp(tmpKey, acceptKey, WSS_CLIENT_ACCEPT_KEY_LEN)!=0){
    DLOGD("validate accept key failed\n");
      return -1;
  }
  return 0;
}

/**
 * @brief   send data to the socket layer.
 * 
 * @param[in]
 * 
 * @return
*/
INT32 wss_client_socket_send(wss_client_context_t* pCtx, const uint8_t* data, SIZE_T len, int flags)
{
  return networkSend( pCtx->pNetworkContext, data, len );
}
/**
 * @brief   receive data from the socket layer.
 * 
 * @param[in]
 * @return
*/
INT32 wss_client_socket_read(wss_client_context_t* pCtx, uint8_t* data, SIZE_T len, int flags)
{
  return networkRecv( pCtx->pNetworkContext, data, len );
}

ssize_t wss_client_feed_body(wss_client_context_t* pCtx, uint8_t *data, SIZE_T len) 
{
  DLOGD("feed body callback****\n");
  return 0;
}
/**
 * @brief   the callback for wslay.
 * 
 * @param[in]
 * 
 * @return
*/
ssize_t wslay_send_callback(wslay_event_context_ptr ctx,
                      const uint8_t *data,
                      SIZE_T len,
                      int flags,
                      VOID *user_data) 
{
  wss_client_context_t *pCtx = (wss_client_context_t *)user_data;
  ssize_t r = wss_client_socket_send(pCtx, data, len, flags);
  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  }
  return r;
}

ssize_t wslay_recv_callback(wslay_event_context_ptr ctx,
                      uint8_t *data,
                      SIZE_T len,
                      int flags,
                      VOID *user_data) 
{
  wss_client_context_t *pCtx = (wss_client_context_t *)user_data;
  ssize_t r = wss_client_socket_read(pCtx, data, len, flags);
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


int wslay_genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, SIZE_T len,
                     VOID *user_data) {
  wss_client_context_t *ws = (wss_client_context_t *)user_data;
  wss_client_generate_random_number(buf, len);
  return 0;
}

VOID wslay_msg_recv_callback(wslay_event_context_ptr ctx,
                          const struct wslay_event_on_msg_recv_arg *arg,
                          VOID *user_data) 
{
  wss_client_context_t *ws = (wss_client_context_t *)user_data;
  if (!wslay_is_ctrl_frame(arg->opcode)) {
    //struct wslay_event_msg msgarg = {arg->opcode, arg->msg, arg->msg_length};
    //wslay_event_queue_msg(ctx, &msgarg);
    DLOGD("received(%d): %s\n", arg->opcode, arg->msg);
  }else{
    DLOGD("<===   ");
    if(arg->opcode==WSLAY_PONG){
      DLOGD("received pong, len: %ld\n", arg->msg_length);
    }else if(arg->opcode==WSLAY_PING){
      DLOGD("received ping, len: %ld\n", arg->msg_length);
    }else if(arg->opcode==WSLAY_CONNECTION_CLOSE){
      DLOGD("received connection close, len: %ld\n", arg->msg_length);
    }else{
      DLOGD("received ctrl msg(%d), len: %ld\n", arg->opcode, arg->msg_length);
    }
  }
}

ssize_t feed_body_callback(wslay_event_context_ptr ctx, uint8_t *data,
                           SIZE_T len, int flags, VOID *user_data) {
  wss_client_context_t *pCtx = (wss_client_context_t *)user_data;
  return wss_client_feed_body(pCtx, data, len);
}


/*-----------------------------------------------------------*/
/**
 * @brief the following APIs need to be protected by client mutex.
*/
/*-----------------------------------------------------------*/


BOOL wss_client_want_read(wss_client_context_t* pCtx)
{
  BOOL retStatus = true;
  CLIENT_LOCK(pCtx);
  retStatus = wslay_event_want_read(pCtx->event_ctx);
  CLIENT_UNLOCK(pCtx);
  return retStatus;
}

BOOL wss_client_want_write(wss_client_context_t* pCtx)
{
  BOOL retStatus = true;
  CLIENT_LOCK(pCtx);
  retStatus = wslay_event_want_write(pCtx->event_ctx);
  CLIENT_UNLOCK(pCtx);
  return retStatus;
}

UINT32 wss_client_on_read_event(wss_client_context_t* pCtx)
{
  BOOL retStatus = true;
  CLIENT_LOCK(pCtx);
  retStatus = wslay_event_recv(pCtx->event_ctx);
  CLIENT_UNLOCK(pCtx);
  return retStatus;
}

UINT32 wss_client_on_write_event(wss_client_context_t* pCtx)
{
  BOOL retStatus = true;
  CLIENT_LOCK(pCtx);
  retStatus = wslay_event_send(pCtx->event_ctx);
  CLIENT_UNLOCK(pCtx);
  return retStatus;
}

static INT32 wss_client_send(wss_client_context_t* pCtx, struct wslay_event_msg* arg)
{
  INT32 retStatus = 0;
  DLOGD("===>   (%d)\n", arg->opcode);
  CLIENT_LOCK(pCtx);
  retStatus = wslay_event_queue_msg(pCtx->event_ctx, arg);
  CLIENT_UNLOCK(pCtx);
  return retStatus;
}

INT32 wss_client_send_text(wss_client_context_t* pCtx, UINT8* buf, UINT32 len)
{
  struct wslay_event_msg arg;
  arg.opcode = WSLAY_TEXT_FRAME;
  arg.msg = buf;
  arg.msg_length = len;
  return  wss_client_send(pCtx, &arg);
}

INT32 wss_client_send_binary(wss_client_context_t* pCtx, UINT8* buf, UINT32 len)
{
  struct wslay_event_msg arg;
  arg.opcode = WSLAY_BINARY_FRAME;
  arg.msg = buf;
  arg.msg_length = len;
  return  wss_client_send(pCtx, &arg);
}

INT32 wss_client_send_ping(wss_client_context_t* pCtx)
{
  struct wslay_event_msg arg;
  memset(&arg, 0, sizeof(arg));
  arg.opcode = WSLAY_PING;
  arg.msg_length = 0;
  return  wss_client_send(pCtx, &arg);
}


#define WSS_SEND_TEST 1
#if (WSS_SEND_TEST == 1)
VOID* testThread(VOID* arg)
{
  wss_client_context_t* context = (wss_client_context_t*)arg;
  UINT32 index = 0;
  CHAR indexBuf[256];

  while(1){
    #if 0
    memset(indexBuf, 0, 256);
    sprintf(indexBuf, "{\n"
                        "\t\"action\": \"ICE_CANDIDATE\","
                        "\t\"recipientClientId\": \"string\","
                        "\t\"messagePayload\": \"string%d\","
                        "\t\"correlationId\": \"string\"\n}", index);
    DLOGD("send\n");
    wss_client_send_text(context, indexBuf, STRLEN(indexBuf));
    DLOGD("send done\n");
    #else
    wss_client_send_ping(context);
    #endif
    sleep(1);
  }


}
#endif


/**
 * @brief create the context of wss client and initialize the wss client.
 * 
 * @param[in, out]
 * @param[in] pNetworkContext
 * 
 * @return
*/
VOID wss_client_create(wss_client_context_t** ppWssClientCtx, NetworkContext_t * pNetworkContext)
{
  INT32 retStatus = 0;
  wss_client_context_t* pCtx = malloc(sizeof(wss_client_context_t));
  memset(pCtx, 0, sizeof(wss_client_context_t));

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

  // the initialization of the mutex 
  {
    pthread_mutexattr_t mutexAttributes;

    if (0 != pthread_mutexattr_init(&mutexAttributes) ||
        0 != pthread_mutexattr_settype(&mutexAttributes, PTHREAD_MUTEX_NORMAL) ||
        0 != pthread_mutex_init(&pCtx->client_lock, &mutexAttributes)) {
        DLOGD("create the mutex failed\n");
        return;
    }

  }
  wslay_event_context_client_init(&pCtx->event_ctx, &pCtx->event_callbacks, pCtx);;
  *ppWssClientCtx = pCtx;
  return;
}

VOID ctl_epollev(int epollfd, int op, wss_client_context_t* pWssClientCtx)
{
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));

  if (wss_client_want_read(pWssClientCtx)) {
      ev.events |= EPOLLIN;
  }
  if (wss_client_want_write(pWssClientCtx)) {
      ev.events |= EPOLLOUT;
  }
  if (epoll_ctl(epollfd, op, pWssClientCtx->pNetworkContext->server_fd.fd, &ev) == -1) {
      DLOGD("epoll_ctl failed\n ");
      exit(EXIT_FAILURE);
  }
}



/**
 * @brief 
 * 
 * @param[in]
 * 
 * @return
*/
INT32 wss_client_start(wss_client_context_t* pWssClientCtx)
{
  static const SIZE_T MAX_EVENTS = 1;
  struct epoll_event events[MAX_EVENTS];
  BOOL ok = true;

  //
  wslay_event_config_set_callbacks(pWssClientCtx->event_ctx, &pWssClientCtx->event_callbacks);
  DLOGD("epoll_create ");
  int epollfd = epoll_create(1);
  if (epollfd == -1) {
      DLOGD("failed\n");
      return -1;
  }
  DLOGD("success\n");
  
  ctl_epollev(epollfd, EPOLL_CTL_ADD, pWssClientCtx);
  DLOGD("polling start\n");

  #if (WSS_SEND_TEST == 1)
  
  pthread_t threadId;

  INT32 ret = pthread_create (&threadId, NULL, testThread, pWssClientCtx);
  if(ret != 0){
    DLOGD("create the child thread failed.");
  }
  #endif
  

  
  // check the wss client want to read or write or not.
  
  while (wss_client_want_read(pWssClientCtx) || wss_client_want_write(pWssClientCtx)) {
    
    // need to setup the timeout of epoll in order to let the wss cleint thread to write the buffer out.
    //DLOGD("epoll waiting \n");
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, 1000);
    //std::cerr << "wait" << std::endl;
    //DLOGD("epoll timeout, nfds:%x\n", nfds);

    if (nfds == -1) {
      DLOGD("epoll_wait failed\n");
      return -1;
    }
    //DLOGD("processing event \n");
    for (int n = 0; n < nfds; ++n) {
      if (((events[n].events & EPOLLIN) && wss_client_on_read_event(pWssClientCtx) != 0) ||
          ((events[n].events & EPOLLOUT) && wss_client_on_write_event(pWssClientCtx) != 0)) {
        ok = false;
        break;
      }
    }
    
    if (!ok) {
      break;
    }
    //DLOGD("processing event done\n");
    ctl_epollev(epollfd, EPOLL_CTL_MOD, pWssClientCtx);
  }
  DLOGD("polling end\n");
  #if (WSS_SEND_TEST == 1)
  // waiting for the child thread.
  pthread_join(threadId, NULL);
  #endif

  return ok ? 0 : -1;
}


VOID wss_client_close(wss_client_context_t* pWssClientCtx)
{
  INT32 retStatus = 0;
  {
    retStatus = pthread_mutex_destroy(&pWssClientCtx->client_lock);
    if(retStatus != 0){
      DLOGD("destroy the client mutex failed\n");
    }
    
  }
  free(pWssClientCtx);
  return;
}
/*-----------------------------------------------------------*/



