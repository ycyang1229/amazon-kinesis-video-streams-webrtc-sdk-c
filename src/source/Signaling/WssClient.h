/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#ifndef _WEBRTC_WSS_CLIENT_H_
#define _WEBRTC_WSS_CLIENT_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// wslay related lib.
//#include "wslay/wslay.h"

// SIGNALING_SERVICE_WSS_PING_PONG_INTERVAL_IN_SECONDS
#define WSS_CLIENT_RFC6455_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WSS_CLIENT_RFC6455_UUID_LEN strlen(WSS_CLIENT_RFC6455_UUID)
#define WSS_CLIENT_RANDOM_SEED_LEN 16
#define WSS_CLIENT_BASED64_RANDOM_SEED_LEN 24
#define WSS_CLIENT_SHA1_RANDOM_SEED_W_UUID_LEN 20
#define WSS_CLIENT_ACCEPT_KEY_LEN 28

typedef struct wss_client_context{
    wslay_event_context_ptr event_ctx;
    struct wslay_event_callbacks event_callbacks;
    PCHAR client_key;
    UINT32 client_key_len;
    // socket related stuff.
    NetworkContext_t * pNetworkContext;
    // os related stuff.
    pthread_t thread_id;    
    pthread_mutex_t client_lock;
}wss_client_context_t;

INT32 wss_client_generate_random_number(CHAR* num, UINT32 len);
INT32 wss_client_generate_client_key(CHAR* buf, UINT32 bufLen);
INT32 wss_client_validate_accept_key(CHAR* clientKey, UINT32 clientKeyLen, CHAR* acceptKey, UINT32 acceptKeyLen);
VOID wss_client_create(wss_client_context_t** ppWssClientCtx, NetworkContext_t * pNetworkContext);
INT32 wss_client_start(wss_client_context_t* pWssClientCtx);
INT32 wss_client_send_text(wss_client_context_t* pCtx, UINT8* buf, UINT32 len);
INT32 wss_client_send_binary(wss_client_context_t* pCtx, UINT8* buf, UINT32 len);
INT32 wss_client_send_ping(wss_client_context_t* pCtx);
VOID wss_client_close(wss_client_context_t* pWssClientCtx);

#ifdef __cplusplus
}
#endif
#endif // #ifndef _WEBRTC_WSS_CLIENT_H_