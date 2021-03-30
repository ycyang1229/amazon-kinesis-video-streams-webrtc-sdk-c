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

#ifndef __KINESIS_VIDEO_WEBRTC_WSS_CLIENT_H__
#define __KINESIS_VIDEO_WEBRTC_WSS_CLIENT_H__

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
#define WSS_CLIENT_POLLING_INTERVAL 50 // unit:ms.
#define WSS_CLIENT_PING_PONG_INTERVAL 10 // unit:sec.
#define WSS_CLIENT_PING_PONG_COUNTER (WSS_CLIENT_PING_PONG_INTERVAL*1000)/WSS_CLIENT_POLLING_INTERVAL
typedef STATUS (*MessageHandlerFunc)(PVOID, PCHAR, UINT32);

typedef struct {
    wslay_event_context_ptr event_ctx;
    struct wslay_event_callbacks event_callbacks;
    PCHAR client_key;
    UINT32 client_key_len;
    // socket related stuff.
    NetworkContext_t * pNetworkContext;
    // os related stuff.
    pthread_t thread_id;    
    pthread_mutex_t client_lock;
    PVOID pUserData;
    MessageHandlerFunc messageHandler;
}WssClientContext, *PWssClientContext;

STATUS wssClientGenerateRandomNumber(PCHAR num, UINT32 len);
STATUS wssClientGenerateClientKey(PCHAR buf, UINT32 bufLen);
STATUS wssClientValidateAcceptKey(PCHAR clientKey, UINT32 clientKeyLen, PCHAR acceptKey, UINT32 acceptKeyLen);
VOID wssClientCreate(WssClientContext** ppWssClientCtx, NetworkContext_t * pNetworkContext, PVOID arg, MessageHandlerFunc pFunc);
INT32 wssClientStart(WssClientContext* pWssClientCtx);
INT32 wssClientSendText(WssClientContext* pCtx, UINT8* buf, UINT32 len);
INT32 wssClientSendBinary(WssClientContext* pCtx, UINT8* buf, UINT32 len);
INT32 wssClientSendPing(WssClientContext* pCtx);
VOID wss_client_close(WssClientContext* pWssClientCtx);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_WSS_CLIENT_H__ */