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

#ifndef __KINESIS_VIDEO_WEBRTC_WSS_API_H__
#define __KINESIS_VIDEO_WEBRTC_WSS_API_H__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Specifies whether to block on the correlation id
#define BLOCK_ON_CORRELATION_ID FALSE
// Max length of the signaling message type string length
#define MAX_SIGNALING_MESSAGE_TYPE_LEN ARRAY_SIZE(SIGNALING_RECONNECT_ICE_SERVER)
#define LWS_MESSAGE_BUFFER_SIZE (SIZEOF(CHAR) * (MAX_SIGNALING_MESSAGE_LEN))

typedef struct {
    // The first member is the public signaling message structure
    ReceivedSignalingMessage receivedSignalingMessage;

    // The messaging client object
    PSignalingClient pSignalingClient;
} SignalingMessageWrapper, *PSignalingMessageWrapper;

STATUS wssConnectSignalingChannel(PSignalingClient pSignalingClient, UINT64 time);
STATUS wssSendMessage(PSignalingClient pSignalingClient, PCHAR pMessageType, PCHAR peerClientId, PCHAR pMessage, UINT32 messageLen,
                      PCHAR pCorrelationId, UINT32 correlationIdLen);
STATUS wssReceiveMessage(PSignalingClient pSignalingClient, PCHAR pMessage, UINT32 messageLen);
// #YC_TBD.
STATUS wssTerminateConnectionWithStatus(PSignalingClient pSignalingClient, SERVICE_CALL_RESULT callResult);
STATUS wssTerminateListenerLoop(PSignalingClient pSignalingClient);
// json parser.
STATUS wssApiRspReceivedMessage( const CHAR * pResponseStr, UINT32 resultLen, PSignalingMessageWrapper pSignalingMessageWrapper);


#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_WSS_API_H__ */