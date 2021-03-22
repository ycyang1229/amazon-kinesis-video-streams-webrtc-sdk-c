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

#ifndef _WEBRTC_WSS_API_H_
#define _WEBRTC_WSS_API_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

STATUS wssConnectSignalingChannel( webrtcServiceParameter_t * pServiceParameter, webrtcChannelInfo_t * pChannelInfo);
STATUS wssSendMessage(PVOID pSignalingClient, PCHAR pMessageType, PCHAR peerClientId, PCHAR pMessage, UINT32 messageLen,
                      PCHAR pCorrelationId, UINT32 correlationIdLen);
STATUS wssTerminateThread(PVOID pSignalingClient);
#ifdef __cplusplus
}
#endif
#endif // #ifndef _WEBRTC_WSS_API_H_