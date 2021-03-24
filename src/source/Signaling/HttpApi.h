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

#ifndef _WEBRTC_REST_API_H_
#define _WEBRTC_REST_API_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//#define WEBRTC_CHANNEL_PROTOCOL "\"WSS\""
#define WEBRTC_CHANNEL_PROTOCOL "\"WSS\", \"HTTPS\""

// api
STATUS httpApiCreateChannl(PSignalingClient pSignalingClient, UINT64 time);
STATUS httpApiDeleteChannl(PSignalingClient pSignalingClient, UINT64 time);
STATUS httpApiDescribeChannel(PSignalingClient pSignalingClient, UINT64 time);
STATUS httpApiGetChannelEndpoint(PSignalingClient pSignalingClient, UINT64 time);
STATUS httpApiGetIceConfig(PSignalingClient pSignalingClient, UINT64 time);
// rsp
STATUS httpApiRspCreateChannel( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspDeleteChannel( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspDescribeChannel( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspGetChannelEndpoint( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspGetIceConfig( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
#ifdef __cplusplus
}
#endif
#endif // #ifndef _WEBRTC_REST_API_H_