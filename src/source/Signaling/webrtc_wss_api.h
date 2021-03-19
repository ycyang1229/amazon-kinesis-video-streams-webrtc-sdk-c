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

#include "webrtc_rest_api.h"
INT32 webrtc_connect_end_point( webrtcServiceParameter_t * pServiceParameter,
                        webrtcChannelInfo_t * pChannelInfo);

#ifdef __cplusplus
}
#endif
#endif // #ifndef _WEBRTC_WSS_API_H_