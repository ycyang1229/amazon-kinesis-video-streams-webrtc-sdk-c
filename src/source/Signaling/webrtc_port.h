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

#ifndef _WEBRTC_PORT_H_
#define _WEBRTC_PORT_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


/**
 * @brief sleep in milliseconds
 *
 * @param[in] ms The desired milliseconds to sleep
 */
VOID sleepInMs( UINT32 ms );

/**
 * @brief Return time in ISO 8601 format: YYYYMMDD'T'HHMMSS'Z'
 *
 * AWS Signature V4 requires HTTP header x-amz-date which is in ISO 8601 format. ISO 8601 format is YYYYMMDD'T'HHMMSS'Z'.
 * For example, "20150830T123600Z" is a valid timestamp.
 *
 * @param[out] buf The buffer to store ths ISO 8601 string (including end of string character)
 * @param[out] uBufSize The buffer size
 * @return
 */
INT32 getTimeInIso8601( CHAR *buf, UINT32 uBufSize );
#ifdef __cplusplus
}
#endif
#endif