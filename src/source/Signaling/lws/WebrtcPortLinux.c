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
#define LOG_CLASS "webrtc_port"
#include "../Include_i.h"

#define DATE_TIME_ISO_8601_FORMAT_STRING_SIZE (17)

VOID sleepInMs(UINT32 ms)
{
    usleep(ms * 1000);
}

INT32 getTimeInIso8601(CHAR* pBuf, UINT32 uBufSize)
{
    INT32 retStatus = STATUS_SUCCESS;
    time_t timeUtcNow = {0};

    if (pBuf == NULL || uBufSize < DATE_TIME_ISO_8601_FORMAT_STRING_SIZE) {
        retStatus = STATUS_INVALID_ARG;
    } else {
        timeUtcNow = time(NULL);
        strftime(pBuf, DATE_TIME_ISO_8601_FORMAT_STRING_SIZE, "%Y%m%dT%H%M%SZ", gmtime(&timeUtcNow));
    }

    return retStatus;
}
