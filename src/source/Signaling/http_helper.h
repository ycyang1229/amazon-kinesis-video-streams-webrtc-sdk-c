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

#ifndef __KINESIS_VIDEO_WEBRTC_HTTP_HELPER_H__
#define __KINESIS_VIDEO_WEBRTC_HTTP_HELPER_H__

#include <inttypes.h>

#include "llhttp.h"
#include "list.h"

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


typedef struct http_field
{
    PCHAR field;
    UINT32 fieldLen;
    PCHAR value;
    UINT32 valueLen;
    struct list_head list;
}http_field_t;

typedef struct http_response_context
{
    UINT32 uhttpStatusCode;
    UINT32 uhttpBodyLen;
    PCHAR phttpBodyLoc;
    http_field_t curField;
    struct list_head* requiredHeader;
}http_response_context_t;

STATUS parseHttpResponse( PCHAR pBuf, UINT32 uLen );
UINT32 getLastHttpStatusCode( VOID );
PCHAR getLastHttpBodyLoc( VOID );
UINT32 getLastHttpBodyLen( VOID );

// new interface

INT32 http_add_required_header(struct list_head* head, PCHAR field, UINT32 fieldLen, PCHAR value, UINT32 valudLen);
http_field_t* http_get_value_by_field(struct list_head* head, PCHAR field, UINT32 fieldLen);
UINT32 http_get_http_status_code(http_response_context_t* pHttpRspCtx);
PCHAR http_get_http_body_location(http_response_context_t* pHttpRspCtx);
UINT32 http_get_http_body_length(http_response_context_t* pHttpRspCtx);
STATUS http_parse_start(http_response_context_t** ppHttpRspCtx, PCHAR pBuf, UINT32 uLen, struct list_head* requiredHeader);
STATUS http_parse_detroy(http_response_context_t* pHttpRspCtx);
#ifdef __cplusplus
}
#endif
#endif/* __KINESIS_VIDEO_WEBRTC_HTTP_HELPER_H__ */