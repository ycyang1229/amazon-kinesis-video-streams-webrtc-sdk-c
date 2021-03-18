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

#ifndef _HTTP_HELPER_H_
#define _HTTP_HELPER_H_

#include <inttypes.h>

#include "llhttp.h"
#include "list.h"

typedef struct http_field
{
    char* field;
    uint32_t fieldLen;
    char* value;
    uint32_t valueLen;
    struct list_head list;
}http_field_t;

typedef struct http_response_context
{
    uint32_t uhttpStatusCode;
    uint32_t uhttpBodyLen;
    char* phttpBodyLoc;
    http_field_t curField;
    struct list_head* requiredHeader;
}http_response_context_t;

int32_t parseHttpResponse( char *pBuf, uint32_t uLen );
uint32_t getLastHttpStatusCode( void );
char * getLastHttpBodyLoc( void );
uint32_t getLastHttpBodyLen( void );

// new interface
int32_t http_add_required_header(struct list_head* head, char* field, uint32_t fieldLen, char* value, uint32_t valudLen);
http_field_t* http_get_value_by_field(struct list_head* head, char* field, uint32_t fieldLen);
int32_t http_parse_start(http_response_context_t** ppHttpRspCtx, char *pBuf, uint32_t uLen, struct list_head* requiredHeader);
uint32_t http_get_http_status_code(http_response_context_t* pHttpRspCtx);
char* http_get_http_body_location(http_response_context_t* pHttpRspCtx);
uint32_t http_get_http_body_length(http_response_context_t* pHttpRspCtx);
int32_t http_parse_detroy(http_response_context_t* pHttpRspCtx);
#endif