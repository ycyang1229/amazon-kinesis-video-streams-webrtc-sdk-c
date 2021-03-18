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

#define LOG_CLASS "http_helper"
#include "../Include_i.h"

#include "http_helper.h"

#include "llhttp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*-----------------------------------------------------------*/

static uint32_t uLastHttpStatusCode = 0;
static char *pLastHttpBodyLoc = NULL;
static uint32_t uLastHttpBodyLen = 0;

typedef struct user_llhttp
{
    llhttp_t httpParser;
    void* user_data;
}user_llhttp_t;


#define GET_USER_DATA(p) (((user_llhttp_t*)p)->user_data)

/*-----------------------------------------------------------*/
http_field_t* http_get_value_by_field(struct list_head* head, char* field, uint32_t fieldLen)
{
    struct list_head *listptr;
    http_field_t *node;
    uint32_t found = 0;

    list_for_each(listptr, head) {
        node = list_entry(listptr, http_field_t, list);
        if(strncmp(node->field, field, node->fieldLen) == 0 && node->fieldLen == fieldLen ){
            //printf("%s found\n", node->field);
            found = 1;
            break;
        }
        
    }
    if(!found){
        return NULL;
    }else{
        return node;
    }
}

int32_t http_add_required_header(struct list_head* head, char* field, uint32_t fieldLen, char* value, uint32_t valueLen)
{
    http_field_t* node = (http_field_t*)malloc(sizeof(http_field_t));
    node->field = field;
    node->fieldLen = fieldLen;
    node->value = value;
    node->valueLen = valueLen;
    //printf("required: field = %s | len = %d | value = %s | len = %d\n",
    //    node->field,
    //    node->fieldLen,
    //    node->value,
    //    node->valueLen);
    list_add(&node->list, head);
    return 0;
}

void http_del_all_header(struct list_head* head)
{
    struct list_head *listptr;
    http_field_t *node;

    list_for_each(listptr, head) {
        node = list_entry(listptr, http_field_t, list);

        //printf("\nFree: field = %s | len = %d | value = %s | len = %d\n",
        //        node->field,
        //        node->fieldLen,
        //        node->value,
        //        node->valueLen);
        free(node);
        node=NULL;
    }
    return;
}




static int handleHttpOnBodyComplete( llhttp_t *httpParser, const char *at, size_t length )
{
    /* FIXME: It's neither a thread safe design, nor a memory safe design. */
    pLastHttpBodyLoc = ( char * )at;
    uLastHttpBodyLen = ( uint32_t )length;
    return 0;
}


static int _on_message_begin( llhttp_t *httpParser )
{
    //printf("on_message_begin\n");
    return 0;
}


static int _on_url( llhttp_t *httpParser, const char *at, size_t length )
{
    //printf("on_url\n");
    //char* buf = malloc(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //printf("%s\n", buf);
    return 0;
}


static int _on_status( llhttp_t *httpParser, const char *at, size_t length )
{
    //printf("on_status\n");
    //char* buf = malloc(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //printf("%s\n", buf);
    return 0;
}


static int _on_header_field( llhttp_t *httpParser, const char *at, size_t length )
{
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    //printf("on_header_field\n");
    //char* buf = malloc(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //printf("%s\n", buf);

    pCtx->curField.field = ( char * )at;
    pCtx->curField.fieldLen = length;
    return 0;
}

static int _on_header_value( llhttp_t *httpParser, const char *at, size_t length )
{
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    //printf("on_header_value\n");
    //char* buf = malloc(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //printf("%s\n", buf);
    pCtx->curField.value = ( char * )at;
    pCtx->curField.valueLen = length;
    return 0;
}


static int _on_headers_complete( llhttp_t *httpParser )
{
    //printf("on_headers_complete\n");
    return 0;
}


static int _on_body( llhttp_t *httpParser, const char *at, size_t length )
{
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    //printf("on_body\n");
    //char* buf = malloc(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //printf("%s\n", buf);
    pCtx->phttpBodyLoc = ( char * )at;
    pCtx->uhttpBodyLen = length;
    return 0;
}


static int _on_message_complete( llhttp_t *httpParser )
{
    //printf("on_message_complete\n");
    //http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);

    return -1;
}


static int _on_chunk_header( llhttp_t *httpParser )
{
    //printf("on_chunk_header\n");
    return 0;
}


static int _on_chunk_complete( llhttp_t *httpParser )
{
    //printf("on_chunk_complete\n");
    return 0;
}


static int _on_url_complete( llhttp_t *httpParser )
{
    //printf("on_url_complete\n");
    return 0;
}


static int _on_status_complete( llhttp_t *httpParser )
{
    //printf("on_status_complete\n");
    return 0;
}

static int _on_header_field_complete( llhttp_t *httpParser )
{
    //printf("on_header_field_complete\n");
    return 0;
}


static int _on_header_value_complete( llhttp_t *httpParser )
{
    //printf("on_header_value_complete\n");
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    if(pCtx->requiredHeader == NULL){
        return 0;
    }
    http_field_t *node = http_get_value_by_field(pCtx->requiredHeader, pCtx->curField.field, pCtx->curField.fieldLen);
    if(node != NULL){
        node->value = pCtx->curField.value;
        node->valueLen = pCtx->curField.valueLen;
        //printf("complete: %s hit\n", node->field);
    }else{
        return -1;
    }

    return 0;
}
/*-----------------------------------------------------------*/

int32_t parseHttpResponse( char *pBuf, uint32_t uLen )
{
    int32_t retStatus = STATUS_SUCCESS;
    llhttp_t httpParser = { 0 };
    llhttp_settings_t httpSettings = { 0 };
    
    enum llhttp_errno httpErrno = HPE_OK;

    pLastHttpBodyLoc = NULL;
    uLastHttpBodyLen = 0;

    llhttp_settings_init( &httpSettings );
    httpSettings.on_body = handleHttpOnBodyComplete;
    llhttp_init( &httpParser, HTTP_RESPONSE, &httpSettings);

    httpErrno = llhttp_execute( &httpParser, pBuf, ( size_t )uLen );
    if ( httpErrno != HPE_OK && httpErrno < HPE_CB_MESSAGE_BEGIN )
    {
        retStatus = STATUS_RECV_DATA_FAILED;
    }
    else
    {
        uLastHttpStatusCode = ( uint32_t )(httpParser.status_code);
        return STATUS_SUCCESS;
    }
}

uint32_t getLastHttpStatusCode( void )
{
    return uLastHttpStatusCode;
}

char * getLastHttpBodyLoc( void )
{
    return pLastHttpBodyLoc;
}

uint32_t getLastHttpBodyLen( void )
{
    return uLastHttpBodyLen;
}


uint32_t http_get_http_status_code(http_response_context_t* pHttpRspCtx)
{
    return pHttpRspCtx->uhttpStatusCode;
}

char* http_get_http_body_location(http_response_context_t* pHttpRspCtx)
{
    return pHttpRspCtx->phttpBodyLoc;
}

uint32_t http_get_http_body_length(http_response_context_t* pHttpRspCtx)
{
    return pHttpRspCtx->uhttpBodyLen;
}

int32_t http_parse_start(http_response_context_t** ppHttpRspCtx, char *pBuf, uint32_t uLen, struct list_head* requiredHeader)
{
    int32_t retStatus = STATUS_SUCCESS;
    user_llhttp_t userParser = { 0 };
    llhttp_settings_t httpSettings = { 
        NULL, //_on_message_begin, /* on_message_begin */
        NULL, //_on_url, /* on_url */
        _on_status, /* on_status */
        _on_header_field, /* on_header_field */
        _on_header_value, /* on_header_value */
        _on_headers_complete, /* on_headers_complete */
        _on_body, /* on_body */
        NULL, //_on_message_complete, /* on_message_complete */
        NULL, //_on_chunk_header, /* on_chunk_header */
        NULL, //_on_chunk_complete, /* on_chunk_complete */
        NULL, //_on_url_complete, /* on_url_complete */
        _on_status_complete, /* on_status_complete */
        _on_header_field_complete, /* on_header_field_complete */
        _on_header_value_complete /* on_header_value_complete */
    };
    enum llhttp_errno httpErrno = HPE_OK;

    http_response_context_t* pCtx = (http_response_context_t*)malloc(sizeof(http_response_context_t));
    if(pCtx == NULL){
        return -1;
    }
    memset(pCtx, 0, sizeof(http_response_context_t));
    pCtx->requiredHeader = requiredHeader;
    *ppHttpRspCtx = pCtx;
    
    llhttp_init( (void*)&userParser, HTTP_RESPONSE, &httpSettings);
    userParser.user_data = pCtx;
    httpErrno = llhttp_execute( (void*)&userParser, pBuf, ( size_t )uLen );
    if ( httpErrno != HPE_OK && httpErrno < HPE_CB_MESSAGE_BEGIN )
    {
        retStatus = STATUS_RECV_DATA_FAILED;
    }
    else
    {
        pCtx->uhttpStatusCode = ( uint32_t )(userParser.httpParser.status_code);
        return STATUS_SUCCESS;
    }
Exit:

    return retStatus;
}


int32_t http_parse_detroy(http_response_context_t* pHttpRspCtx)
{
    int32_t retStatus = STATUS_SUCCESS;
    printf("detroying required headers... \n");
    if(pHttpRspCtx != NULL && pHttpRspCtx->requiredHeader != NULL){
        http_del_all_header(pHttpRspCtx->requiredHeader);
        printf("all required headers is removed... \n");
        free(pHttpRspCtx->requiredHeader);
    }
    printf("detroying context... \n");
    free(pHttpRspCtx);
    return retStatus;
}
