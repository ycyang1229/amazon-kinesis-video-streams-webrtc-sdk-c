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


/*-----------------------------------------------------------*/

static UINT32 uLastHttpStatusCode = 0;
static char *pLastHttpBodyLoc = NULL;
static UINT32 uLastHttpBodyLen = 0;

typedef struct user_llhttp
{
    llhttp_t httpParser;
    PVOID user_data;
}user_llhttp_t;


#define GET_USER_DATA(p) (((user_llhttp_t*)p)->user_data)

/*-----------------------------------------------------------*/
http_field_t* http_get_value_by_field(struct list_head* head, char* field, UINT32 fieldLen)
{
    struct list_head *listptr;
    http_field_t *node;
    UINT32 found = 0;

    list_for_each(listptr, head) {
        node = list_entry(listptr, http_field_t, list);
        if(STRNCMP(node->field, field, node->fieldLen) == 0 && node->fieldLen == fieldLen ){
            //DLOGD("%s found", node->field);
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

int32_t http_add_required_header(struct list_head* head, char* field, UINT32 fieldLen, char* value, UINT32 valueLen)
{
    http_field_t* node = (http_field_t*)MEMALLOC(sizeof(http_field_t));
    node->field = field;
    node->fieldLen = fieldLen;
    node->value = value;
    node->valueLen = valueLen;
    //DLOGD("required: field = %s | len = %d | value = %s | len = %d",
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

        //DLOGD("\nFree: field = %s | len = %d | value = %s | len = %d",
        //        node->field,
        //        node->fieldLen,
        //        node->value,
        //        node->valueLen);
        MEMFREE(node);
        node=NULL;
    }
    return;
}




static INT32 handleHttpOnBodyComplete( llhttp_t *httpParser, const char *at, size_t length )
{
    /* FIXME: It's neither a thread safe design, nor a memory safe design. */
    pLastHttpBodyLoc = ( char * )at;
    uLastHttpBodyLen = ( UINT32 )length;
    return 0;
}


static INT32 _on_message_begin( llhttp_t *httpParser )
{
    //DLOGD("on_message_begin");
    return 0;
}


static INT32 _on_url( llhttp_t *httpParser, const char *at, size_t length )
{
    //DLOGD("on_url");
    //char* buf = MEMALLOC(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //DLOGD("%s", buf);
    return 0;
}


static INT32 _on_status( llhttp_t *httpParser, const char *at, size_t length )
{
    //DLOGD("on_status");
    //char* buf = MEMALLOC(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //DLOGD("%s", buf);
    return 0;
}


static INT32 _on_header_field( llhttp_t *httpParser, const char *at, size_t length )
{
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    //DLOGD("on_header_field");
    //char* buf = MEMALLOC(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //DLOGD("%s", buf);

    pCtx->curField.field = ( char * )at;
    pCtx->curField.fieldLen = length;
    return 0;
}

static INT32 _on_header_value( llhttp_t *httpParser, const char *at, size_t length )
{
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    //DLOGD("on_header_value");
    //char* buf = MEMALLOC(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //DLOGD("%s", buf);
    pCtx->curField.value = ( char * )at;
    pCtx->curField.valueLen = length;
    return 0;
}


static INT32 _on_headers_complete( llhttp_t *httpParser )
{
    //DLOGD("on_headers_complete");
    return 0;
}


static INT32 _on_body( llhttp_t *httpParser, const char *at, size_t length )
{
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    //DLOGD("on_body");
    //char* buf = MEMALLOC(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //DLOGD("%s", buf);
    pCtx->phttpBodyLoc = ( char * )at;
    pCtx->uhttpBodyLen = length;
    return 0;
}


static INT32 _on_message_complete( llhttp_t *httpParser )
{
    //DLOGD("on_message_complete");
    //http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);

    return -1;
}


static INT32 _on_chunk_header( llhttp_t *httpParser )
{
    //DLOGD("on_chunk_header");
    return 0;
}


static INT32 _on_chunk_complete( llhttp_t *httpParser )
{
    //DLOGD("on_chunk_complete");
    return 0;
}


static INT32 _on_url_complete( llhttp_t *httpParser )
{
    //DLOGD("on_url_complete");
    return 0;
}


static INT32 _on_status_complete( llhttp_t *httpParser )
{
    //DLOGD("on_status_complete");
    return 0;
}

static INT32 _on_header_field_complete( llhttp_t *httpParser )
{
    //DLOGD("on_header_field_complete");
    return 0;
}


static INT32 _on_header_value_complete( llhttp_t *httpParser )
{
    //DLOGD("on_header_value_complete");
    http_response_context_t* pCtx = (http_response_context_t*)GET_USER_DATA(httpParser);
    if(pCtx->requiredHeader == NULL){
        return 0;
    }
    http_field_t *node = http_get_value_by_field(pCtx->requiredHeader, pCtx->curField.field, pCtx->curField.fieldLen);
    if(node != NULL){
        node->value = pCtx->curField.value;
        node->valueLen = pCtx->curField.valueLen;
        //DLOGD("complete: %s hit", node->field);
    }else{
        return -1;
    }

    return 0;
}
/*-----------------------------------------------------------*/

STATUS parseHttpResponse( PCHAR pBuf, UINT32 uLen )
{
    STATUS retStatus = STATUS_SUCCESS;
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
        uLastHttpStatusCode = ( UINT32 )(httpParser.status_code);
        return STATUS_SUCCESS;
    }
}

UINT32 getLastHttpStatusCode( VOID )
{
    return uLastHttpStatusCode;
}

PCHAR getLastHttpBodyLoc( VOID )
{
    return pLastHttpBodyLoc;
}

UINT32 getLastHttpBodyLen( VOID )
{
    return uLastHttpBodyLen;
}


UINT32 http_get_http_status_code(http_response_context_t* pHttpRspCtx)
{
    return pHttpRspCtx->uhttpStatusCode;
}

PCHAR http_get_http_body_location(http_response_context_t* pHttpRspCtx)
{
    return pHttpRspCtx->phttpBodyLoc;
}

UINT32 http_get_http_body_length(http_response_context_t* pHttpRspCtx)
{
    return pHttpRspCtx->uhttpBodyLen;
}

STATUS http_parse_start(http_response_context_t** ppHttpRspCtx, PCHAR pBuf, UINT32 uLen, struct list_head* requiredHeader)
{
    STATUS retStatus = STATUS_SUCCESS;
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

    http_response_context_t* pCtx = (http_response_context_t*)MEMALLOC(sizeof(http_response_context_t));
    if(pCtx == NULL){
        return -1;
    }
    MEMSET(pCtx, 0, sizeof(http_response_context_t));
    pCtx->requiredHeader = requiredHeader;
    *ppHttpRspCtx = pCtx;
    
    llhttp_init( (PVOID)&userParser, HTTP_RESPONSE, &httpSettings);
    userParser.user_data = pCtx;
    httpErrno = llhttp_execute( (void*)&userParser, pBuf, ( size_t )uLen );
    if ( httpErrno != HPE_OK && httpErrno < HPE_CB_MESSAGE_BEGIN )
    {
        retStatus = STATUS_RECV_DATA_FAILED;
    }
    else
    {
        pCtx->uhttpStatusCode = ( UINT32 )(userParser.httpParser.status_code);
        return STATUS_SUCCESS;
    }
Exit:

    return retStatus;
}


STATUS http_parse_detroy(http_response_context_t* pHttpRspCtx)
{
    STATUS retStatus = STATUS_SUCCESS;
    DLOGD("detroying required headers...");
    if(pHttpRspCtx != NULL && pHttpRspCtx->requiredHeader != NULL){
        http_del_all_header(pHttpRspCtx->requiredHeader);
        DLOGD("all required headers is removed...");
        MEMFREE(pHttpRspCtx->requiredHeader);
    }
    DLOGD("detroying context...");
    MEMFREE(pHttpRspCtx);
    return retStatus;
}
