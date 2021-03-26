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

#define LOG_CLASS "HttpHelper"
#include "../Include_i.h"

/*-----------------------------------------------------------*/
typedef struct{
    llhttp_t httpParser;
    PVOID customData;
}CustomLlhttp, *PCustomLlhttp;


#define GET_USER_DATA(p) (((PCustomLlhttp)p)->customData)

/*-----------------------------------------------------------*/
PHttpField httpParserGetValueByField(struct list_head* head, char* field, UINT32 fieldLen)
{
    struct list_head *listptr;
    PHttpField node;
    UINT32 found = 0;

    list_for_each(listptr, head) {
        node = list_entry(listptr, HttpField, list);
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

int32_t httpParserAddRequiredHeader(struct list_head* head, char* field, UINT32 fieldLen, char* value, UINT32 valueLen)
{
    PHttpField node = (PHttpField)MEMALLOC(sizeof(HttpField));
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

void httpParserDeleteAllHeader(struct list_head* head)
{
    struct list_head *listptr;
    PHttpField node;

    list_for_each(listptr, head) {
        node = list_entry(listptr, HttpField, list);

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
    HttpResponseContext* pCtx = (HttpResponseContext*)GET_USER_DATA(httpParser);
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
    HttpResponseContext* pCtx = (HttpResponseContext*)GET_USER_DATA(httpParser);
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
    HttpResponseContext* pCtx = (HttpResponseContext*)GET_USER_DATA(httpParser);
    //DLOGD("on_body");
    //char* buf = MEMALLOC(length+1);
    //memcpy(buf, at, length);
    //buf[length] = '\0';
    //DLOGD("%s", buf);
    pCtx->phttpBodyLoc = ( char * )at;
    pCtx->httpBodyLen = length;
    return 0;
}


static INT32 _on_message_complete( llhttp_t *httpParser )
{
    //DLOGD("on_message_complete");
    //HttpResponseContext* pCtx = (HttpResponseContext*)GET_USER_DATA(httpParser);

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
    PHttpResponseContext pCtx = (PHttpResponseContext)GET_USER_DATA(httpParser);
    if(pCtx->requiredHeader == NULL){
        return 0;
    }
    PHttpField node = httpParserGetValueByField(pCtx->requiredHeader, pCtx->curField.field, pCtx->curField.fieldLen);
    if(node != NULL){
        node->value = pCtx->curField.value;
        node->valueLen = pCtx->curField.valueLen;
    }else{
        return -1;
    }

    return 0;
}
/*-----------------------------------------------------------*/

UINT32 httpParserGetHttpStatusCode(HttpResponseContext* pHttpRspCtx)
{
    return pHttpRspCtx->httpStatusCode;
}

PCHAR httpParserGetHttpBodyLocation(HttpResponseContext* pHttpRspCtx)
{
    return pHttpRspCtx->phttpBodyLoc;
}

UINT32 httpParserGetHttpBodyLength(HttpResponseContext* pHttpRspCtx)
{
    return pHttpRspCtx->httpBodyLen;
}

STATUS httpParserStart(HttpResponseContext** ppHttpRspCtx, PCHAR pBuf, UINT32 uLen, struct list_head* requiredHeader)
{
    STATUS retStatus = STATUS_SUCCESS;
    CustomLlhttp userParser = { 0 };
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

    HttpResponseContext* pCtx = (HttpResponseContext*)MEMALLOC(sizeof(HttpResponseContext));
    if(pCtx == NULL){
        return -1;
    }
    MEMSET(pCtx, 0, sizeof(HttpResponseContext));
    pCtx->requiredHeader = requiredHeader;
    *ppHttpRspCtx = pCtx;
    
    llhttp_init( (PVOID)&userParser, HTTP_RESPONSE, &httpSettings);
    userParser.customData = pCtx;
    httpErrno = llhttp_execute( (void*)&userParser, pBuf, ( size_t )uLen );
    // #YC_TBD, need to be fixed.
    if ( httpErrno != HPE_OK && httpErrno < HPE_CB_MESSAGE_BEGIN )
    {
        retStatus = STATUS_RECV_DATA_FAILED;
    }
    else
    {
        pCtx->httpStatusCode = ( UINT32 )(userParser.httpParser.status_code);
        return STATUS_SUCCESS;
    }
CleanUp:

    return retStatus;
}


STATUS httpParserDetroy(HttpResponseContext* pHttpRspCtx)
{
    STATUS retStatus = STATUS_SUCCESS;
    //DLOGD("detroying required headers...");
    if(pHttpRspCtx != NULL && pHttpRspCtx->requiredHeader != NULL){
        httpParserDeleteAllHeader(pHttpRspCtx->requiredHeader);
        //DLOGD("all required headers is removed...");
        MEMFREE(pHttpRspCtx->requiredHeader);
    }
    //DLOGD("detroying context...");
    MEMFREE(pHttpRspCtx);
    return retStatus;
}


STATUS httpPackSendBuf(PRequestInfo pRequestInfo, PCHAR pVerb, PCHAR pHost, UINT32 hostLen, PCHAR outputBuf, UINT32 bufLen, BOOL bWss)
{
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR p = NULL;
    PCHAR pPath = NULL;
    PCHAR pHostStart, pHostEnd;
    UINT32 headerCount;
    PSingleListNode pCurNode;
    UINT64 item;
    PRequestHeader pRequestHeader;    
        
    // Sign the request
    if(!bWss){
        CHK_STATUS(signAwsRequestInfo(pRequestInfo));
    }else{
        CHK_STATUS(signAwsRequestInfoQueryParam(pRequestInfo));
    }

    CHK_STATUS(getRequestHost(pRequestInfo->url, &pHostStart, &pHostEnd));
    CHK(pHostEnd == NULL || *pHostEnd == '/' || *pHostEnd == '?', STATUS_INTERNAL_ERROR);
    MEMCPY(pHost, pHostStart, pHostEnd-pHostStart);

    UINT32 pathLen = MAX_URI_CHAR_LEN;
    CHK(NULL != (pPath = (PCHAR) MEMCALLOC(pathLen + 1, SIZEOF(CHAR))), STATUS_NOT_ENOUGH_MEMORY);
    // Store the pPath
    pPath[MAX_URI_CHAR_LEN] = '\0';
    if (pHostEnd != NULL) {
        if (*pHostEnd == '/') {
            STRNCPY(pPath, pHostEnd, MAX_URI_CHAR_LEN);
        } else {
            pPath[0] = '/';
            STRNCPY(&pPath[1], pHostEnd, MAX_URI_CHAR_LEN - 1);
        }
    } else {
        pPath[0] = '/';
        pPath[1] = '\0';
    }

    p = (PCHAR)(outputBuf);
    /* header */
    p += SPRINTF(p, "%s %s HTTP/1.1\r\n", pVerb, pPath);
    p += SPRINTF(p, "Accept: */*\r\n");


    CHK_STATUS(singleListGetHeadNode(pRequestInfo->pRequestHeaders, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(singleListGetNodeData(pCurNode, &item));
        pRequestHeader = (PRequestHeader) item;

        //pPrevNode = pCurNode;
        DLOGD("Appending header - %s %s", pRequestHeader->pName, pRequestHeader->pValue);
        p += SPRINTF(p, "%s: %s\r\n", pRequestHeader->pName, pRequestHeader->pValue);

        CHK_STATUS(singleListGetNextNode(pCurNode, &pCurNode));
    }

    p += SPRINTF(p, "\r\n" );
    /* body */
    p += SPRINTF(p, "%s\r\n", pRequestInfo->body );
    p += SPRINTF(p, "\r\n" );
CleanUp:

    SAFE_MEMFREE(pPath);
    return retStatus;
}


STATUS httpPackSendBufEx(PRequestInfo pRequestInfo, PCHAR pVerb, PCHAR pHost, UINT32 hostLen, PCHAR outputBuf, UINT32 bufLen, BOOL bWss)
{
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR p = NULL;
    PCHAR pPath = NULL;
    PCHAR pHostStart, pHostEnd;
    UINT32 headerCount;
    PSingleListNode pCurNode;
    UINT64 item;
    PRequestHeader pRequestHeader;    
        
    // Sign the request
    if(!bWss){
        CHK_STATUS(signAwsRequestInfo(pRequestInfo));
    }else{
        CHK_STATUS(signAwsRequestInfoQueryParam(pRequestInfo));
    }

    CHK_STATUS(getRequestHost(pRequestInfo->url, &pHostStart, &pHostEnd));
    CHK(pHostEnd == NULL || *pHostEnd == '/' || *pHostEnd == '?', STATUS_INTERNAL_ERROR);
    MEMCPY(pHost, pHostStart, pHostEnd-pHostStart);

    UINT32 pathLen = MAX_URI_CHAR_LEN;
    CHK(NULL != (pPath = (PCHAR) MEMCALLOC(pathLen + 1, SIZEOF(CHAR))), STATUS_NOT_ENOUGH_MEMORY);
    // Store the pPath
    pPath[MAX_URI_CHAR_LEN] = '\0';
    if (pHostEnd != NULL) {
        if (*pHostEnd == '/') {
            STRNCPY(pPath, pHostEnd, MAX_URI_CHAR_LEN);
        } else {
            pPath[0] = '/';
            STRNCPY(&pPath[1], pHostEnd, MAX_URI_CHAR_LEN - 1);
        }
    } else {
        pPath[0] = '/';
        pPath[1] = '\0';
    }

    p = (PCHAR)(outputBuf);
    /* header */
    p += SPRINTF(p, "%s %s%s HTTP/1.1\r\n", HTTP_METHOD_GET, uri, pParameterUriEncode);
    p += SPRINTF(p, "Accept: */*\r\n");


    CHK_STATUS(singleListGetHeadNode(pRequestInfo->pRequestHeaders, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(singleListGetNodeData(pCurNode, &item));
        pRequestHeader = (PRequestHeader) item;

        //pPrevNode = pCurNode;
        DLOGD("Appending header - %s %s", pRequestHeader->pName, pRequestHeader->pValue);
        p += SPRINTF(p, "%s: %s\r\n", pRequestHeader->pName, pRequestHeader->pValue);

        CHK_STATUS(singleListGetNextNode(pCurNode, &pCurNode));
    }
    /* Web socket upgrade */
        p += SPRINTF(p, "Pragma: no-cache\r\n");
        p += SPRINTF(p, "Cache-Control: no-cache\r\n");
        p += SPRINTF(p, "upgrade: WebSocket\r\n");
        p += SPRINTF(p, "connection: Upgrade\r\n");
        
        p += SPRINTF(p, "Sec-WebSocket-Key: %s\r\n", clientKey);
        p += SPRINTF(p, "Sec-WebSocket-Protocol: wss\r\n");
        p += SPRINTF(p, "Sec-WebSocket-Version: 13\r\n");


    p += SPRINTF(p, "\r\n" );
    /* body */
    p += SPRINTF(p, "%s\r\n", pRequestInfo->body );
    p += SPRINTF(p, "\r\n" );
CleanUp:

    SAFE_MEMFREE(pPath);
    return retStatus;
}