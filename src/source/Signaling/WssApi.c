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

#define LOG_CLASS "WssApi"
#include "../Include_i.h"

#include "json_helper.h"
#include "http_helper.h"
#include "parson.h"
#include "wslay/wslay.h"

/*-----------------------------------------------------------*/

#define KVS_ENDPOINT_TCP_PORT   "443"
#define HTTP_METHOD_POST        "POST"
#define HTTP_METHOD_GET        "GET"


/*-----------------------------------------------------------*/

#define HDR_CONNECTION                  "connection"
#define HDR_HOST                        "host"
#define HDR_TRANSFER_ENCODING           "transfer-encoding"
#define HDR_USER_AGENT                  "user-agent"
#define HDR_X_AMZ_DATE                  "x-amz-date"
#define HDR_X_AMZ_SECURITY_TOKEN        "x-amz-security-token"
#define HDR_X_AMZN_FRAG_ACK_REQUIRED    "x-amzn-fragment-acknowledgment-required"
#define HDR_X_AMZN_FRAG_T_TYPE          "x-amzn-fragment-timecode-type"
#define HDR_X_AMZN_PRODUCER_START_T     "x-amzn-producer-start-timestamp"
#define HDR_X_AMZN_STREAM_NAME          "x-amzn-stream-name"
#define HDR_X_AMZN_CHANNELARN           "X-Amz-ChannelARN"


#define MAX_STRLEN_OF_INT32_t   ( 11 )
#define MAX_STRLEN_OF_UINT32    ( 10 )
#define MIN_FRAGMENT_LENGTH     ( 6 )

#define HTTP_HEADER_FIELD_CONNECTION "Connection"
#define HTTP_HEADER_FIELD_UPGRADE "upgrade"
#define HTTP_HEADER_FIELD_SEC_WS_ACCEPT "sec-websocket-accept"


#define HTTP_HEADER_VALUE_UPGRADE "upgrade"
#define HTTP_HEADER_VALUE_WS "websocket"


#define AWS_SIGNER_V4_BUFFER_SIZE           ( 4096 )
#define MAX_CONNECTION_RETRY                ( 3 )
#define CONNECTION_RETRY_INTERVAL_IN_MS     ( 1000 )
/*-----------------------------------------------------------*/
/*-----------------------------------------------------------*/

static INT32 checkServiceParameter( webrtcServiceParameter_t * pServiceParameter )
{
    if( pServiceParameter->pAccessKey == NULL ||
        pServiceParameter->pSecretKey == NULL ||
        pServiceParameter->pRegion == NULL ||
        pServiceParameter->pService == NULL ||
        pServiceParameter->pHost == NULL ||
        pServiceParameter->pUserAgent == NULL )
    {
        return STATUS_INVALID_ARG;
    }
    else
    {
        return STATUS_SUCCESS;
    }
}

static VOID uriEncode(CHAR *ori, CHAR *dst)
{
    CHAR *p = dst;
    for (int i=0; i<STRLEN(ori); i++)
    {
        switch(ori[i])
        {
            case ':':
                p += sprintf(p, "%%3A");
                break;
            case '/':
                p += sprintf(p, "%%2F");
                break;
            case '&':
                p += sprintf(p, "%%3B");
                break;
            default:
                p += sprintf(p, "%c", ori[i]);
                break;
        }
    }
}
/*-----------------------------------------------------------*/


/*-----------------------------------------------------------*/

STATUS wssConnectSignalingChannel( webrtcServiceParameter_t * pServiceParameter,
                        webrtcChannelInfo_t * pChannelInfo)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHAR *p = NULL;
    BOOL bUseIotCert = false;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0;

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext;
    CHAR pXAmzDate[SIGNATURE_DATE_TIME_STRING_LEN];

    /* Variables for HTTP request */
    CHAR *pHttpParameter = "";

    UINT32 uHttpBodyLen = 0;

    UINT32 uHttpStatusCode = 0;
    CHAR *method = "GET";
    CHAR *uri = "/";
    CHAR pParameter[512];
    CHAR pParameterUriEncode[512];
    CHAR clientKey[WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1];

    int n;
    CHAR *pHttpBody = "";
    http_response_context_t* httpRspCtx = NULL;

    DLOGD("%s(%d) connect\n", __func__, __LINE__);

    do
    {
        if( checkServiceParameter( pServiceParameter ) != STATUS_SUCCESS )
        {
            retStatus = STATUS_INVALID_ARG;
            break;
        }
        else if( pChannelInfo == NULL  || pChannelInfo->channelName[0] == '\0')
        {
            retStatus = STATUS_INVALID_ARG;
            break;
        }

        if( pServiceParameter->pToken != NULL )
        {
            bUseIotCert = true;
        }

        /* generate HTTP request body */
        

        /* generate UTC time in x-amz-date formate */
        retStatus = getTimeInIso8601( pXAmzDate, sizeof( pXAmzDate ) );

        if( retStatus != STATUS_SUCCESS )
        {
            DLOGD("%s(%d) connect\n", __func__, __LINE__);
            break;
        }
        //strcpy(pXAmzDate, "20210311T024335Z");
        p = pParameter;
        p += sprintf(p, "?X-Amz-ChannelARN=%s", pChannelInfo->channelArn);
        uriEncode(pParameter, pParameterUriEncode);


        /* Create canonical request and sign the request. */
        retStatus = AwsSignerV4_initContext( &signerContext, AWS_SIGNER_V4_BUFFER_SIZE );
        AwsSignerV4_initCanonicalRequest( &signerContext, method, STRLEN(method), uri, STRLEN(uri), pParameterUriEncode, STRLEN(pParameterUriEncode) );
        AwsSignerV4_addCanonicalHeader( &signerContext, "host", STRLEN("host"), pServiceParameter->pHost, STRLEN( pServiceParameter->pHost ) );
        AwsSignerV4_addCanonicalHeader( &signerContext, "user-agent", STRLEN("user-agent"), pServiceParameter->pUserAgent, STRLEN( pServiceParameter->pUserAgent ) );
        AwsSignerV4_addCanonicalHeader( &signerContext, "x-amz-date", STRLEN("x-amz-date"), pXAmzDate, STRLEN( pXAmzDate ) );
        AwsSignerV4_addCanonicalBody( &signerContext, pHttpBody, STRLEN( pHttpBody ) );
        AwsSignerV4_sign( &signerContext, pServiceParameter->pSecretKey, STRLEN(pServiceParameter->pSecretKey), pServiceParameter->pRegion, STRLEN(pServiceParameter->pRegion), pServiceParameter->pService, STRLEN(pServiceParameter->pService), pXAmzDate, STRLEN(pXAmzDate) );

        /* Initialize and generate HTTP request, then send it. */
        pNetworkContext = ( NetworkContext_t * ) MEMALLOC( sizeof( NetworkContext_t ) );
        if( pNetworkContext == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            DLOGD("%s(%d) connect\n", __func__, __LINE__);
            break;
        }

        if( ( retStatus = initNetworkContext( pNetworkContext ) ) != STATUS_SUCCESS )
        {
            DLOGD("%s(%d) connect\n", __func__, __LINE__);
            break;
        }

        for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
        {
            if( ( retStatus = connectToServer( pNetworkContext, pServiceParameter->pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                DLOGD("%s(%d) connect successfully\n", __func__, __LINE__);
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        /*
            GET /?X-Amz-Algorithm=AWS4-HMAC-SHA256&
            X-Amz-ChannelARN=arn%3Aaws%3Akinesisvideo%3Aus-west-2%3A021108525330%3Achannel%2FScaryTestChannel%2F1599141861798&
            X-Amz-Credential=AKIAQJ2RKREJMCCKFZ3G%2F20210309%2Fus-west-2%2Fkinesisvideo%2Faws4_request&
            X-Amz-Date=20210309T151602Z&
            X-Amz-Expires=604800&
            X-Amz-SignedHeaders=host&
            X-Amz-Signature=1797277081a3c6d77b4ad3acdd6515348fbed9d015bcabf0e891d9388d29ae5e HTTP/1.1
            Pragma: no-cache
            Cache-Control: no-cache
            Host: m-d73cdb00.kinesisvideo.us-west-2.amazonaws.com
            Upgrade: websocket
            Connection: Upgrade
            Sec-WebSocket-Key: yZfoKfFLHC2SNs5mO4HmaQ==
            Sec-WebSocket-Protocol: wss
            Sec-WebSocket-Version: 13
        */
        memset(clientKey, 0, WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1);
        wss_client_generate_client_key(clientKey, WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1);

        p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
        p += sprintf(p, "%s %s%s HTTP/1.1\r\n", method, uri, pParameterUriEncode);
        p += sprintf(p, "Host: %s\r\n", pServiceParameter->pHost);
        p += sprintf(p, "Accept: */*\r\n");
        p += sprintf(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                        AWS_SIG_V4_ALGORITHM,
                        pServiceParameter->pAccessKey,
                        AwsSignerV4_getScope( &signerContext ),
                        AwsSignerV4_getSignedHeader( &signerContext ),
                        AwsSignerV4_getHmacEncoded( &signerContext )
        );

        p += sprintf(p, "Pragma: no-cache\r\n");
        p += sprintf(p, "Cache-Control: no-cache\r\n");
        p += sprintf(p, "user-agent: %s\r\n", pServiceParameter->pUserAgent);
        p += sprintf(p, "X-Amz-Date: %s\r\n", pXAmzDate);

        /* Web socket upgrade */
        p += sprintf(p, "upgrade: WebSocket\r\n");
        p += sprintf(p, "connection: Upgrade\r\n");
        
        p += sprintf(p, "Sec-WebSocket-Key: %s\r\n", clientKey);
        p += sprintf(p, "Sec-WebSocket-Protocol: wss\r\n");
        p += sprintf(p, "Sec-WebSocket-Version: 13\r\n");

        p += sprintf(p, "\r\n");

        DLOGD("--\nsending http request:\n%s\n--\n", pNetworkContext->pHttpSendBuffer);

        AwsSignerV4_terminateContext(&signerContext);

        uBytesToSend = p - ( CHAR * )pNetworkContext->pHttpSendBuffer;
        retStatus = networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend );
        if( retStatus != uBytesToSend )
        {
            retStatus = STATUS_SEND_DATA_FAILED;
            break;
        }

        retStatus = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
        DLOGD("--\nreceived http response:\n%s\n--\n", pNetworkContext->pHttpRecvBuffer);
        if( retStatus < STATUS_SUCCESS )
        {
            break;
        }

        //DLOGD("start parsing \n");
        struct list_head* requiredHeader = malloc(sizeof(struct list_head));
        // on_status, Switching Protocols
        // Connection, upgrade
        // upgrade, websocket
        // sec-websocket-accept, P9UpKZWjaPkoB8NXkHhLgAYqRtc=
        INIT_LIST_HEAD(requiredHeader);
        http_add_required_header(requiredHeader, HTTP_HEADER_FIELD_CONNECTION, STRLEN(HTTP_HEADER_FIELD_CONNECTION), NULL, 0);
        http_add_required_header(requiredHeader, HTTP_HEADER_FIELD_UPGRADE, STRLEN(HTTP_HEADER_FIELD_UPGRADE), NULL, 0);
        http_add_required_header(requiredHeader, HTTP_HEADER_FIELD_SEC_WS_ACCEPT, STRLEN(HTTP_HEADER_FIELD_SEC_WS_ACCEPT), NULL, 0);
        retStatus =  http_parse_start( &httpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )retStatus, requiredHeader);
        
        http_field_t* node;
        node = http_get_value_by_field(requiredHeader, HTTP_HEADER_FIELD_CONNECTION, STRLEN(HTTP_HEADER_FIELD_CONNECTION));
        //DLOGD("val:%d, -%s-\n\n", val, node->value, );
        if( node != NULL && 
            node->valueLen == STRLEN(HTTP_HEADER_VALUE_UPGRADE) &&
            memcmp(node->value, HTTP_HEADER_VALUE_UPGRADE, node->valueLen) == 0 ){
            //DLOGD("connection upgrade\n");
        }

        node = http_get_value_by_field(requiredHeader, HTTP_HEADER_FIELD_UPGRADE, STRLEN(HTTP_HEADER_FIELD_UPGRADE));
        //DLOGD("val:%d, -%s-\n\n", val, node->value, );
        if( node != NULL && 
            node->valueLen == STRLEN(HTTP_HEADER_VALUE_WS) &&
            memcmp(node->value, HTTP_HEADER_VALUE_WS, node->valueLen) == 0 ){
            //DLOGD("upgrade websocket\n");
        }

        node = http_get_value_by_field(requiredHeader, HTTP_HEADER_FIELD_SEC_WS_ACCEPT, STRLEN(HTTP_HEADER_FIELD_SEC_WS_ACCEPT));
        //DLOGD("val:%d, -%s-\n\n", val, node->value, );
        if( node != NULL ){
            
            if(wss_client_validate_accept_key(clientKey, WSS_CLIENT_BASED64_RANDOM_SEED_LEN, node->value, node->valueLen)!=0){
                DLOGD("validate accept key failed\n");
            }else{
                DLOGD("validate accept key failed success\n");
            }
        }


        uHttpStatusCode = http_get_http_status_code(httpRspCtx);

        /* Check HTTP results */
        if( uHttpStatusCode == 101 )
        {
            DLOGD("connect signaling channel successfully.\n");
            /* We got a success response here. */
            wss_client_context_t* wss_client_ctx = NULL;
            // #YC_TBD.
            mbedtls_ssl_conf_read_timeout(&pNetworkContext->conf, 50);
            //mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
            //                                    mbedtls_timing_get_delay );
            wss_client_create(&wss_client_ctx, pNetworkContext);
            wss_client_start(wss_client_ctx);
        }
        else if( uHttpStatusCode == 404 )
        {
            retStatus = STATUS_HTTP_RES_NOT_FOUND_ERROR;
            break;
        }
        else
        {
            DLOGE("Unable to get endpoint:\r\n%.*s\r\n", (int)http_get_http_body_length(httpRspCtx), http_get_http_body_location(httpRspCtx));
            if( uHttpStatusCode == 400 )
            {
                retStatus = STATUS_HTTP_REST_EXCEPTION_ERROR;
                break;
            }
            else if( uHttpStatusCode == 401 )
            {
                retStatus = STATUS_HTTP_REST_NOT_AUTHORIZED_ERROR;
                break;
            }
            else
            {
                retStatus = STATUS_HTTP_REST_UNKNOWN_ERROR;
                break;
            }
        }
        
    } while ( 0 );

    if(httpRspCtx != NULL){
        retStatus =  http_parse_detroy(httpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            DLOGD("destroying http parset failed. \n");
        }
    }

    if( pNetworkContext != NULL )
    {
        //disconnectFromServer( pNetworkContext );
        //terminateNetworkContext(pNetworkContext);
        //MEMFREE( pNetworkContext );
        AwsSignerV4_terminateContext(&signerContext);
    }

    return retStatus;
}

/*-----------------------------------------------------------*/



STATUS wssSendMessage(PSignalingClient pSignalingClient, PCHAR pMessageType, PCHAR peerClientId, PCHAR pMessage, UINT32 messageLen,
                      PCHAR pCorrelationId, UINT32 correlationIdLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    return retStatus;
}


STATUS wssTerminateThread(PSignalingClient pSignalingClient)
{
    STATUS retStatus = STATUS_SUCCESS;
    return retStatus;
}