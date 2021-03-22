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


#define WSS_API_ENTER() DLOGD("enter")
#define WSS_API_EXIT() DLOGD("exit")
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

static VOID uriEncode(CHAR *ori, CHAR *dst)
{
    CHAR *p = dst;
    for (int i=0; i<STRLEN(ori); i++)
    {
        switch(ori[i])
        {
            case ':':
                p += SPRINTF(p, "%%3A");
                break;
            case '/':
                p += SPRINTF(p, "%%2F");
                break;
            case '&':
                p += SPRINTF(p, "%%3B");
                break;
            default:
                p += SPRINTF(p, "%c", ori[i]);
                break;
        }
    }
}
/*-----------------------------------------------------------*/


/*-----------------------------------------------------------*/

STATUS wssConnectSignalingChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    WSS_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    CHAR *p = NULL;
    BOOL bUseIotCert = FALSE;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;
    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0;

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext;
    CHAR pXAmzDate[SIGNATURE_DATE_TIME_STRING_LEN];

    /* Variables for HTTP request */
    CHAR *pHttpParameter = "";
    CHAR *pHttpBody = "";
    UINT32 uHttpBodyLen = 0;

    UINT32 uHttpStatusCode = 0;
    CHAR *uri = "/";
    CHAR pParameter[512];
    CHAR pParameterUriEncode[512];
    CHAR clientKey[WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1];

    int n;
    
    http_response_context_t* pHttpRspCtx = NULL;

    // temp interface.
    PCHAR pAccessKey = getenv(ACCESS_KEY_ENV_VAR);  // It's AWS access key if not using IoT certification.
    PCHAR pSecretKey = getenv(SECRET_KEY_ENV_VAR);  // It's secret of AWS access key if not using IoT certification.
    PCHAR pToken = NULL;
    PCHAR pRegion = pSignalingClient->pChannelInfo->pRegion;     // The desired region of KVS service
    PCHAR pService = KINESIS_VIDEO_SERVICE_NAME;    // KVS service name
    PCHAR pHost = NULL;
    PCHAR pUserAgent = "userAgent";//pSignalingClient->pChannelInfo->pCustomUserAgent;  // HTTP agent name

    CHK(NULL != (pHost = (CHAR *)MEMALLOC(MAX_CONTROL_PLANE_URI_CHAR_LEN)), STATUS_NOT_ENOUGH_MEMORY);
    SNPRINTF(pHost, MAX_CONTROL_PLANE_URI_CHAR_LEN, "%s.%s%s", 
                                                    KINESIS_VIDEO_SERVICE_NAME,
                                                    pSignalingClient->pChannelInfo->pRegion,
                                                    CONTROL_PLANE_URI_POSTFIX);


    DLOGD("%s(%d) connect\n", __func__, __LINE__);

    do
    {
        CHK((pChannelInfo != NULL && pChannelInfo->pChannelName[0] != '\0'), STATUS_INVALID_ARG);

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
        p += SPRINTF(p, "?X-Amz-ChannelARN=%s", pSignalingClient->channelDescription.channelArn);
        uriEncode(pParameter, pParameterUriEncode);


        /* Create canonical request and sign the request. */
        retStatus = AwsSignerV4_initContext( &signerContext, AWS_SIGNER_V4_BUFFER_SIZE );
        AwsSignerV4_initCanonicalRequest( &signerContext, HTTP_METHOD_GET, STRLEN(HTTP_METHOD_GET), uri, STRLEN(uri), pParameterUriEncode, STRLEN(pParameterUriEncode) );
        AwsSignerV4_addCanonicalHeader( &signerContext, HDR_HOST, STRLEN(HDR_HOST), pHost, STRLEN( pHost ) );
        AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, STRLEN(HDR_USER_AGENT), pUserAgent, STRLEN( pUserAgent ) );
        AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_DATE, STRLEN(HDR_X_AMZ_DATE), pXAmzDate, STRLEN( pXAmzDate ) );
        AwsSignerV4_addCanonicalBody( &signerContext, pHttpBody, STRLEN( pHttpBody ) );
        AwsSignerV4_sign( &signerContext, pSecretKey, STRLEN(pSecretKey), pRegion, STRLEN(pRegion), pService, STRLEN(pService), pXAmzDate, STRLEN(pXAmzDate) );

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
            if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
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
        p += SPRINTF(p, "%s %s%s HTTP/1.1\r\n", HTTP_METHOD_GET, uri, pParameterUriEncode);
        p += SPRINTF(p, "Host: %s\r\n", pHost);
        p += SPRINTF(p, "Accept: */*\r\n");
        p += SPRINTF(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                        AWS_SIG_V4_ALGORITHM,
                        pAccessKey,
                        AwsSignerV4_getScope( &signerContext ),
                        AwsSignerV4_getSignedHeader( &signerContext ),
                        AwsSignerV4_getHmacEncoded( &signerContext )
        );

        p += SPRINTF(p, "Pragma: no-cache\r\n");
        p += SPRINTF(p, "Cache-Control: no-cache\r\n");
        p += SPRINTF(p, "user-agent: %s\r\n", pUserAgent);
        p += SPRINTF(p, "X-Amz-Date: %s\r\n", pXAmzDate);

        /* Web socket upgrade */
        p += SPRINTF(p, "upgrade: WebSocket\r\n");
        p += SPRINTF(p, "connection: Upgrade\r\n");
        
        p += SPRINTF(p, "Sec-WebSocket-Key: %s\r\n", clientKey);
        p += SPRINTF(p, "Sec-WebSocket-Protocol: wss\r\n");
        p += SPRINTF(p, "Sec-WebSocket-Version: 13\r\n");

        p += SPRINTF(p, "\r\n");

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
        retStatus =  http_parse_start( &pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )retStatus, requiredHeader);
        
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


        PCHAR pResponseStr = http_get_http_body_location(pHttpRspCtx);
        UINT32 resultLen = http_get_http_body_length(pHttpRspCtx);
        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

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
            DLOGE("Unable to get endpoint:\r\n%.*s\r\n", (int)http_get_http_body_length(pHttpRspCtx), http_get_http_body_location(pHttpRspCtx));
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

    if(pHttpRspCtx != NULL){
        retStatus =  http_parse_detroy(pHttpRspCtx);
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
CleanUp:
    WSS_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/



//STATUS wssSendMessage(PSignalingClient pSignalingClient, PCHAR pMessageType, PCHAR peerClientId, PCHAR pMessage, UINT32 messageLen,
//                      PCHAR pCorrelationId, UINT32 correlationIdLen)
STATUS wssSendMessage(PSignalingClient pSignalingClient, PCHAR pMessageType, PCHAR peerClientId, PCHAR pMessage, UINT32 messageLen,
                      PCHAR pCorrelationId, UINT32 correlationIdLen)
{
    WSS_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
CleanUp:
    WSS_API_EXIT();
    return retStatus;
}

//STATUS wssTerminateThread(PSignalingClient pSignalingClient)
STATUS wssTerminateThread(PSignalingClient pSignalingClient)
{
    WSS_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
CleanUp:
    WSS_API_EXIT();
    return retStatus;
}