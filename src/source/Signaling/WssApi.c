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

// #YC_TBD, need to be fixed.
#define AWS_SIGNER_V4_BUFFER_SIZE           ( 4096+1024 )
#define MAX_CONNECTION_RETRY                ( 3 )
#define CONNECTION_RETRY_INTERVAL_IN_MS     ( 1000 )

#define LWS_MESSAGE_BUFFER_SIZE (SIZEOF(CHAR) * (MAX_SIGNALING_MESSAGE_LEN))

// Send message JSON template
#define SIGNALING_SEND_MESSAGE_TEMPLATE                                                                                                              \
    "{\n"                                                                                                                                            \
    "\t\"action\": \"%s\",\n"                                                                                                                        \
    "\t\"RecipientClientId\": \"%.*s\",\n"                                                                                                           \
    "\t\"MessagePayload\": \"%s\"\n"                                                                                                                 \
    "}"

// Send message JSON template with correlation id
#define SIGNALING_SEND_MESSAGE_TEMPLATE_WITH_CORRELATION_ID                                                                                          \
    "{\n"                                                                                                                                            \
    "\t\"action\": \"%s\",\n"                                                                                                                        \
    "\t\"RecipientClientId\": \"%.*s\",\n"                                                                                                           \
    "\t\"MessagePayload\": \"%s\",\n"                                                                                                                \
    "\t\"CorrelationId\": \"%.*s\"\n"                                                                                                                \
    "}"

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
/**
 * @brief   It is a non-blocking call, and it spin off one thread to handle the reception.
 * 
 * @param[in]
 * @param[in]
 * 
 * @return
*/
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
    CHAR pParameter[1024];
    CHAR pParameterUriEncode[1024];
    CHAR clientKey[WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1];

    int n;
    
    http_response_context_t* pHttpRspCtx = NULL;


    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);
    CHK(pSignalingClient->channelEndpointWss[0] != '\0', STATUS_INTERNAL_ERROR);
    ATOMIC_STORE_BOOL(&pSignalingClient->connected, FALSE);

    // temp interface.
    PCHAR pAccessKey = getenv(ACCESS_KEY_ENV_VAR);  // It's AWS access key if not using IoT certification.
    PCHAR pSecretKey = getenv(SECRET_KEY_ENV_VAR);  // It's secret of AWS access key if not using IoT certification.
    PCHAR pToken = NULL;
    PCHAR pRegion = pSignalingClient->pChannelInfo->pRegion;     // The desired region of KVS service
    PCHAR pService = KINESIS_VIDEO_SERVICE_NAME;    // KVS service name
    PCHAR pHost = NULL;
    
    PCHAR pUserAgent = "userAgent";//pSignalingClient->pChannelInfo->pCustomUserAgent;  // HTTP agent name

    CHK(NULL != (pHost = (CHAR *)MEMALLOC(STRLEN(pSignalingClient->channelEndpointWss)+1)), STATUS_NOT_ENOUGH_MEMORY);
    MEMSET(pHost, 0, STRLEN(pSignalingClient->channelEndpointWss+1));
    STRCPY(pHost, pSignalingClient->channelEndpointWss+6);
    DLOGD("pSignalingClient->channelEndpointWss:%s", pSignalingClient->channelEndpointWss);
    DLOGD("pHost:%s", pHost);

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
        DLOGD("pParameter:%d", strlen(pParameter));
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
        MEMSET(clientKey, 0, WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1);
        wssClientGenerateClientKey(clientKey, WSS_CLIENT_BASED64_RANDOM_SEED_LEN+1);

        p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
        p += SPRINTF(p, "%s %s%s HTTP/1.1\r\n", HTTP_METHOD_GET, uri, pParameterUriEncode);
        p += SPRINTF(p, "Host: %s\r\n", pHost);
        p += SPRINTF(p, "Accept: */*\r\n");
        p += SPRINTF(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                        AWS_SIG_V4_ALGORITHM,
                        pAccessKey,
                        AwsSignerV4_getScope( &signerContext ),
                        AwsSignerV4_getSignedHeader( &signerContext ),
                        AwsSignerV4_getHmacEncoded( &signerContext ));

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
            MEMCMP(node->value, HTTP_HEADER_VALUE_UPGRADE, node->valueLen) == 0 ){
            //DLOGD("connection upgrade\n");
        }

        node = http_get_value_by_field(requiredHeader, HTTP_HEADER_FIELD_UPGRADE, STRLEN(HTTP_HEADER_FIELD_UPGRADE));
        //DLOGD("val:%d, -%s-\n\n", val, node->value, );
        if( node != NULL && 
            node->valueLen == STRLEN(HTTP_HEADER_VALUE_WS) &&
            MEMCMP(node->value, HTTP_HEADER_VALUE_WS, node->valueLen) == 0 ){
            //DLOGD("upgrade websocket\n");
        }

        node = http_get_value_by_field(requiredHeader, HTTP_HEADER_FIELD_SEC_WS_ACCEPT, STRLEN(HTTP_HEADER_FIELD_SEC_WS_ACCEPT));
        //DLOGD("val:%d, -%s-\n\n", val, node->value, );
        if( node != NULL ){
            
            if(wssClientValidateAcceptKey(clientKey, WSS_CLIENT_BASED64_RANDOM_SEED_LEN, node->value, node->valueLen)!=0){
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
            /**
             * switch to wss client.
            */
            // #YC_TBD.
            

            DLOGD("connect signaling channel successfully.\n");
            /* We got a success response here. */
            WssClientContext* wss_client_ctx = NULL;
            // #YC_TBD.
            mbedtls_ssl_conf_read_timeout(&pNetworkContext->conf, 50);
            //mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
            //                                    mbedtls_timing_get_delay );
            wssClientCreate(&wss_client_ctx, pNetworkContext);
            // #YC_TBD !!!!!!!!! MUST
            pSignalingClient->pOngoingCallInfo = (PLwsCallInfo)wss_client_ctx;
            CHK_STATUS(THREAD_CREATE(&pSignalingClient->listenerTracker.threadId, wssClientStart, (PVOID) wss_client_ctx));
            CHK_STATUS(THREAD_DETACH(pSignalingClient->listenerTracker.threadId));
            ATOMIC_STORE_BOOL(&pSignalingClient->connected, TRUE);
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

CleanUp:

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

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pSignalingClient != NULL) {
        // Fix-up the timeout case
        SERVICE_CALL_RESULT serviceCallResult =
            (retStatus == STATUS_OPERATION_TIMED_OUT) ? SERVICE_CALL_NETWORK_CONNECTION_TIMEOUT : SERVICE_CALL_UNKNOWN;
        // Trigger termination
        if (!ATOMIC_LOAD_BOOL(&pSignalingClient->listenerTracker.terminated) &&
            pSignalingClient->pOngoingCallInfo != NULL /*&&
            pSignalingClient->pOngoingCallInfo->callInfo.pRequestInfo != NULL*/) {
            wssTerminateConnectionWithStatus(pSignalingClient, serviceCallResult);
        }

        ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) serviceCallResult);
    }
    WSS_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief   
 *          https://docs.aws.amazon.com/zh_tw/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis-7.html
 * 
 * @param[in]
 * 
 * @return 
*/
STATUS wssSendMessage(PSignalingClient pSignalingClient, PCHAR pMessageType, PCHAR peerClientId, PCHAR pMessage, UINT32 messageLen,
                      PCHAR pCorrelationId, UINT32 correlationIdLen)
{
    
    WSS_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    #if 0
    PCHAR pEncodedMessage = NULL;
    UINT32 size, writtenSize, correlationLen;
    BOOL awaitForResponse;

    // Ensure we are in a connected state
    CHK_STATUS(signalingFsmAccept(pSignalingClient, SIGNALING_STATE_CONNECTED));

    CHK(pSignalingClient != NULL && pSignalingClient->pOngoingCallInfo != NULL, STATUS_NULL_ARG);
    // #YC_TBD, need to enhance, #heap.
    CHK(NULL != (pEncodedMessage = (PCHAR) MEMALLOC(MAX_SESSION_DESCRIPTION_INIT_SDP_LEN + 1)), STATUS_NOT_ENOUGH_MEMORY);

    // Calculate the lengths if not specified
    if (messageLen == 0) {
        size = (UINT32) STRLEN(pMessage);
    } else {
        size = messageLen;
    }

    if (correlationIdLen == 0) {
        correlationLen = (UINT32) STRLEN(pCorrelationId);
    } else {
        correlationLen = correlationIdLen;
    }

    // Base64 encode the message
    writtenSize = MAX_SESSION_DESCRIPTION_INIT_SDP_LEN + 1;
    CHK_STATUS(base64Encode(pMessage, size, pEncodedMessage, &writtenSize));

    // Account for the template expansion + Action string + max recipient id
    size = SIZEOF(pSignalingClient->pOngoingCallInfo->sendBuffer) - LWS_PRE;
    CHK(writtenSize <= size, STATUS_SIGNALING_MAX_MESSAGE_LEN_AFTER_ENCODING);

    // Prepare json message
    if (correlationLen == 0) {
        writtenSize = (UINT32) SNPRINTF((PCHAR)(pSignalingClient->pOngoingCallInfo->sendBuffer + LWS_PRE),
                                        size,
                                        SIGNALING_SEND_MESSAGE_TEMPLATE,
                                        pMessageType,
                                        MAX_SIGNALING_CLIENT_ID_LEN,
                                        peerClientId,
                                        pEncodedMessage);
    } else {
        writtenSize = (UINT32) SNPRINTF((PCHAR)(pSignalingClient->pOngoingCallInfo->sendBuffer + LWS_PRE),
                                        size,
                                        SIGNALING_SEND_MESSAGE_TEMPLATE_WITH_CORRELATION_ID,
                                        pMessageType,
                                        MAX_SIGNALING_CLIENT_ID_LEN,
                                        peerClientId,
                                        pEncodedMessage,
                                        correlationLen,
                                        pCorrelationId);
    }

    // Validate against max
    CHK(writtenSize <= LWS_MESSAGE_BUFFER_SIZE, STATUS_SIGNALING_MAX_MESSAGE_LEN_AFTER_ENCODING);

    writtenSize *= SIZEOF(CHAR);
    CHK(writtenSize <= size, STATUS_INVALID_ARG);

    // Store the data pointer
    ATOMIC_STORE(&pSignalingClient->pOngoingCallInfo->sendBufferSize, LWS_PRE + writtenSize);
    ATOMIC_STORE(&pSignalingClient->pOngoingCallInfo->sendOffset, LWS_PRE);

    // Send the data to the web socket
    awaitForResponse = (correlationLen != 0) && BLOCK_ON_CORRELATION_ID;
    CHK_STATUS(lwsWriteData(pSignalingClient, awaitForResponse));

    // Re-setting the buffer size and offset
    ATOMIC_STORE(&pSignalingClient->pOngoingCallInfo->sendBufferSize, 0);
    ATOMIC_STORE(&pSignalingClient->pOngoingCallInfo->sendOffset, 0);

CleanUp:
    SAFE_MEMFREE(pEncodedMessage);
    #endif
    WSS_API_EXIT();
    return retStatus;
}

STATUS wssGetMessageTypeFromString(PCHAR typeStr, UINT32 typeLen, SIGNALING_MESSAGE_TYPE* pMessageType)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 len;

    CHK(typeStr != NULL && pMessageType != NULL, STATUS_NULL_ARG);

    if (typeLen == 0) {
        len = (UINT32) STRLEN(typeStr);
    } else {
        len = typeLen;
    }

    if (0 == STRNCMP(typeStr, SIGNALING_SDP_TYPE_OFFER, len)) {
        *pMessageType = SIGNALING_MESSAGE_TYPE_OFFER;
    } else if (0 == STRNCMP(typeStr, SIGNALING_SDP_TYPE_ANSWER, len)) {
        *pMessageType = SIGNALING_MESSAGE_TYPE_ANSWER;
    } else if (0 == STRNCMP(typeStr, SIGNALING_ICE_CANDIDATE, len)) {
        *pMessageType = SIGNALING_MESSAGE_TYPE_ICE_CANDIDATE;
    } else if (0 == STRNCMP(typeStr, SIGNALING_GO_AWAY, len)) {
        *pMessageType = SIGNALING_MESSAGE_TYPE_GO_AWAY;
    } else if (0 == STRNCMP(typeStr, SIGNALING_RECONNECT_ICE_SERVER, len)) {
        *pMessageType = SIGNALING_MESSAGE_TYPE_RECONNECT_ICE_SERVER;
    } else if (0 == STRNCMP(typeStr, SIGNALING_STATUS_RESPONSE, len)) {
        *pMessageType = SIGNALING_MESSAGE_TYPE_STATUS_RESPONSE;
    } else {
        *pMessageType = SIGNALING_MESSAGE_TYPE_UNKNOWN;
        CHK_WARN(FALSE, retStatus, "Unrecognized message type received");
    }

CleanUp:

    LEAVES();
    return retStatus;
}


PVOID wssReceiveMessageWrapper(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingMessageWrapper pSignalingMessageWrapper = (PSignalingMessageWrapper) args;
    PSignalingClient pSignalingClient = NULL;

    CHK(pSignalingMessageWrapper != NULL, STATUS_NULL_ARG);

    pSignalingClient = pSignalingMessageWrapper->pSignalingClient;

    CHK(pSignalingClient != NULL, STATUS_INTERNAL_ERROR);

    // Updating the diagnostics info before calling the client callback
    ATOMIC_INCREMENT(&pSignalingClient->diagnostics.numberOfMessagesReceived);

    // Calling client receive message callback if specified
    if (pSignalingClient->signalingClientCallbacks.messageReceivedFn != NULL) {
        CHK_STATUS(pSignalingClient->signalingClientCallbacks.messageReceivedFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                                &pSignalingMessageWrapper->receivedSignalingMessage));
    }

CleanUp:
    CHK_LOG_ERR(retStatus);

    SAFE_MEMFREE(pSignalingMessageWrapper);

    return (PVOID)(ULONG_PTR) retStatus;
}

STATUS wssReceiveMessage(PSignalingClient pSignalingClient, PCHAR pMessage, UINT32 messageLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    jsmn_parser parser;
    jsmntok_t* pTokens = NULL;
    UINT32 i, strLen, outLen = MAX_SIGNALING_MESSAGE_LEN;
    UINT32 tokenCount;
    PSignalingMessageWrapper pSignalingMessageWrapper = NULL;
#if !defined(KVS_PLAT_ESP_FREERTOS) && !defined(KVS_PLAT_RTK_FREERTOS)
    TID receivedTid = INVALID_TID_VALUE;
#endif
    BOOL parsedMessageType = FALSE, parsedStatusResponse = FALSE;
    PSignalingMessage pOngoingMessage;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);
    CHK(NULL != (pTokens = (jsmntok_t*) MEMALLOC(MAX_JSON_TOKEN_COUNT * SIZEOF(jsmntok_t))), STATUS_NOT_ENOUGH_MEMORY);

    // If we have a signalingMessage and if there is a correlation id specified then the response should be non-empty
    if (pMessage == NULL || messageLen == 0) {
        if (BLOCK_ON_CORRELATION_ID) {
            // Get empty correlation id message from the ongoing if exists
            CHK_STATUS(signalingGetOngoingMessage(pSignalingClient, EMPTY_STRING, EMPTY_STRING, &pOngoingMessage));
            if (pOngoingMessage == NULL) {
                DLOGW("Received an empty body for a message with no correlation id which has been already removed from the queue. Warning 0x%08x",
                      STATUS_SIGNALING_RECEIVE_EMPTY_DATA_NOT_SUPPORTED);
            } else {
                CHK_STATUS(signalingRemoveOngoingMessage(pSignalingClient, EMPTY_STRING));
            }
        }

        // Check if anything needs to be done
        CHK_WARN(pMessage != NULL && messageLen != 0, retStatus, "Signaling received an empty message");
    }

    // Parse the response
    jsmn_init(&parser);
    tokenCount = jsmn_parse(&parser, pMessage, messageLen, pTokens, MAX_JSON_TOKEN_COUNT);
    CHK(tokenCount > 1, STATUS_INVALID_API_CALL_RETURN_JSON);
    CHK(pTokens[0].type == JSMN_OBJECT, STATUS_INVALID_API_CALL_RETURN_JSON);

    CHK(NULL != (pSignalingMessageWrapper = (PSignalingMessageWrapper) MEMCALLOC(1, SIZEOF(SignalingMessageWrapper))), STATUS_NOT_ENOUGH_MEMORY);

    pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.version = SIGNALING_MESSAGE_CURRENT_VERSION;

    // Loop through the tokens and extract the stream description
    for (i = 1; i < tokenCount; i++) {
        if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "senderClientId")) {
            strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
            CHK(strLen <= MAX_SIGNALING_CLIENT_ID_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
            STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.peerClientId, pMessage + pTokens[i + 1].start, strLen);
            pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.peerClientId[MAX_SIGNALING_CLIENT_ID_LEN] = '\0';
            i++;
        } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "messageType")) {
            strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
            CHK(strLen <= MAX_SIGNALING_MESSAGE_TYPE_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
            CHK_STATUS(wssGetMessageTypeFromString(pMessage + pTokens[i + 1].start, strLen,
                                                &pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.messageType));

            parsedMessageType = TRUE;
            i++;
        } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "messagePayload")) {
            strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
            CHK(strLen <= MAX_SIGNALING_MESSAGE_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);

            // Base64 decode the message
            CHK_STATUS(base64Decode(pMessage + pTokens[i + 1].start, strLen,
                                    (PBYTE)(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payload), &outLen));
            pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payload[MAX_SIGNALING_MESSAGE_LEN] = '\0';
            pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payloadLen = outLen;
            i++;
        } else {
            if (!parsedStatusResponse) {
                if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "statusResponse")) {
                    parsedStatusResponse = TRUE;
                    i++;
                }
            } else {
                if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "correlationId")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_CORRELATION_ID_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
                    STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.correlationId, pMessage + pTokens[i + 1].start,
                            strLen);
                    pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.correlationId[MAX_CORRELATION_ID_LEN] = '\0';

                    i++;
                } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "errorType")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_ERROR_TYPE_STRING_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
                    STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.errorType, pMessage + pTokens[i + 1].start, strLen);
                    pSignalingMessageWrapper->receivedSignalingMessage.errorType[MAX_ERROR_TYPE_STRING_LEN] = '\0';

                    i++;
                } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "statusCode")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_STATUS_CODE_STRING_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);

                    // Parse the status code
                    CHK_STATUS(STRTOUI32(pMessage + pTokens[i + 1].start, pMessage + pTokens[i + 1].end, 10,
                                         (PUINT32)&pSignalingMessageWrapper->receivedSignalingMessage.statusCode));

                    i++;
                } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "description")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_MESSAGE_DESCRIPTION_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
                    STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.description, pMessage + pTokens[i + 1].start, strLen);
                    pSignalingMessageWrapper->receivedSignalingMessage.description[MAX_MESSAGE_DESCRIPTION_LEN] = '\0';

                    i++;
                }
            }
        }
    }

    // Message type is a mandatory field.
    CHK(parsedMessageType, STATUS_SIGNALING_INVALID_MESSAGE_TYPE);
    pSignalingMessageWrapper->pSignalingClient = pSignalingClient;

    switch (pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.messageType) {
        case SIGNALING_MESSAGE_TYPE_STATUS_RESPONSE:
            if (pSignalingMessageWrapper->receivedSignalingMessage.statusCode != SERVICE_CALL_RESULT_OK) {
                DLOGW("Failed to deliver message. Correlation ID: %s, Error Type: %s, Error Code: %u, Description: %s",
                      pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.correlationId,
                      pSignalingMessageWrapper->receivedSignalingMessage.errorType, pSignalingMessageWrapper->receivedSignalingMessage.statusCode,
                      pSignalingMessageWrapper->receivedSignalingMessage.description);

                // Store the response
                ATOMIC_STORE(&pSignalingClient->messageResult,
                             (SIZE_T) getServiceCallResultFromHttpStatus(pSignalingMessageWrapper->receivedSignalingMessage.statusCode));
            } else {
                // Success
                ATOMIC_STORE(&pSignalingClient->messageResult, (SIZE_T) SERVICE_CALL_RESULT_OK);
            }

            // Notify the awaiting send
            CVAR_BROADCAST(pSignalingClient->receiveCvar);
            // Delete the message wrapper and exit
            SAFE_MEMFREE(pSignalingMessageWrapper);
            CHK(FALSE, retStatus);
            break;

        case SIGNALING_MESSAGE_TYPE_GO_AWAY:
            // Move the describe state
            CHK_STATUS(wssTerminateConnectionWithStatus(pSignalingClient, SERVICE_CALL_RESULT_SIGNALING_GO_AWAY));

            // Delete the message wrapper and exit
            SAFE_MEMFREE(pSignalingMessageWrapper);

            // Iterate the state machinery
            CHK_STATUS(signalingFsmStep(pSignalingClient, retStatus));

            CHK(FALSE, retStatus);
            break;

        case SIGNALING_MESSAGE_TYPE_RECONNECT_ICE_SERVER:
            // Move to get ice config state
            CHK_STATUS(wssTerminateConnectionWithStatus(pSignalingClient, SERVICE_CALL_RESULT_SIGNALING_RECONNECT_ICE));

            // Delete the message wrapper and exit
            SAFE_MEMFREE(pSignalingMessageWrapper);

            // Iterate the state machinery
            CHK_STATUS(signalingFsmStep(pSignalingClient, retStatus));

            CHK(FALSE, retStatus);
            break;

        case SIGNALING_MESSAGE_TYPE_OFFER:
            CHK(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.peerClientId[0] != '\0',
                STATUS_SIGNALING_NO_PEER_CLIENT_ID_IN_MESSAGE);
            // Explicit fall-through !!!
        case SIGNALING_MESSAGE_TYPE_ANSWER:
        case SIGNALING_MESSAGE_TYPE_ICE_CANDIDATE:
            CHK(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payloadLen > 0 &&
                    pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payloadLen <= MAX_SIGNALING_MESSAGE_LEN,
                STATUS_SIGNALING_INVALID_PAYLOAD_LEN_IN_MESSAGE);
            CHK(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payload[0] != '\0', STATUS_SIGNALING_NO_PAYLOAD_IN_MESSAGE);
            break;

        default:
            break;
    }

#if !defined(KVS_PLAT_ESP_FREERTOS) && !defined(KVS_PLAT_RTK_FREERTOS)
    // Issue the callback on a separate thread
    CHK_STATUS(THREAD_CREATE(&receivedTid, wssReceiveMessageWrapper, (PVOID) pSignalingMessageWrapper));
    CHK_STATUS(THREAD_DETACH(receivedTid));
#else
    CHK_STATUS(lwsDispatchMsg((PVOID) pSignalingMessageWrapper));
#endif

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (pSignalingClient != NULL && STATUS_FAILED(retStatus)) {
        ATOMIC_INCREMENT(&pSignalingClient->diagnostics.numberOfRuntimeErrors);
        if (pSignalingClient->signalingClientCallbacks.errorReportFn != NULL) {
            retStatus = pSignalingClient->signalingClientCallbacks.errorReportFn(pSignalingClient->signalingClientCallbacks.customData, retStatus,
                                                                                 pMessage, messageLen);
        }
#if !defined(KVS_PLAT_ESP_FREERTOS) && !defined(KVS_PLAT_RTK_FREERTOS)
        // Kill the receive thread on error
        if (IS_VALID_TID_VALUE(receivedTid)) {
            THREAD_CANCEL(receivedTid);
        }

        SAFE_MEMFREE(pSignalingMessageWrapper);
#endif
    }
    SAFE_MEMFREE(pTokens);
    LEAVES();
    return retStatus;
}

/**
 * @brief   #YC_TBD.
 * 
 * @param[]
 * @param[]
 * 
 * @return
*/
STATUS wssWakeServiceEventLoop(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    // Early exit in case we don't need to do anything
    CHK(pSignalingClient != NULL && pSignalingClient->pWssContext != NULL, retStatus);

    MUTEX_LOCK(pSignalingClient->lwsServiceLock);
    //lws_callback_on_writable_all_protocol(pSignalingClient->pWssContext, &pSignalingClient->signalingProtocols[WSS_SIGNALING_PROTOCOL_INDEX]);
    MUTEX_UNLOCK(pSignalingClient->lwsServiceLock);

CleanUp:

    LEAVES();
    return retStatus;
}

/**
 * @brief   terminate the websocket connection.
 * 
 * @param[in]
 * @param[in]
 * 
 * @return
*/
STATUS wssTerminateConnectionWithStatus(PSignalingClient pSignalingClient, SERVICE_CALL_RESULT callResult)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    ATOMIC_STORE_BOOL(&pSignalingClient->connected, FALSE);
    CVAR_BROADCAST(pSignalingClient->connectedCvar);
    CVAR_BROADCAST(pSignalingClient->receiveCvar);
    CVAR_BROADCAST(pSignalingClient->sendCvar);
    ATOMIC_STORE(&pSignalingClient->messageResult, (SIZE_T) SERVICE_CALL_UNKNOWN);
    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) callResult);

    if (pSignalingClient->pOngoingCallInfo != NULL) {
        ATOMIC_STORE_BOOL(&pSignalingClient->pOngoingCallInfo->cancelService, TRUE);
    }

    // Wake up the service event loop
    CHK_STATUS(wssWakeServiceEventLoop(pSignalingClient));
    // waiting the termination of listener thread.
    CHK_STATUS(signalingAwaitForThreadTermination(&pSignalingClient->listenerTracker, SIGNALING_CLIENT_SHUTDOWN_TIMEOUT));

CleanUp:

    LEAVES();
    return retStatus;
}


STATUS wssTerminateListenerLoop(PSignalingClient pSignalingClient)
{
    WSS_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, retStatus);

    if (pSignalingClient->pOngoingCallInfo != NULL) {
        // Check if anything needs to be done
        CHK(!ATOMIC_LOAD_BOOL(&pSignalingClient->listenerTracker.terminated), retStatus);

        // Terminate the listener
        wssTerminateConnectionWithStatus(pSignalingClient, SERVICE_CALL_RESULT_OK);
    }

CleanUp:

    WSS_API_EXIT();
    return retStatus;
}
