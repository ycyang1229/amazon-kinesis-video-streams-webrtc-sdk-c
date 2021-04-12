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

#define LOG_CLASS "HttpApi"
#include "../Include_i.h"


#define HTTP_API_ENTER() //DLOGD("enter")
#define HTTP_API_EXIT() //DLOGD("exit")


/*-----------------------------------------------------------*/
#define KVS_ENDPOINT_TCP_PORT   "443"
/*-----------------------------------------------------------*/
// API postfix definitions
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_CreateSignalingChannel.html
#define WEBRTC_API_CREATE_SIGNALING_CHANNEL       "/createSignalingChannel"
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_DeleteSignalingChannel.html
#define WEBRTC_API_DELETE_SIGNALING_CHANNEL       "/deleteSignalingChannel"
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_DescribeSignalingChannel.html
#define WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL     "/describeSignalingChannel"
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_GetSignalingChannelEndpoint.html
#define WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT "/getSignalingChannelEndpoint"
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_ListSignalingChannels.html
#define WEBRTC_API_LIST_SIGNALING_CHANNEL         "/listSignalingChannels"
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_UpdateSignalingChannel.html
#define WEBRTC_API_UPDATE_SIGNALING_CHANNEL       "/updateSignalingChannel"
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_GetIceServerConfig.html
#define WEBRTC_API_GET_ICE_CONFIG                 "/v1/get-ice-server-config"
/*-----------------------------------------------------------*/
#define SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT (2 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define MAX_CONNECTION_RETRY                ( 3 )
#define CONNECTION_RETRY_INTERVAL_IN_MS     ( 1000 )
/*-----------------------------------------------------------*/
// API request body
/**
 * @brief   API_CreateSignalingChannel
 * POST /createSignalingChannel HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelName": "string",
 *    "ChannelType": "string",
 *    "SingleMasterConfiguration": { 
 *       "MessageTtlSeconds": number
 *    },
 *    "Tags": [ 
 *       { 
 *          "Key": "string",
 *          "Value": "string"
 *       }
 *    ]
 * }
*/
#define CREATE_CHANNEL_JSON_TEMPLATE                                                                                                           \
    "{\n\t\"ChannelName\": \"%s\""                                                                                                                  \
    "\n}"

// Parameterized string for TagStream API - we should have at least one tag
#define TAGS_PARAM_JSON_TEMPLATE ",\n\t\"Tags\": [%s\n\t]"
#define TAG_PARAM_JSON_OBJ_TEMPLATE "\n\t\t{\"Key\": \"%s\", \"Value\": \"%s\"},"

/**
 * @brief   API_DeleteSignalingChannel
 * POST /deleteSignalingChannel HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelARN": "string",
 *    "CurrentVersion": "string"
 * }
*/
#define DELETE_CHANNEL_PARAM_JSON_TEMPLATE                                                                                                           \
    "{\n\t\"ChannelARN\": \"%s\","                                                                                                                   \
    "\n\t\"CurrentVersion\": \"%s\"\n}"

/**
 * @brief   API_DescribeSignalingChannel
 * POST /describeSignalingChannel HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelARN": "string",
 *    "ChannelName": "string"
 * }
*/
#define DESCRIBE_CHANNEL_JSON_TEMPLATE "{\n\t\"ChannelName\": \"%s\"\n}"

/**
 * @brief   API_GetSignalingChannelEndpoint
 * POST /getSignalingChannelEndpoint HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelARN": "string",
 *    "SingleMasterChannelEndpointConfiguration": { 
 *       "Protocols": [ "string" ],
 *       "Role": "string"
 *    }
 * }
*/
#define GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE                                                                                                     \
    "{\n\t\"ChannelARN\": \"%s\","                                                                                                                   \
    "\n\t\"SingleMasterChannelEndpointConfiguration\": {"                                                                                            \
    "\n\t\t\"Protocols\": [%s],"                                                                                                                     \
    "\n\t\t\"Role\": \"%s\""                                                                                                                         \
    "\n\t}\n}"
/**
 * @brief   API_ListSignalingChannels
 * POST /listSignalingChannels HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelNameCondition": { 
 *       "ComparisonOperator": "string",
 *       "ComparisonValue": "string"
 *    },
 *    "MaxResults": number,
 *    "NextToken": "string"
 * }
*/
//#define LIST_SIGNALING_CHANNELS_PARAM_JSON_TEMPLATE

/**
 * @brief   API_UpdateSignalingChannel
 * POST /updateSignalingChannel HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelARN": "string",
 *    "CurrentVersion": "string",
 *    "SingleMasterConfiguration": { 
 *       "MessageTtlSeconds": number
 *    }
 * }
*/
//#define UPDATE_SIGNALING_CHANNELS_PARAM_JSON_TEMPLATE

// Parameterized string for Get Ice Server Config API
/**
 * @brief   API_AWSAcuitySignalingService_GetIceServerConfig
 * POST /v1/get-ice-server-config HTTP/1.1
 * Content-type: application/json
 * 
 * {
 *    "ChannelARN": "string",
 *    "ClientId": "string",
 *    "Service": "string",
 *    "Username": "string"
 * }
*/
#define GET_ICE_CONFIG_PARAM_JSON_TEMPLATE                                                                                                           \
    "{\n\t\"ChannelARN\": \"%s\","                                                                                                                   \
    "\n\t\"ClientId\": \"%s\","                                                                                                                      \
    "\n\t\"Service\": \"TURN\""                                                                                                                      \
    "\n}"

#define MAX_STRLEN_OF_INT32_t   ( 11 )
#define MAX_STRLEN_OF_UINT32    ( 10 )

/*-----------------------------------------------------------*/
/*-----------------------------------------------------------*/

/*-----------------------------------------------------------*/
/**
 * 
*/
STATUS httpApiCreateChannl(PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;

    /* Variables for network connection */
    NetworkContext_t* pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0, uBytesReceived = 0;

    /* Variables for HTTP request */
    PCHAR pUrl = NULL;
    PRequestInfo pRequestInfo = NULL;
    PCHAR pHttpBody = NULL;

    // temp interface.
    //PCHAR pAccessKey = pSignalingClient->pAwsCredentials->accessKeyId;
    //PCHAR pSecretKey = pSignalingClient->pAwsCredentials->secretKey;
    //PCHAR pToken = pSignalingClient->pAwsCredentials->sessionToken;
    //PCHAR pRegion = pSignalingClient->pChannelInfo->pRegion;     // The desired region of KVS service
    //PCHAR pService = KINESIS_VIDEO_SERVICE_NAME;    // KVS service name
    PCHAR pHost = NULL;
    //PCHAR pUserAgent = pChannelInfo->pUserAgent;//pSignalingClient->pChannelInfo->pCustomUserAgent;  // HTTP agent name
    // rsp
    UINT32 uHttpStatusCode = 0;
    HttpResponseContext* pHttpRspCtx = NULL;
    PCHAR pResponseStr;
    UINT32 resultLen;


    CHK(NULL != (pHost = (PCHAR)MEMALLOC(MAX_CONTROL_PLANE_URI_CHAR_LEN)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pUrl = (PCHAR)MEMALLOC(STRLEN(pSignalingClient->pChannelInfo->pControlPlaneUrl) +
                                        STRLEN(WEBRTC_API_CREATE_SIGNALING_CHANNEL) + 1)), STATUS_NOT_ENOUGH_MEMORY);

    // Create the API url
    STRCPY(pUrl, pSignalingClient->pChannelInfo->pControlPlaneUrl);
    STRCAT(pUrl, WEBRTC_API_CREATE_SIGNALING_CHANNEL);

    CHK(NULL != (pHttpBody = (CHAR *)MEMALLOC(  SIZEOF( CREATE_CHANNEL_JSON_TEMPLATE ) +
                                                STRLEN( pChannelInfo->pChannelName ) +
                                                MAX_STRLEN_OF_UINT32 + 1 )), STATUS_NOT_ENOUGH_MEMORY);

    /* generate HTTP request body */
    SPRINTF( pHttpBody, CREATE_CHANNEL_JSON_TEMPLATE, pChannelInfo->pChannelName);
    // Create the request info with the body
    CHK_STATUS(createRequestInfo(pUrl, pHttpBody, pSignalingClient->pChannelInfo->pRegion, (PCHAR)pSignalingClient->pChannelInfo->pCertPath, NULL, NULL,
                                 SSL_CERTIFICATE_TYPE_NOT_SPECIFIED, pSignalingClient->pChannelInfo->pUserAgent,
                                 SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT, SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT,
                                 DEFAULT_LOW_SPEED_LIMIT, DEFAULT_LOW_SPEED_TIME_LIMIT, pSignalingClient->pAwsCredentials, &pRequestInfo));

    /* Initialize and generate HTTP request, then send it. */
    CHK(NULL != (pNetworkContext = (NetworkContext_t *)MEMALLOC( SIZEOF(NetworkContext_t))), STATUS_NOT_ENOUGH_MEMORY);
    CHK_STATUS(initNetworkContext( pNetworkContext ) );
    
    httpPackSendBuf(pRequestInfo, HTTP_REQUEST_VERB_POST_STRING, pHost, MAX_CONTROL_PLANE_URI_CHAR_LEN, (PCHAR)pNetworkContext->pHttpSendBuffer, MAX_HTTP_SEND_BUFFER_LEN, FALSE, NULL);

    for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
    {
        if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
        {
            break;
        }
        THREAD_SLEEP( CONNECTION_RETRY_INTERVAL_IN_MS*HUNDREDS_OF_NANOS_IN_A_MILLISECOND );
    }


    uBytesToSend = STRLEN((PCHAR)pNetworkContext->pHttpSendBuffer);
    CHK(uBytesToSend == networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend ), STATUS_SEND_DATA_FAILED);
    uBytesReceived = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
    CHK(uBytesReceived > 0, STATUS_RECV_DATA_FAILED);

    CHK_STATUS(httpParserStart(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )uBytesReceived, NULL));

    pResponseStr = httpParserGetHttpBodyLocation(pHttpRspCtx);
    resultLen = httpParserGetHttpBodyLength(pHttpRspCtx);
    uHttpStatusCode = httpParserGetHttpStatusCode(pHttpRspCtx);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
    /* Check HTTP results */
    
    CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);

    CHK_STATUS(httpApiRspCreateChannel( ( const CHAR * )pResponseStr, resultLen, pSignalingClient ));

CleanUp:

    CHK_LOG_ERR(retStatus);

    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
    }

    if(pHttpRspCtx != NULL)
    {
        retStatus =  httpParserDetroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }
    SAFE_MEMFREE(pHttpBody);
    SAFE_MEMFREE(pHost);
    SAFE_MEMFREE(pUrl);
    freeRequestInfo(&pRequestInfo);
    
    HTTP_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/
/**
 * @brief   
 *          
 *
 * 
 * @param[]
 * @
*/
STATUS httpApiDescribeChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0, uBytesReceived = 0;

    /* Variables for HTTP request */
    // http req.
    PCHAR pUrl = NULL;
    PRequestInfo pRequestInfo = NULL;
    PCHAR pHttpBody = NULL;

    // temp interface.
    //PCHAR pAccessKey = pSignalingClient->pAwsCredentials->accessKeyId;
    //PCHAR pSecretKey = pSignalingClient->pAwsCredentials->secretKey;
    //PCHAR pToken = pSignalingClient->pAwsCredentials->sessionToken;
    //PCHAR pRegion = pSignalingClient->pChannelInfo->pRegion;     // The desired region of KVS service
    //PCHAR pService = KINESIS_VIDEO_SERVICE_NAME;    // KVS service name
    PCHAR pHost = NULL;
    //PCHAR pUserAgent = pChannelInfo->pUserAgent;//pSignalingClient->pChannelInfo->pCustomUserAgent;  // HTTP agent name
    // rsp
    UINT32 uHttpStatusCode = 0;
    HttpResponseContext* pHttpRspCtx = NULL;
    PCHAR pResponseStr;
    UINT32 resultLen;
    
    CHK(NULL != (pHost = (PCHAR)MEMALLOC(MAX_CONTROL_PLANE_URI_CHAR_LEN)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pUrl = (PCHAR) MEMALLOC(STRLEN(pSignalingClient->pChannelInfo->pControlPlaneUrl) +
                                        STRLEN(WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL) + 1)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pHttpBody = (PCHAR) MEMALLOC(STRLEN(DESCRIBE_CHANNEL_JSON_TEMPLATE)+ 
                                              STRLEN(pSignalingClient->pChannelInfo->pChannelName)+1)), STATUS_NOT_ENOUGH_MEMORY);
    // Create the http url
    STRCPY(pUrl, pSignalingClient->pChannelInfo->pControlPlaneUrl);
    STRCAT(pUrl, WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL);
    // create the http body
    SNPRINTF(pHttpBody, MAX_JSON_PARAMETER_STRING_LEN, DESCRIBE_CHANNEL_JSON_TEMPLATE, pSignalingClient->pChannelInfo->pChannelName);

    // Create the request info with the body
    CHK_STATUS(createRequestInfo(pUrl, pHttpBody, pSignalingClient->pChannelInfo->pRegion, pSignalingClient->pChannelInfo->pCertPath, NULL, NULL,
                                 SSL_CERTIFICATE_TYPE_NOT_SPECIFIED, pSignalingClient->pChannelInfo->pUserAgent,
                                 SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT, SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT,
                                 DEFAULT_LOW_SPEED_LIMIT, DEFAULT_LOW_SPEED_TIME_LIMIT, pSignalingClient->pAwsCredentials, &pRequestInfo));

    /* Initialize and generate HTTP request, then send it. */
    CHK(NULL != (pNetworkContext = (NetworkContext_t *)MEMALLOC( SIZEOF(NetworkContext_t))), STATUS_NOT_ENOUGH_MEMORY);

    CHK_STATUS(initNetworkContext( pNetworkContext ) );
    
    httpPackSendBuf(pRequestInfo, HTTP_REQUEST_VERB_POST_STRING, pHost, MAX_CONTROL_PLANE_URI_CHAR_LEN, (PCHAR)pNetworkContext->pHttpSendBuffer, MAX_HTTP_SEND_BUFFER_LEN, FALSE, NULL);

    for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
    {
        if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
        {
            break;
        }
        THREAD_SLEEP( CONNECTION_RETRY_INTERVAL_IN_MS*HUNDREDS_OF_NANOS_IN_A_MILLISECOND );
    }

    uBytesToSend = STRLEN((PCHAR)pNetworkContext->pHttpSendBuffer);
    CHK(uBytesToSend == networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend ), STATUS_SEND_DATA_FAILED);
    uBytesReceived = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
    CHK(uBytesReceived > 0, STATUS_RECV_DATA_FAILED);

    CHK_STATUS(httpParserStart(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )uBytesReceived, NULL));
    pResponseStr = httpParserGetHttpBodyLocation(pHttpRspCtx);
    resultLen = httpParserGetHttpBodyLength(pHttpRspCtx);
    uHttpStatusCode = httpParserGetHttpStatusCode(pHttpRspCtx);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
    /* Check HTTP results */
    CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);
    retStatus = httpApiRspDescribeChannel( ( const CHAR * )pResponseStr, resultLen, pSignalingClient );

CleanUp:
    CHK_LOG_ERR(retStatus);
    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
    }
    if(pHttpRspCtx != NULL)
    {
        retStatus =  httpParserDetroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }
    SAFE_MEMFREE(pHttpBody);
    SAFE_MEMFREE(pHost);
    SAFE_MEMFREE(pUrl);
    freeRequestInfo(&pRequestInfo);

    HTTP_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiGetChannelEndpoint( PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0, uBytesReceived = 0;

    /* Variables for HTTP request */
    PCHAR pUrl = NULL;
    PRequestInfo pRequestInfo = NULL;
    PCHAR pHttpBody = NULL;

    // temp interface.
    //PCHAR pAccessKey = pSignalingClient->pAwsCredentials->accessKeyId;
    //PCHAR pSecretKey = pSignalingClient->pAwsCredentials->secretKey;
    //PCHAR pToken = pSignalingClient->pAwsCredentials->sessionToken;
    //PCHAR pRegion = pSignalingClient->pChannelInfo->pRegion;     // The desired region of KVS service
    //PCHAR pService = KINESIS_VIDEO_SERVICE_NAME;    // KVS service name
    PCHAR pHost = NULL;
    //PCHAR pUserAgent = pChannelInfo->pUserAgent;//pSignalingClient->pChannelInfo->pCustomUserAgent;  // HTTP agent name
    // rsp
    UINT32 uHttpStatusCode = 0;
    HttpResponseContext* pHttpRspCtx = NULL;
    PCHAR pResponseStr;
    UINT32 resultLen;

    CHK(NULL != (pHost = (PCHAR)MEMALLOC(MAX_CONTROL_PLANE_URI_CHAR_LEN)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pUrl = (PCHAR) MEMALLOC(STRLEN(pSignalingClient->pChannelInfo->pControlPlaneUrl) +
                                        STRLEN(WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT) + 1)), STATUS_NOT_ENOUGH_MEMORY);

    // Create the API url
    STRCPY(pUrl, pSignalingClient->pChannelInfo->pControlPlaneUrl);
    STRCAT(pUrl, WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT);

    CHK(NULL != (pHttpBody = (PCHAR) MEMALLOC( SIZEOF( GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE ) + 
                                    STRLEN( pSignalingClient->channelDescription.channelArn ) + 
                                    STRLEN( WEBRTC_CHANNEL_PROTOCOL ) +
                                    STRLEN( getStringFromChannelRoleType( pChannelInfo->channelRoleType )) + 
                                    1 )), STATUS_NOT_ENOUGH_MEMORY);

    /* generate HTTP request body */
    SPRINTF( pHttpBody, GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE, pSignalingClient->channelDescription.channelArn, WEBRTC_CHANNEL_PROTOCOL, getStringFromChannelRoleType( pChannelInfo->channelRoleType ) );
    // Create the request info with the body
    CHK_STATUS(createRequestInfo(pUrl, pHttpBody, pSignalingClient->pChannelInfo->pRegion, pSignalingClient->pChannelInfo->pCertPath, NULL, NULL,
                                 SSL_CERTIFICATE_TYPE_NOT_SPECIFIED, pSignalingClient->pChannelInfo->pUserAgent,
                                 SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT, SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT,
                                 DEFAULT_LOW_SPEED_LIMIT, DEFAULT_LOW_SPEED_TIME_LIMIT, pSignalingClient->pAwsCredentials, &pRequestInfo));

    /* Initialize and generate HTTP request, then send it. */
    CHK(NULL != (pNetworkContext = (NetworkContext_t *) MEMALLOC( SIZEOF( NetworkContext_t ))), STATUS_NOT_ENOUGH_MEMORY);
    CHK_STATUS(initNetworkContext( pNetworkContext ) != STATUS_SUCCESS);

    httpPackSendBuf(pRequestInfo, HTTP_REQUEST_VERB_POST_STRING, pHost, MAX_CONTROL_PLANE_URI_CHAR_LEN, (PCHAR)pNetworkContext->pHttpSendBuffer, MAX_HTTP_SEND_BUFFER_LEN, FALSE, NULL);

    for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
    {
        if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
        {
            break;
        }
        THREAD_SLEEP( CONNECTION_RETRY_INTERVAL_IN_MS*HUNDREDS_OF_NANOS_IN_A_MILLISECOND );
    }

    uBytesToSend = STRLEN((PCHAR)pNetworkContext->pHttpSendBuffer);
    CHK(uBytesToSend == networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend ), STATUS_SEND_DATA_FAILED);
    uBytesReceived = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
    CHK(uBytesReceived > 0, STATUS_RECV_DATA_FAILED);

    CHK_STATUS(httpParserStart(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )uBytesReceived, NULL));
    pResponseStr = httpParserGetHttpBodyLocation(pHttpRspCtx);
    resultLen = httpParserGetHttpBodyLength(pHttpRspCtx);
    uHttpStatusCode = httpParserGetHttpStatusCode(pHttpRspCtx);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
    /* Check HTTP results */
    CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);

    retStatus = httpApiRspGetChannelEndpoint( ( const CHAR * )pResponseStr, resultLen, pSignalingClient );
    /* We got a success response here. */


CleanUp:
    CHK_LOG_ERR(retStatus);
    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
    }

    if(pHttpRspCtx != NULL)
    {
        retStatus =  httpParserDetroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }
    SAFE_MEMFREE(pHttpBody);
    SAFE_MEMFREE(pHost);
    SAFE_MEMFREE(pUrl);
    freeRequestInfo(&pRequestInfo);
    HTTP_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiGetIceConfig( PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0, uBytesReceived = 0;

    /* Variables for HTTP request */
    // http req.
    PCHAR pUrl = NULL;
    PRequestInfo pRequestInfo = NULL;
    PCHAR pHttpBody = NULL;

    // temp interface.
    //PCHAR pAccessKey = pSignalingClient->pAwsCredentials->accessKeyId;
    //PCHAR pSecretKey = pSignalingClient->pAwsCredentials->secretKey;
    //PCHAR pToken = pSignalingClient->pAwsCredentials->sessionToken;
    //PCHAR pRegion = pSignalingClient->pChannelInfo->pRegion;     // The desired region of KVS service
    //PCHAR pService = KINESIS_VIDEO_SERVICE_NAME;    // KVS service name
    PCHAR pHost = NULL;
    //PCHAR pUserAgent = pChannelInfo->pUserAgent;//pSignalingClient->pChannelInfo->pCustomUserAgent;  // HTTP agent name
    // rsp
    UINT32 uHttpStatusCode = 0;
    HttpResponseContext* pHttpRspCtx = NULL;
    PCHAR pResponseStr;
    UINT32 resultLen;

    CHK(NULL != (pHost = (PCHAR)MEMALLOC(MAX_CONTROL_PLANE_URI_CHAR_LEN)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pUrl = (PCHAR) MEMALLOC(STRLEN(pSignalingClient->channelEndpointHttps) +
                                        STRLEN(WEBRTC_API_GET_ICE_CONFIG) + 1)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pHttpBody = (PCHAR) MEMALLOC( SIZEOF( GET_ICE_CONFIG_PARAM_JSON_TEMPLATE ) + 
                                    STRLEN( pSignalingClient->channelDescription.channelArn ) + 
                                    STRLEN( pSignalingClient->clientInfo.signalingClientInfo.clientId ) +
                                    1 )), STATUS_NOT_ENOUGH_MEMORY);


    STRCPY(pUrl, pSignalingClient->channelEndpointHttps);
    STRCAT(pUrl, WEBRTC_API_GET_ICE_CONFIG);
    /* generate HTTP request body */
    SPRINTF( pHttpBody, GET_ICE_CONFIG_PARAM_JSON_TEMPLATE, pSignalingClient->channelDescription.channelArn, pSignalingClient->clientInfo.signalingClientInfo.clientId);

    // Create the request info with the body
    CHK_STATUS(createRequestInfo(pUrl, pHttpBody, pSignalingClient->pChannelInfo->pRegion, pSignalingClient->pChannelInfo->pCertPath, NULL, NULL,
                                 SSL_CERTIFICATE_TYPE_NOT_SPECIFIED, pSignalingClient->pChannelInfo->pUserAgent,
                                 SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT, SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT,
                                 DEFAULT_LOW_SPEED_LIMIT, DEFAULT_LOW_SPEED_TIME_LIMIT, pSignalingClient->pAwsCredentials, &pRequestInfo));

    /* Initialize and generate HTTP request, then send it. */
    CHK(NULL != (pNetworkContext = (NetworkContext_t *) MEMALLOC( SIZEOF( NetworkContext_t ))), STATUS_NOT_ENOUGH_MEMORY);

    CHK_STATUS(initNetworkContext( pNetworkContext ) != STATUS_SUCCESS);

    httpPackSendBuf(pRequestInfo, HTTP_REQUEST_VERB_POST_STRING, pHost, MAX_CONTROL_PLANE_URI_CHAR_LEN, (PCHAR)pNetworkContext->pHttpSendBuffer, MAX_HTTP_SEND_BUFFER_LEN, FALSE, NULL);

    for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
    {
        if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
        {
            break;
        }
        THREAD_SLEEP( CONNECTION_RETRY_INTERVAL_IN_MS*HUNDREDS_OF_NANOS_IN_A_MILLISECOND );
    }

    uBytesToSend = STRLEN((PCHAR)pNetworkContext->pHttpSendBuffer);
    CHK(uBytesToSend == networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend ), STATUS_SEND_DATA_FAILED);
    uBytesReceived = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
    CHK(uBytesReceived > 0, STATUS_RECV_DATA_FAILED);

    CHK_STATUS(httpParserStart(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )uBytesReceived, NULL));
    
    pResponseStr = httpParserGetHttpBodyLocation(pHttpRspCtx);
    resultLen = httpParserGetHttpBodyLength(pHttpRspCtx);
    uHttpStatusCode = httpParserGetHttpStatusCode(pHttpRspCtx);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
    /* Check HTTP results */
    CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);

    retStatus = httpApiRspGetIceConfig( ( const CHAR * )pResponseStr, resultLen, pSignalingClient );

    if(retStatus != STATUS_SUCCESS)
    {
        DLOGD("parse failed.");
    }

CleanUp:
    CHK_LOG_ERR(retStatus);
    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
    }
    if(pHttpRspCtx != NULL)
    {
        retStatus =  httpParserDetroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }
    SAFE_MEMFREE(pHttpBody);
    SAFE_MEMFREE(pHost);
    SAFE_MEMFREE(pUrl);
    freeRequestInfo(&pRequestInfo);
    HTTP_API_EXIT();
    return retStatus;
}


STATUS httpApiDeleteChannl(PSignalingClient pSignalingClient, UINT64 time)
{
    //STATUS retStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;//retStatus;
}
