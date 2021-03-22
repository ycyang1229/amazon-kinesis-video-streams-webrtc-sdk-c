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


#define HTTP_API_ENTER() DLOGD("enter")
#define HTTP_API_EXIT() DLOGD("exit")


/*-----------------------------------------------------------*/

#define KVS_ENDPOINT_TCP_PORT   "443"
#define HTTP_METHOD_POST        "POST"
#define HTTP_METHOD_GET        "GET"

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

#define AWS_SIGNER_V4_BUFFER_SIZE           ( 4096 )
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

#define MAX_X_AMZN_PRODUCER_START_TIMESTAMP_LEN (32)

#define MIN_FRAGMENT_LENGTH     ( 6 )

/*-----------------------------------------------------------*/

#define JSON_KEY_EVENT_TYPE             "EventType"
#define JSON_KEY_FRAGMENT_TIMECODE      "FragmentTimecode"
#define JSON_KEY_ERROR_ID               "ErrorId"

#define EVENT_TYPE_BUFFERING    "\"BUFFERING\""
#define EVENT_TYPE_RECEIVED     "\"RECEIVED\""
#define EVENT_TYPE_PERSISTED    "\"PERSISTED\""
#define EVENT_TYPE_ERROR        "\"ERROR\""
#define EVENT_TYPE_IDLE         "\"IDLE\""

typedef enum {
    EVENT_UNKNOWN = 0,
    EVENT_BUFFERING,
    EVENT_RECEIVED,
    EVENT_PERSISTED,
    EVENT_ERROR,
    EVENT_IDLE
} EVENT_TYPE;

typedef struct
{
    EVENT_TYPE eventType;
    UINT64 uFragmentTimecode;
    INT32 uErrorId;
} FragmentAck_t;

/*-----------------------------------------------------------*/

/*-----------------------------------------------------------*/
/**
 * 
*/
STATUS httpApiCreateSignalingChannl(PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;
    PCHAR p = NULL;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0;

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext = { 0 };
    CHAR pXAmzDate[ SIGNATURE_DATE_TIME_STRING_LEN ];

    /* Variables for HTTP request */
    CHAR *pHttpParameter = "";
    CHAR *pHttpBody = NULL;
    SIZE_T uHttpBodyLen = 0;

    UINT32 uHttpStatusCode = 0;
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
    DLOGD("preparing the call");
    do
    {
        CHK((pChannelInfo != NULL && pChannelInfo->pChannelName[0] != '\0'), STATUS_INVALID_ARG);

        pHttpBody = ( CHAR * )MEMALLOC( sizeof( CREATE_CHANNEL_JSON_TEMPLATE ) + STRLEN( pChannelInfo->pChannelName ) +
                MAX_STRLEN_OF_UINT32 + 1 );
        if( pHttpBody == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        /* generate HTTP request body */
        uHttpBodyLen = SPRINTF( pHttpBody, CREATE_CHANNEL_JSON_TEMPLATE, pChannelInfo->pChannelName);

        /* generate UTC time in x-amz-date formate */
        retStatus = getTimeInIso8601( pXAmzDate, sizeof( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        /* Create canonical request and sign the request. */
        retStatus = AwsSignerV4_initContext( &signerContext, AWS_SIGNER_V4_BUFFER_SIZE );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_initCanonicalRequest( &signerContext, HTTP_METHOD_POST, sizeof( HTTP_METHOD_POST ) - 1,
                                                      WEBRTC_API_CREATE_SIGNALING_CHANNEL, sizeof( WEBRTC_API_CREATE_SIGNALING_CHANNEL ) - 1,
                                                      pHttpParameter, STRLEN( pHttpParameter ) );
        if( retStatus  != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_HOST, sizeof( HDR_HOST ) - 1,
                                                    pHost, STRLEN( pHost ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pUserAgent, STRLEN( pUserAgent ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_DATE, sizeof( HDR_X_AMZ_DATE ) - 1,
                                                    pXAmzDate, STRLEN( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalBody( &signerContext, ( uint8_t * )pHttpBody, uHttpBodyLen);
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_sign( &signerContext, pSecretKey, STRLEN( pSecretKey ),
                                      pRegion, STRLEN( pRegion ),
                                      pService, STRLEN( pService ),
                                      pXAmzDate, STRLEN( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        /* Initialize and generate HTTP request, then send it. */
        pNetworkContext = ( NetworkContext_t * ) MEMALLOC( sizeof( NetworkContext_t ) );
        if( pNetworkContext == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        if( ( retStatus = initNetworkContext( pNetworkContext ) ) != STATUS_SUCCESS )
        {
            break;
        }

        for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
        {
            if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        p = ( CHAR * )( pNetworkContext->pHttpSendBuffer );
        p += SPRINTF( p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_CREATE_SIGNALING_CHANNEL );
        p += SPRINTF( p, "Host: %s\r\n", pHost );
        p += SPRINTF( p, "Accept: */*\r\n" );
        p += SPRINTF( p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                      AWS_SIG_V4_ALGORITHM, pAccessKey, AwsSignerV4_getScope( &signerContext ),
                      AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
        p += SPRINTF( p, "content-length: %u\r\n", (UINT32) uHttpBodyLen );
        p += SPRINTF( p, "content-type: application/json\r\n" );
        p += SPRINTF( p, HDR_USER_AGENT ": %s\r\n", pUserAgent );
        p += SPRINTF( p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
        p += SPRINTF( p, "\r\n" );
        p += SPRINTF( p, "%s", pHttpBody );

        AwsSignerV4_terminateContext(&signerContext);

        uBytesToSend = p - ( CHAR * )pNetworkContext->pHttpSendBuffer;
        retStatus = networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend );
        if( retStatus != uBytesToSend )
        {
            retStatus = STATUS_SEND_DATA_FAILED;
            break;
        }

        retStatus = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
        if( retStatus < STATUS_SUCCESS )
        {
            break;
        }

        retStatus = http_parse_start(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )retStatus, NULL);
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        PCHAR pResponseStr = http_get_http_body_location(pHttpRspCtx);
        UINT32 resultLen = http_get_http_body_length(pHttpRspCtx);
        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

        ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
        /* Check HTTP results */
        CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);
        DLOGD("receive 200 response.");
        retStatus = httpApiRspCreateChannel( ( const CHAR * )pResponseStr, resultLen, pChannelInfo );
        /* We got a success response here. */
    } while ( 0 );

    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
        AwsSignerV4_terminateContext(&signerContext);
    }
    if(pHttpRspCtx != NULL)
    {
        retStatus =  http_parse_detroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }
    if( pHttpBody != NULL )
    {
        MEMFREE( pHttpBody );
    }
CleanUp:

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
STATUS httpApiDescribeSignalingChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;

    PCHAR p = NULL;
    BOOL bUseIotCert = FALSE;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0;

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext;
    CHAR pXAmzDate[SIGNATURE_DATE_TIME_STRING_LEN];

    /* Variables for HTTP request */
    PCHAR pHttpParameter = "";
    PCHAR pHttpBody = NULL;
    UINT32 uHttpBodyLen = 0;

    UINT32 uHttpStatusCode = 0;
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

    do
    {
        CHK((pChannelInfo != NULL && pChannelInfo->pChannelName[0] != '\0'), STATUS_INVALID_ARG);
        CHK(NULL != (pHttpBody = (CHAR *) MEMALLOC( sizeof( DESCRIBE_CHANNEL_JSON_TEMPLATE ) + STRLEN( pChannelInfo->pChannelName ) + 1 )), STATUS_NOT_ENOUGH_MEMORY);

        /* generate HTTP request body */
        uHttpBodyLen = SPRINTF( pHttpBody, DESCRIBE_CHANNEL_JSON_TEMPLATE, pChannelInfo->pChannelName );

        /* generate UTC time in x-amz-date formate */
        retStatus = getTimeInIso8601( pXAmzDate, sizeof( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        /* Create canonical request and sign the request. */
        retStatus = AwsSignerV4_initContext( &signerContext, AWS_SIGNER_V4_BUFFER_SIZE );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_initCanonicalRequest( &signerContext, HTTP_METHOD_POST, sizeof( HTTP_METHOD_POST ) - 1,
                                                      WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL,
                                                      sizeof( WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL ) - 1,
                                                      pHttpParameter, STRLEN( pHttpParameter ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_HOST, sizeof( HDR_HOST ) - 1,
                                                    pHost, STRLEN( pHost ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pUserAgent, STRLEN( pUserAgent ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_DATE, sizeof( HDR_X_AMZ_DATE ) - 1,
                                                    pXAmzDate, STRLEN( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        if( bUseIotCert )
        {
            retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_SECURITY_TOKEN, sizeof( HDR_X_AMZ_SECURITY_TOKEN ) - 1,
                                                        pToken, STRLEN( pToken ) );
            if( retStatus != STATUS_SUCCESS )
            {
                break;
            }
        }

        retStatus = AwsSignerV4_addCanonicalBody( &signerContext, ( uint8_t * )pHttpBody, uHttpBodyLen );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_sign( &signerContext, pSecretKey, STRLEN( pSecretKey ),
                                      pRegion, STRLEN( pRegion ),
                                      pService, STRLEN( pService ),
                                      pXAmzDate, STRLEN( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        /* Initialize and generate HTTP request, then send it. */

        CHK(NULL != (pNetworkContext = (NetworkContext_t *) MEMALLOC( sizeof( NetworkContext_t ))), STATUS_NOT_ENOUGH_MEMORY);

        if( ( retStatus = initNetworkContext( pNetworkContext ) ) != STATUS_SUCCESS )
        {
            break;
        }

        for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
        {
            if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
        p += SPRINTF(p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL);
        p += SPRINTF(p, "Host: %s\r\n", pHost);
        p += SPRINTF(p, "Accept: */*\r\n");
        p += SPRINTF(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                     AWS_SIG_V4_ALGORITHM, pAccessKey, AwsSignerV4_getScope( &signerContext ),
                     AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
        p += SPRINTF(p, "content-length: %u\r\n", (UINT32) uHttpBodyLen );
        p += SPRINTF(p, "content-type: application/json\r\n" );
        p += SPRINTF(p, HDR_USER_AGENT ": %s\r\n", pUserAgent );
        p += SPRINTF(p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
        if( bUseIotCert )
        {
            p += SPRINTF(p, HDR_X_AMZ_SECURITY_TOKEN ": %s\r\n", pToken );
        }
        p += SPRINTF(p, "\r\n" );
        p += SPRINTF(p, "%s", pHttpBody );

        AwsSignerV4_terminateContext(&signerContext);

        uBytesToSend = p - ( CHAR * )pNetworkContext->pHttpSendBuffer;
        retStatus = networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend );
        if( retStatus != uBytesToSend )
        {
            retStatus = STATUS_SEND_DATA_FAILED;
            break;
        }
    
        retStatus = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
        if( retStatus < STATUS_SUCCESS )
        {
            break;
        }
        
        CHK_STATUS(http_parse_start(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )retStatus, NULL));


        PCHAR pResponseStr = http_get_http_body_location(pHttpRspCtx);
        UINT32 resultLen = http_get_http_body_length(pHttpRspCtx);
        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

        ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
        /* Check HTTP results */
        CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);
        DLOGD("receive 200 response.");
        retStatus = httpApiRspDescribeChannel( ( const CHAR * )pResponseStr, resultLen, pSignalingClient );

    } while ( 0 );

CleanUp:

    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
        AwsSignerV4_terminateContext(&signerContext);
    }
    if(pHttpRspCtx != NULL)
    {
        retStatus =  http_parse_detroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }

    SAFE_MEMFREE(pHttpBody);
    SAFE_MEMFREE(pHost);

    HTTP_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiGetChannelEndpoint( PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;
    PCHAR p = NULL;
    BOOL bUseIotCert = FALSE;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0;

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext;
    CHAR pXAmzDate[SIGNATURE_DATE_TIME_STRING_LEN];

    /* Variables for HTTP request */
    CHAR *pHttpParameter = "";
    CHAR *pHttpBody = NULL;
    UINT32 uHttpBodyLen = 0;
    http_response_context_t* pHttpRspCtx = NULL;
    UINT32 uHttpStatusCode = 0;

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
    DLOGD("preparing the call");
    do
    {
        CHK((pChannelInfo != NULL && pChannelInfo->pChannelName[0] != '\0'), STATUS_INVALID_ARG);

        pHttpBody = (CHAR *) MEMALLOC( sizeof( GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE ) + 
                                        STRLEN( pSignalingClient->channelDescription.channelArn ) + 
                                        STRLEN( WEBRTC_CHANNEL_PROTOCOL ) +
                                        STRLEN( getStringFromChannelRoleType( pChannelInfo->channelRoleType )) + 
                                        1 );
        if( pHttpBody == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        /* generate HTTP request body */
        uHttpBodyLen = SPRINTF( pHttpBody, GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE, pSignalingClient->channelDescription.channelArn, WEBRTC_CHANNEL_PROTOCOL, getStringFromChannelRoleType( pChannelInfo->channelRoleType ) );

        /* generate UTC time in x-amz-date formate */
        retStatus = getTimeInIso8601( pXAmzDate, sizeof( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        /* Create canonical request and sign the request. */
        retStatus = AwsSignerV4_initContext( &signerContext, AWS_SIGNER_V4_BUFFER_SIZE );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_initCanonicalRequest( &signerContext, HTTP_METHOD_POST, sizeof( HTTP_METHOD_POST ) - 1,
                                                      WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT, sizeof( WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT ) - 1,
                                                      pHttpParameter, STRLEN( pHttpParameter ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_HOST, sizeof( HDR_HOST ) - 1,
                                                    pHost, STRLEN( pHost ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pUserAgent, STRLEN( pUserAgent ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_DATE, sizeof( HDR_X_AMZ_DATE ) - 1,
                                                    pXAmzDate, STRLEN( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        if( bUseIotCert )
        {
            retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_SECURITY_TOKEN, sizeof( HDR_X_AMZ_SECURITY_TOKEN ) - 1,
                                                        pToken, STRLEN( pToken ) );
            if( retStatus != STATUS_SUCCESS )
            {
                break;
            }
        }

        retStatus = AwsSignerV4_addCanonicalBody( &signerContext, ( uint8_t * )pHttpBody, uHttpBodyLen );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_sign( &signerContext, pSecretKey, STRLEN( pSecretKey ),
                                      pRegion, STRLEN( pRegion ),
                                      pService, STRLEN( pService ),
                                      pXAmzDate, STRLEN( pXAmzDate ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        /* Initialize and generate HTTP request, then send it. */
        pNetworkContext = ( NetworkContext_t * ) MEMALLOC( sizeof( NetworkContext_t ) );
        if( pNetworkContext == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        if( ( retStatus = initNetworkContext( pNetworkContext ) ) != STATUS_SUCCESS )
        {
            break;
        }

        for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
        {
            if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
        p += SPRINTF(p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT);
        p += SPRINTF(p, "Host: %s\r\n", pHost);
        p += SPRINTF(p, "Accept: */*\r\n");
        p += SPRINTF(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                     AWS_SIG_V4_ALGORITHM, pAccessKey, AwsSignerV4_getScope( &signerContext ),
                     AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
        p += SPRINTF(p, "content-length: %u\r\n", (UINT32) uHttpBodyLen );
        p += SPRINTF(p, "content-type: application/json\r\n" );
        p += SPRINTF(p, HDR_USER_AGENT ": %s\r\n", pUserAgent );
        p += SPRINTF(p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
        if( bUseIotCert )
        {
            p += SPRINTF(p, HDR_X_AMZ_SECURITY_TOKEN ": %s\r\n", pToken );
        }
        p += SPRINTF(p, "\r\n" );
        p += SPRINTF(p, "%s", pHttpBody );

        AwsSignerV4_terminateContext(&signerContext);

        uBytesToSend = p - ( CHAR * )pNetworkContext->pHttpSendBuffer;
        retStatus = networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend );
        if( retStatus != uBytesToSend )
        {
            retStatus = STATUS_SEND_DATA_FAILED;
            break;
        }

        retStatus = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
        if( retStatus < STATUS_SUCCESS )
        {
            break;
        }

        retStatus = http_parse_start(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )retStatus, NULL);
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        PCHAR pResponseStr = http_get_http_body_location(pHttpRspCtx);
        UINT32 resultLen = http_get_http_body_length(pHttpRspCtx);
        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

        ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
        /* Check HTTP results */
        CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);
        DLOGD("receive 200 response.");
        retStatus = httpApiRspGetChannelEndpoint( ( const CHAR * )pResponseStr, resultLen, pChannelInfo );
        /* We got a success response here. */
        
    } while ( 0 );

    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
        AwsSignerV4_terminateContext(&signerContext);
    }

    if( pHttpBody != NULL )
    {
        MEMFREE( pHttpBody );
    }
    if(pHttpRspCtx != NULL)
    {
        retStatus =  http_parse_detroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }

CleanUp:

    HTTP_API_EXIT();
    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiGetIceConfig( PSignalingClient pSignalingClient, UINT64 time)
{
    HTTP_API_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo = pSignalingClient->pChannelInfo;
    PCHAR p = NULL;
    BOOL bUseIotCert = FALSE;

    /* Variables for network connection */
    NetworkContext_t *pNetworkContext = NULL;
    SIZE_T uConnectionRetryCnt = 0;
    UINT32 uBytesToSend = 0;

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext;
    CHAR pXAmzDate[SIGNATURE_DATE_TIME_STRING_LEN];

    /* Variables for HTTP request */
    CHAR *pHttpParameter = "";
    CHAR *pHttpBody = NULL;
    UINT32 uHttpBodyLen = 0;
    http_response_context_t* pHttpRspCtx = NULL;
    UINT32 uHttpStatusCode = 0;


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
    DLOGD("preparing the call");
    pHttpBody = (CHAR *) MEMALLOC( sizeof( GET_ICE_CONFIG_PARAM_JSON_TEMPLATE ) + 
                                    STRLEN( pSignalingClient->channelDescription.channelArn ) + 
                                    STRLEN( pSignalingClient->clientInfo.signalingClientInfo.clientId ) +
                                    1 );
    if( pHttpBody == NULL )
    {
        retStatus = STATUS_NOT_ENOUGH_MEMORY;
    }

    /* generate HTTP request body */
    uHttpBodyLen = SPRINTF( pHttpBody, GET_ICE_CONFIG_PARAM_JSON_TEMPLATE, pSignalingClient->channelDescription.channelArn, pSignalingClient->clientInfo.signalingClientInfo.clientId);

    /* generate UTC time in x-amz-date formate */
    retStatus = getTimeInIso8601( pXAmzDate, sizeof( pXAmzDate ) );
    
    retStatus = AwsSignerV4_initContext( &signerContext, AWS_SIGNER_V4_BUFFER_SIZE );
    retStatus = AwsSignerV4_initCanonicalRequest( &signerContext, HTTP_METHOD_POST, sizeof( HTTP_METHOD_POST ) - 1,
                                                    WEBRTC_API_GET_ICE_CONFIG, sizeof( WEBRTC_API_GET_ICE_CONFIG ) - 1,
                                                    pHttpParameter, STRLEN( pHttpParameter ) );


    retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_HOST, sizeof( HDR_HOST ) - 1,
                                                    pHost, STRLEN( pHost ) );

    retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pUserAgent, STRLEN( pUserAgent ) );

    retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_X_AMZ_DATE, sizeof( HDR_X_AMZ_DATE ) - 1,
                                                    pXAmzDate, STRLEN( pXAmzDate ) );

    retStatus = AwsSignerV4_addCanonicalBody( &signerContext, ( uint8_t * )pHttpBody, uHttpBodyLen );

    retStatus = AwsSignerV4_sign( &signerContext, pSecretKey, STRLEN( pSecretKey ),
                                      pRegion, STRLEN( pRegion ),
                                      pService, STRLEN( pService ),
                                      pXAmzDate, STRLEN( pXAmzDate ) );

    /* Initialize and generate HTTP request, then send it. */
    pNetworkContext = ( NetworkContext_t * ) MEMALLOC( sizeof( NetworkContext_t ) );
    if( pNetworkContext == NULL )
    {
        retStatus = STATUS_NOT_ENOUGH_MEMORY;

    }

    if( ( retStatus = initNetworkContext( pNetworkContext ) ) != STATUS_SUCCESS )
    {

    }

    for( uConnectionRetryCnt = 0; uConnectionRetryCnt < MAX_CONNECTION_RETRY; uConnectionRetryCnt++ )
    {
        if( ( retStatus = connectToServer( pNetworkContext, pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
        {
            break;
        }
        sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
    }

    p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
    p += SPRINTF(p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_GET_ICE_CONFIG);
    p += SPRINTF(p, "Host: %s\r\n", pHost);
    p += SPRINTF(p, "Accept: */*\r\n");
    p += SPRINTF(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                     AWS_SIG_V4_ALGORITHM, pAccessKey, AwsSignerV4_getScope( &signerContext ),
                     AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
    p += SPRINTF(p, "content-length: %u\r\n", (UINT32) uHttpBodyLen );
    p += SPRINTF(p, "content-type: application/json\r\n" );
    p += SPRINTF(p, HDR_USER_AGENT ": %s\r\n", pUserAgent );
    p += SPRINTF(p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
    p += SPRINTF(p, "\r\n");
    p += SPRINTF(p, "%s", pHttpBody);

    AwsSignerV4_terminateContext( &signerContext );

    uBytesToSend = p - ( CHAR * )pNetworkContext->pHttpSendBuffer;
    retStatus = networkSend( pNetworkContext, pNetworkContext->pHttpSendBuffer, uBytesToSend );
    if( retStatus != uBytesToSend )
    {
        retStatus = STATUS_SEND_DATA_FAILED;
    }
    retStatus = networkRecv( pNetworkContext, pNetworkContext->pHttpRecvBuffer, pNetworkContext->uHttpRecvBufferLen );
    

    retStatus = http_parse_start(&pHttpRspCtx, ( CHAR * )pNetworkContext->pHttpRecvBuffer, ( UINT32 )retStatus, NULL);
    

    PCHAR pResponseStr = http_get_http_body_location(pHttpRspCtx);
    UINT32 resultLen = http_get_http_body_length(pHttpRspCtx);
    uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) uHttpStatusCode);
    /* Check HTTP results */
    CHK((SERVICE_CALL_RESULT) ATOMIC_LOAD(&pSignalingClient->result) == SERVICE_CALL_RESULT_OK && resultLen != 0 && pResponseStr != NULL, retStatus);
    DLOGD("receive 200 response.");
    retStatus = httpApiRspGetIceConfig( ( const CHAR * )pResponseStr, resultLen, pSignalingClient );

    if(retStatus != STATUS_SUCCESS)
    {
        DLOGD("parse failed.");
    }
    if( pNetworkContext != NULL )
    {
        disconnectFromServer( pNetworkContext );
        terminateNetworkContext(pNetworkContext);
        MEMFREE( pNetworkContext );
        AwsSignerV4_terminateContext(&signerContext);
    }

    if( pHttpBody != NULL )
    {
        MEMFREE( pHttpBody );
    }
    if(pHttpRspCtx != NULL)
    {
        retStatus =  http_parse_detroy(pHttpRspCtx);
        if( retStatus != STATUS_SUCCESS )
        {
            printf("destroying http parset failed. \n");
        }
    }

CleanUp:

    HTTP_API_EXIT();
    return retStatus;
}


STATUS httpApiDeleteSignalingChannl(PSignalingClient pSignalingClient, UINT64 time)
{
    STATUS retStatus = STATUS_SUCCESS;
    return retStatus;
}
