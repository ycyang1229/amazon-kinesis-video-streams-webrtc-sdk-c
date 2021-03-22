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

static STATUS checkServiceParameter( webrtcServiceParameter_t * pServiceParameter )
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

/*-----------------------------------------------------------*/
/**
 * 
*/
STATUS httpApiCreateSignalingChannl( webrtcServiceParameter_t * pServiceParameter, webrtcChannelInfo_t * pChannelInfo)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHAR *p = NULL;

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
    do
    {
        if( checkServiceParameter( pServiceParameter ) != STATUS_SUCCESS )
        {
            retStatus = STATUS_INVALID_ARG;
            break;
        }
        else if( pChannelInfo == NULL )
        {
            retStatus = STATUS_INVALID_ARG;
            break;
        }else if(pChannelInfo->channelName[0] == '\0' && STRLEN(pChannelInfo->channelName) != 0){
            retStatus = STATUS_INVALID_ARG;
            break;
        }

        pHttpBody = ( CHAR * )MEMALLOC( sizeof( CREATE_CHANNEL_JSON_TEMPLATE ) + STRLEN( pChannelInfo->channelName ) +
                MAX_STRLEN_OF_UINT32 + 1 );
        if( pHttpBody == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        /* generate HTTP request body */
        uHttpBodyLen = sprintf( pHttpBody, CREATE_CHANNEL_JSON_TEMPLATE, pChannelInfo->channelName);

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
                                                    pServiceParameter->pHost, STRLEN( pServiceParameter->pHost ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pServiceParameter->pUserAgent, STRLEN( pServiceParameter->pUserAgent ) );
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

        retStatus = AwsSignerV4_sign( &signerContext, pServiceParameter->pSecretKey, STRLEN( pServiceParameter->pSecretKey ),
                                      pServiceParameter->pRegion, STRLEN( pServiceParameter->pRegion ),
                                      pServiceParameter->pService, STRLEN( pServiceParameter->pService ),
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
            if( ( retStatus = connectToServer( pNetworkContext, pServiceParameter->pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        p = ( CHAR * )( pNetworkContext->pHttpSendBuffer );
        p += sprintf( p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_CREATE_SIGNALING_CHANNEL );
        p += sprintf( p, "Host: %s\r\n", pServiceParameter->pHost );
        p += sprintf( p, "Accept: */*\r\n" );
        p += sprintf( p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                      AWS_SIG_V4_ALGORITHM, pServiceParameter->pAccessKey, AwsSignerV4_getScope( &signerContext ),
                      AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
        p += sprintf( p, "content-length: %u\r\n", (unsigned int) uHttpBodyLen );
        p += sprintf( p, "content-type: application/json\r\n" );
        p += sprintf( p, HDR_USER_AGENT ": %s\r\n", pServiceParameter->pUserAgent );
        p += sprintf( p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
        p += sprintf( p, "\r\n" );
        p += sprintf( p, "%s", pHttpBody );

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

        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

        /* Check HTTP results */
        if( uHttpStatusCode == 200 )
        {
            retStatus = parseCreateChannel( ( const CHAR * )http_get_http_body_location(pHttpRspCtx), http_get_http_body_length(pHttpRspCtx), pChannelInfo->channelArn, WEBRTC_CHANNEL_ARN_LEN_MAX );
            /* We got a success response here. */
        }
        else if( uHttpStatusCode == 400 )
        {
            retStatus = STATUS_HTTP_REST_EXCEPTION_ERROR;
            break;
        }
        else
        {
            retStatus = STATUS_HTTP_REST_UNKNOWN_ERROR;
            break;
        }
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

    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiDescribeSignalingChannel( webrtcServiceParameter_t * pServiceParameter,
                        webrtcChannelInfo_t * pChannelInfo)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHAR *p = NULL;
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

    UINT32 uHttpStatusCode = 0;
    http_response_context_t* pHttpRspCtx = NULL;

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
            bUseIotCert = TRUE;
        }

        pHttpBody = (CHAR *) MEMALLOC( sizeof( DESCRIBE_CHANNEL_JSON_TEMPLATE ) + STRLEN( pChannelInfo->channelName ) + 1 );
        if( pHttpBody == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        /* generate HTTP request body */
        uHttpBodyLen = sprintf( pHttpBody, DESCRIBE_CHANNEL_JSON_TEMPLATE, pChannelInfo->channelName );

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
                                                      WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL, sizeof( WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL ) - 1,
                                                      pHttpParameter, STRLEN( pHttpParameter ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_HOST, sizeof( HDR_HOST ) - 1,
                                                    pServiceParameter->pHost, STRLEN( pServiceParameter->pHost ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pServiceParameter->pUserAgent, STRLEN( pServiceParameter->pUserAgent ) );
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
                                                        pServiceParameter->pToken, STRLEN( pServiceParameter->pToken ) );
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

        retStatus = AwsSignerV4_sign( &signerContext, pServiceParameter->pSecretKey, STRLEN( pServiceParameter->pSecretKey ),
                                      pServiceParameter->pRegion, STRLEN( pServiceParameter->pRegion ),
                                      pServiceParameter->pService, STRLEN( pServiceParameter->pService ),
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
            if( ( retStatus = connectToServer( pNetworkContext, pServiceParameter->pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
        p += sprintf(p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_DESCRIBE_SIGNALING_CHANNEL);
        p += sprintf(p, "Host: %s\r\n", pServiceParameter->pHost);
        p += sprintf(p, "Accept: */*\r\n");
        p += sprintf(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                     AWS_SIG_V4_ALGORITHM, pServiceParameter->pAccessKey, AwsSignerV4_getScope( &signerContext ),
                     AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
        p += sprintf(p, "content-length: %u\r\n", (unsigned int) uHttpBodyLen );
        p += sprintf(p, "content-type: application/json\r\n" );
        p += sprintf(p, HDR_USER_AGENT ": %s\r\n", pServiceParameter->pUserAgent );
        p += sprintf(p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
        if( bUseIotCert )
        {
            p += sprintf(p, HDR_X_AMZ_SECURITY_TOKEN ": %s\r\n", pServiceParameter->pToken );
        }
        p += sprintf(p, "\r\n" );
        p += sprintf(p, "%s", pHttpBody );

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

        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

        /* Check HTTP results */
        if( uHttpStatusCode == 200 )
        {
            retStatus = parseDescribeChannel( ( const CHAR * )http_get_http_body_location(pHttpRspCtx), http_get_http_body_length(pHttpRspCtx), pChannelInfo );

            /* We got a success response here. */
        }
        else if( uHttpStatusCode == 404 )
        {
            retStatus = STATUS_HTTP_RES_NOT_FOUND_ERROR;
            break;
        }
        else
        {
            DLOGE("Unable to describe stream:\r\n%.*s\r\n", (int)http_get_http_body_length(pHttpRspCtx), http_get_http_body_location(pHttpRspCtx));
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

    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiGetChannelEndpoint( webrtcServiceParameter_t * pServiceParameter, webrtcChannelInfo_t * pChannelInfo)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHAR *p = NULL;
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
            bUseIotCert = TRUE;
        }

        pHttpBody = (CHAR *) MEMALLOC( sizeof( GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE ) + 
                                        STRLEN( pChannelInfo->channelArn ) + 
                                        STRLEN( WEBRTC_CHANNEL_PROTOCOL ) +
                                        STRLEN( webrtc_getStringFromChannelRoleType( pChannelInfo->channelRole )) + 
                                        1 );
        if( pHttpBody == NULL )
        {
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
            break;
        }

        /* generate HTTP request body */
        uHttpBodyLen = sprintf( pHttpBody, GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE, pChannelInfo->channelArn, WEBRTC_CHANNEL_PROTOCOL, webrtc_getStringFromChannelRoleType( pChannelInfo->channelRole ) );

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
                                                    pServiceParameter->pHost, STRLEN( pServiceParameter->pHost ) );
        if( retStatus != STATUS_SUCCESS )
        {
            break;
        }

        retStatus = AwsSignerV4_addCanonicalHeader( &signerContext, HDR_USER_AGENT, sizeof( HDR_USER_AGENT ) - 1,
                                                    pServiceParameter->pUserAgent, STRLEN( pServiceParameter->pUserAgent ) );
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
                                                        pServiceParameter->pToken, STRLEN( pServiceParameter->pToken ) );
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

        retStatus = AwsSignerV4_sign( &signerContext, pServiceParameter->pSecretKey, STRLEN( pServiceParameter->pSecretKey ),
                                      pServiceParameter->pRegion, STRLEN( pServiceParameter->pRegion ),
                                      pServiceParameter->pService, STRLEN( pServiceParameter->pService ),
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
            if( ( retStatus = connectToServer( pNetworkContext, pServiceParameter->pHost, KVS_ENDPOINT_TCP_PORT ) ) == STATUS_SUCCESS )
            {
                break;
            }
            sleepInMs( CONNECTION_RETRY_INTERVAL_IN_MS );
        }

        p = (CHAR *)(pNetworkContext->pHttpSendBuffer);
        p += sprintf(p, "%s %s HTTP/1.1\r\n", HTTP_METHOD_POST, WEBRTC_API_GET_SIGNALING_CHANNEL_ENDPOINT);
        p += sprintf(p, "Host: %s\r\n", pServiceParameter->pHost);
        p += sprintf(p, "Accept: */*\r\n");
        p += sprintf(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                     AWS_SIG_V4_ALGORITHM, pServiceParameter->pAccessKey, AwsSignerV4_getScope( &signerContext ),
                     AwsSignerV4_getSignedHeader( &signerContext ), AwsSignerV4_getHmacEncoded( &signerContext ) );
        p += sprintf(p, "content-length: %u\r\n", (unsigned int) uHttpBodyLen );
        p += sprintf(p, "content-type: application/json\r\n" );
        p += sprintf(p, HDR_USER_AGENT ": %s\r\n", pServiceParameter->pUserAgent );
        p += sprintf(p, HDR_X_AMZ_DATE ": %s\r\n", pXAmzDate );
        if( bUseIotCert )
        {
            p += sprintf(p, HDR_X_AMZ_SECURITY_TOKEN ": %s\r\n", pServiceParameter->pToken );
        }
        p += sprintf(p, "\r\n" );
        p += sprintf(p, "%s", pHttpBody );

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

        uHttpStatusCode = http_get_http_status_code(pHttpRspCtx);

        /* Check HTTP results */
        if( uHttpStatusCode == 200 )
        {
            retStatus = parseGetEndPoint( ( const CHAR * )http_get_http_body_location(pHttpRspCtx), http_get_http_body_length(pHttpRspCtx), pChannelInfo );

            /* We got a success response here. */
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
    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS httpApiGetIceConfig( webrtcServiceParameter_t * pServiceParameter, webrtcChannelInfo_t * pChannelInfo)
{
    STATUS retStatus = STATUS_SUCCESS;
    #if 0
    char *method = "POST";
    char *uri = "/v1/get-ice-server-config";
    char *parameter = "";

    char *p;
    int n;
    char pHttpBody[ MAX_HTTP_BODY_LEN ];

    /* Variables for AWS signer V4 */
    AwsSignerV4Context_t signerContext = { 0 };
    char pXAmzDate[ SIGNATURE_DATE_TIME_STRING_LEN ];

    NetworkContext_t networkContext;

    snprintf( pHttpBody, MAX_HTTP_BODY_LEN, "{\n"
                                            "\t\"ChannelARN\": \"%s\",\n"
                                            "\t\"ClientId\": \"%s\",\n"
                                            "\t\"Service\": \"TURN\"\n"
                                            "}", pChannelArn, pClientId );

    getTimeInIso8601( pXAmzDate, sizeof( pXAmzDate ) );

    AwsSignerV4_initContext( &signerContext, 2048 );
    AwsSignerV4_initCanonicalRequest( &signerContext, method, strlen(method), uri, strlen(uri), parameter, strlen(parameter) );
    AwsSignerV4_addCanonicalHeader( &signerContext, "host", strlen("host"), pHost, strlen( pHost ) );
    AwsSignerV4_addCanonicalHeader( &signerContext, "user-agent", strlen("user-agent"), pUserAgent, strlen( pUserAgent ) );
    AwsSignerV4_addCanonicalHeader( &signerContext, "x-amz-date", strlen("x-amz-date"), pXAmzDate, strlen( pXAmzDate ) );
    AwsSignerV4_addCanonicalBody( &signerContext, pHttpBody, strlen( pHttpBody ) );
    AwsSignerV4_sign( &signerContext, pSecretKey, strlen(pSecretKey), pRegion, strlen(pRegion), pService, strlen(pService), pXAmzDate, strlen(pXAmzDate) );

    initNetworkContext( &networkContext );

    connectToServer( &networkContext, pHost, "443" );

    p = networkContext.pHttpSendBuffer;
    p += sprintf(p, "%s %s HTTP/1.1\r\n", method, uri);
    p += sprintf(p, "Host: %s\r\n", pHost);
    p += sprintf(p, "Accept: */*\r\n");
    p += sprintf(p, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
                 AWS_SIG_V4_ALGORITHM,
                 pAccessKey,
                 AwsSignerV4_getScope( &signerContext ),
                 "host;user-agent;x-amz-date",
                 AwsSignerV4_getHmacEncoded( &signerContext )
    );
    p += sprintf(p, "content-length: %lu\r\n", strlen(pHttpBody));
    p += sprintf(p, "content-type: application/json\r\n");
    p += sprintf(p, "user-agent: %s\r\n", pUserAgent);
    p += sprintf(p, "X-Amz-Date: %s\r\n", pXAmzDate);
    p += sprintf(p, "\r\n");
    p += sprintf(p, "%s", pHttpBody);

    AwsSignerV4_terminateContext( &signerContext );

    printf("sendbuf:\n%s\n", networkContext.pHttpSendBuffer);

    n = mbedtls_ssl_write( &(networkContext.ssl), networkContext.pHttpSendBuffer, p - (char *) networkContext.pHttpSendBuffer );
    if ( n > 0 )
    {
        n = mbedtls_ssl_read( &(networkContext.ssl), networkContext.pHttpRecvBuffer, networkContext.uHttpRecvBufferLen );
        if ( n > 0 )
        {
            printf("httpRecvBuf:\n%s\n", networkContext.pHttpRecvBuffer);
        }
        else
        {
            printf("fail to connect\n");
        }
    }

    disconnectFromServer( &networkContext );

    terminateNetworkContext( &networkContext );
    #endif
    return retStatus;
}


STATUS httpApiDeleteChannel( webrtcServiceParameter_t * pServiceParameter, webrtcChannelInfo_t * pChannelInfo)
{
    STATUS retStatus = STATUS_SUCCESS;
    return retStatus;
}
