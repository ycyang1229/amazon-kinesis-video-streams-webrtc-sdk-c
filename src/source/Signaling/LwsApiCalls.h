/*******************************************
Signaling LibWebSocket based API calls include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_LWS_API_CALLS__
#define __KINESIS_VIDEO_WEBRTC_LWS_API_CALLS__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Timeout values
#define SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT (2 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define SIGNALING_SERVICE_API_CALL_TIMEOUT_IN_SECONDS                                                                                                \
    ((SIGNALING_SERVICE_API_CALL_CONNECTION_TIMEOUT + SIGNALING_SERVICE_API_CALL_COMPLETION_TIMEOUT) / HUNDREDS_OF_NANOS_IN_A_SECOND)
#define SIGNALING_SERVICE_TCP_KEEPALIVE_IN_SECONDS                3
#define SIGNALING_SERVICE_TCP_KEEPALIVE_PROBE_COUNT               3
#define SIGNALING_SERVICE_TCP_KEEPALIVE_PROBE_INTERVAL_IN_SECONDS 1
#define SIGNALING_SERVICE_WSS_PING_PONG_INTERVAL_IN_SECONDS       10


// API postfix definitions
// https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_CreateSignalingChannel.html
#define CREATE_SIGNALING_CHANNEL_API_POSTFIX       "/createSignalingChannel"
#define DESCRIBE_SIGNALING_CHANNEL_API_POSTFIX     "/describeSignalingChannel"
#define GET_SIGNALING_CHANNEL_ENDPOINT_API_POSTFIX "/getSignalingChannelEndpoint"
#define DELETE_SIGNALING_CHANNEL_API_POSTFIX       "/deleteSignalingChannel"
#define GET_ICE_CONFIG_API_POSTFIX                 "/v1/get-ice-server-config"

// Signaling protocol name
#define SIGNALING_CHANNEL_PROTOCOL "\"WSS\", \"HTTPS\""

// Parameterized string for Describe Channel API
#define DESCRIBE_CHANNEL_PARAM_JSON_TEMPLATE "{\n\t\"ChannelName\": \"%s\"\n}"

// Parameterized string for Delete Channel API
#define DELETE_CHANNEL_PARAM_JSON_TEMPLATE                                                                                                           \
    "{\n\t\"ChannelARN\": \"%s\","                                                                                                                   \
    "\n\t\"CurrentVersion\": \"%s\"\n}"

// Parameterized string for Create Channel API
#define CREATE_CHANNEL_PARAM_JSON_TEMPLATE                                                                                                           \
    "{\n\t\"ChannelName\": \"%s\","                                                                                                                  \
    "\n\t\"ChannelType\": \"%s\","                                                                                                                   \
    "\n\t\"SingleMasterConfiguration\": {"                                                                                                           \
    "\n\t\t\"MessageTtlSeconds\": %" PRIu64 "\n\t}"                                                                                                  \
    "%s\n}"

// Parameterized string for each tag pair as a JSON object
#define TAG_PARAM_JSON_OBJ_TEMPLATE "\n\t\t{\"Key\": \"%s\", \"Value\": \"%s\"},"

// Parameterized string for TagStream API - we should have at least one tag
#define TAGS_PARAM_JSON_TEMPLATE ",\n\t\"Tags\": [%s\n\t]"

// Parameterized string for Get Channel Endpoint API
#define GET_CHANNEL_ENDPOINT_PARAM_JSON_TEMPLATE                                                                                                     \
    "{\n\t\"ChannelARN\": \"%s\","                                                                                                                   \
    "\n\t\"SingleMasterChannelEndpointConfiguration\": {"                                                                                            \
    "\n\t\t\"Protocols\": [%s],"                                                                                                                     \
    "\n\t\t\"Role\": \"%s\""                                                                                                                         \
    "\n\t}\n}"

// Parameterized string for Get Ice Server Config API
#define GET_ICE_CONFIG_PARAM_JSON_TEMPLATE                                                                                                           \
    "{\n\t\"ChannelARN\": \"%s\","                                                                                                                   \
    "\n\t\"ClientId\": \"%s\","                                                                                                                      \
    "\n\t\"Service\": \"TURN\""                                                                                                                      \
    "\n}"

// Parameter names for Signaling connect URL
// https://docs.aws.amazon.com/zh_tw/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis-1.html
// https://docs.aws.amazon.com/zh_tw/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis-2.html
#define SIGNALING_ROLE_PARAM_NAME         "X-Amz-Role"
#define SIGNALING_CHANNEL_NAME_PARAM_NAME "X-Amz-ChannelName"
#define SIGNALING_CHANNEL_ARN_PARAM_NAME  "X-Amz-ChannelARN"
#define SIGNALING_CLIENT_ID_PARAM_NAME    "X-Amz-ClientId"

// Parameterized string for WSS connect
#define SIGNALING_ENDPOINT_MASTER_URL_WSS_TEMPLATE "%s?%s=%s"
#define SIGNALING_ENDPOINT_VIEWER_URL_WSS_TEMPLATE "%s?%s=%s&%s=%s"

#define SIGNALING_SDP_TYPE_OFFER       "SDP_OFFER"
#define SIGNALING_SDP_TYPE_ANSWER      "SDP_ANSWER"
#define SIGNALING_ICE_CANDIDATE        "ICE_CANDIDATE"
#define SIGNALING_GO_AWAY              "GO_AWAY"
#define SIGNALING_RECONNECT_ICE_SERVER "RECONNECT_ICE_SERVER"
#define SIGNALING_STATUS_RESPONSE      "STATUS_RESPONSE"

// Max length of the signaling message type string length
#define MAX_SIGNALING_MESSAGE_TYPE_LEN ARRAY_SIZE(SIGNALING_RECONNECT_ICE_SERVER)

// Max value length for the status code
#define MAX_SIGNALING_STATUS_MESSAGE_LEN 16

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

// Scratch buffer size
#define LWS_SCRATCH_BUFFER_SIZE (MAX_JSON_PARAMETER_STRING_LEN + LWS_PRE)

// Send and receive buffer size
#define LWS_MESSAGE_BUFFER_SIZE (SIZEOF(CHAR) * (MAX_SIGNALING_MESSAGE_LEN + LWS_PRE))

#define AWS_SIG_V4_HEADER_HOST (PCHAR) "host"

#define BOOLEAN_LITERAL_TRUE  "true"
#define BOOLEAN_LITERAL_FALSE "false"

// Specifies whether to block on the correlation id
#define BLOCK_ON_CORRELATION_ID FALSE

// Service loop iteration wait time when there is an already servicing thread
#define LWS_SERVICE_LOOP_ITERATION_WAIT (50 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)

// Check for the stale credentials
#define CHECK_SIGNALING_CREDENTIALS_EXPIRATION(p)                                                                                                    \
    do {                                                                                                                                             \
        if (GETTIME() >= (p)->pAwsCredentials->expiration) {                                                                                         \
            ATOMIC_STORE(&(p)->result, (SIZE_T) SERVICE_CALL_NOT_AUTHORIZED);                                                                        \
            CHK(FALSE, retStatus);                                                                                                                   \
        }                                                                                                                                            \
    } while (FALSE)

/**
 * Index of the signaling protocol handling WSS
 * IMPORTANT!!! This should match the correct index in the
 * signaling client protocol array
 */

#define LWS_EVENT_SERVICE   (1<<0)
#define LWS_EVENT_ASYNC_ICE_CONF   (1<<1)
#define LWS_EVENT_RECONNECT   (1<<2)
#define LWS_EVENT_RECEIVE_MSG   (1<<3)
#define LWS_EVENT_REFRESH_ICE_CONF   (1<<4)

typedef enum __LwsSignalingProtocol {
    LWS_SIGNALING_PROTOCOL_HTTPS = 0,
    LWS_SIGNALING_PROTOCOL_WSS = 1,
    LWS_SIGNALING_PROTOCOL_NUM
};



/**
 * @brief   the information of calling lws service.
*/
struct __LwsHttpInfo {
    // Service exit indicator;
    volatile ATOMIC_BOOL cancelService;

    // Protocol index
    UINT32 protocolIndex;

    // Call info object
    CallInfo callInfo;

    // Back reference to the signaling client
    PSignalingClient pSignalingClient;

    // Scratch buffer for http processing
    CHAR httpBuf[LWS_SCRATCH_BUFFER_SIZE];
};
typedef struct __LwsHttpInfo LwsHttpInfo;

struct __LwsWssInfo {
    // Service exit indicator;
    volatile ATOMIC_BOOL cancelService;

    // Protocol index
    UINT32 protocolIndex;//!< used for controling the lws layer.

    // Call info object
    CallInfo callInfo;

    // Back reference to the signaling client
    PSignalingClient pSignalingClient;

    // Size of the data in the buffer
    volatile SIZE_T wssTxBufSize;//!< the size of send buffer including the lws_pre.

    // Offset from which to send data
    volatile SIZE_T wssTxBufOfst;//!< the offset of the data needs to be sent. means the offset from the end position of lws_pre.

    // Scratch buffer for sending
    BYTE wssTxBuf[LWS_MESSAGE_BUFFER_SIZE];

    // Scratch buffer for receiving
    BYTE wssRxBuf[LWS_MESSAGE_BUFFER_SIZE];

    // Size of the data in the receive buffer
    UINT32 wssRxBufSize;
};
typedef struct __LwsWssInfo LwsWssInfo;

typedef struct {
    // The first member is the public signaling message structure
    ReceivedSignalingMessage receivedSignalingMessage;

    // The messaging client object
    PSignalingClient pSignalingClient;
} SignalingMessageWrapper, *PSignalingMessageWrapper;

// Signal handler routine
VOID lwsSignalHandler(INT32);
/**
 * @brief   https connection.
*/
STATUS lwsCreateHttpInfo(PSignalingClient, PRequestInfo, UINT32, PLwsHttpInfo*);
STATUS lwsFreeHttpInfo(PLwsHttpInfo*);
INT32 lwsHttpCallbackRoutine(struct lws*, enum lws_callback_reasons, PVOID, PVOID, size_t);
STATUS lwsDescribeChannel(PSignalingClient, UINT64);
STATUS lwsCreateChannel(PSignalingClient, UINT64);
STATUS lwsGetChannelEndpoint(PSignalingClient, UINT64);
STATUS lwsGetIceConfig(PSignalingClient, UINT64);
STATUS lwsDeleteChannel(PSignalingClient, UINT64);

/**
 * @brief   websocket protocol.
*/
STATUS lwsGetMessageTypeFromString(PCHAR, UINT32, SIGNALING_MESSAGE_TYPE*);
STATUS lwsCreateWssInfo(PSignalingClient, PRequestInfo, UINT32, PLwsWssInfo*);
STATUS lwsFreeWssInfo(PLwsWssInfo*);
INT32 lwsWssCallbackRoutine(struct lws*, enum lws_callback_reasons, PVOID, PVOID, size_t);
STATUS lwsWakeServiceEventLoop(PSignalingClient);
STATUS lwsTerminateConnectionWithStatus(PSignalingClient, SERVICE_CALL_RESULT);
STATUS lwsTerminateListenerLoop(PSignalingClient);
// LWS listener handler
PVOID lwsWssHandler(PVOID);
// Retry thread
PVOID lwsReconnectHandler(PVOID);
PVOID lwsReceiveMessageWrapper(PVOID);
#ifdef KVS_PLAT_ESP_FREERTOS
STATUS lwsDispatchMsg(PVOID pMessage);
#endif
STATUS lwsConnectSignalingChannel(PSignalingClient, UINT64);
STATUS lwsSendWssMessage(PSignalingClient, PCHAR, PCHAR, PCHAR, UINT32, PCHAR, UINT32);
STATUS lwsWriteWssData(PSignalingClient, BOOL);

STATUS lwsReceiveWssMessage(PSignalingClient, PCHAR, UINT32);


#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_LWS_API_CALLS__ */
