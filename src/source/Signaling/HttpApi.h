/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#ifndef _WEBRTC_REST_API_H_
#define _WEBRTC_REST_API_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Max update version length in chars
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_DeleteSignalingChannel.html#KinesisVideo-DeleteSignalingChannel-request-CurrentVersion
 */
#define WEBRTC_CHANNEL_VERSION_LEN_MAX 64
/**
 * Max ARN len in chars
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_DescribeSignalingChannel.html#API_DescribeSignalingChannel_RequestSyntax
 */
#define WEBRTC_CHANNEL_ARN_LEN_MAX 1024
/**
 * Maximum allowed channel name length
 */
#define WEBRTC_CHANNEL_NAME_LEN_MAX 256

/**
 * Maximum allowed signaling URI length
 */
#define MAX_SIGNALING_ENDPOINT_URI_LEN 512

#define WEBRTC_CHANNEL_TYPE_UNKNOWN_STR       (CHAR*) "UNKOWN"
#define WEBRTC_CHANNEL_TYPE_SINGLE_MASTER_STR (CHAR*) "SINGLE_MASTER"


// Signaling channel role type string
#define WEBRTC_CHANNEL_ROLE_UNKNOWN_STR (CHAR*) "UNKOWN"
#define WEBRTC_CHANNEL_ROLE_MASTER_STR  (CHAR*) "MASTER"
#define WEBRTC_CHANNEL_ROLE_VIEWER_STR  (CHAR*) "VIEWER"




//#define WEBRTC_CHANNEL_PROTOCOL "\"WSS\""
#define WEBRTC_CHANNEL_PROTOCOL "\"WSS\", \"HTTPS\""

#define WEBRTC_ENDPOINT_TYPE_UNKNOWN_STR (CHAR*) "UNKOWN"
#define WEBRTC_ENDPOINT_TYPE_HTTPS_STR (CHAR*) "HTTPS"
#define WEBRTC_ENDPOINT_TYPE_WSS_STR (CHAR*) "WSS"



/**
 * @brief Channel type as reported by the service
 */
typedef enum {
    WEBRTC_CHANNEL_TYPE_UNKNOWN,       //!< Channel type is unknown
    WEBRTC_CHANNEL_TYPE_SINGLE_MASTER, //!< Channel type is master
    //WEBRTC_CHANNEL_TYPE_FULL_MESH
} WEBRTC_CHANNEL_TYPE;


/**
 * @brief Defines channel status as reported by the service
 */
typedef enum {
    WEBRTC_CHANNEL_STATUS_CREATING, //!< Signaling channel is being created
    WEBRTC_CHANNEL_STATUS_ACTIVE,   //!< Signaling channel is active
    WEBRTC_CHANNEL_STATUS_UPDATING, //!< Signaling channel is being updated
    WEBRTC_CHANNEL_STATUS_DELETING, //!< Signaling channel is being deleted
} WEBRTC_CHANNEL_STATUS;

/**
 * @brief Channel role type
 */
typedef enum {
    WEBRTC_CHANNEL_ROLE_TYPE_UNKNOWN, //!< Channel role is unknown
    WEBRTC_CHANNEL_ROLE_TYPE_MASTER,  //!< Channel role is master
    WEBRTC_CHANNEL_ROLE_TYPE_VIEWER,  //!< Channel role is viewer
} WEBRTC_CHANNEL_ROLE_TYPE;


/**
 * @brief Channel type
 */
typedef enum {
    WEBRTC_ENDPOINT_TYPE_HTTPS,
    WEBRTC_ENDPOINT_TYPE_WSS,
    WEBRTC_ENDPOINT_TYPE_UNKNOWN
} WEBRTC_ENDPOINT_TYPE;

typedef struct
{
    PCHAR pAccessKey;  // It's AWS access key if not using IoT certification.
    PCHAR pSecretKey;  // It's secret of AWS access key if not using IoT certification.
    PCHAR pToken;      // Set to NULL if not using IoT certification.

    PCHAR pRegion;     // The desired region of KVS service
    PCHAR pService;    // KVS service name
    PCHAR pHost;       // Endpoint of the RESTful api
    PCHAR pUserAgent;  // HTTP agent name
} webrtcServiceParameter_t;


/**
 * @brief   
 * 
 * 
 * channel name
 * channel type
 * channel status
 * creation time
 * single master configurarion.
 * tags.
 * channel arn.
 * 
 * current version.
 * 
 * 
*/

typedef struct{
    UINT64 messageTtlSeconds;//!< The period of time a signaling channel retains underlived messages before they are discarded
                                //!< The values are in the range of 5 and 120 seconds
}singleMasterConfiguration_t;


/**
 * @brief Signaling channel description returned from the service
 * 
 * #YC_TBD, need to do the memory alignment.
 */
typedef struct {
    CHAR channelName[WEBRTC_CHANNEL_NAME_LEN_MAX+1];//!< Signaling channel name. Should be unique per AWS account
    CHAR channelArn[WEBRTC_CHANNEL_ARN_LEN_MAX+1];//!< Channel Amazon Resource Name (ARN)

    WEBRTC_CHANNEL_STATUS channelStatus;//!< Current channel status as reported by the service
    WEBRTC_CHANNEL_TYPE channelType;//!< Channel type as reported by the service
    CHAR version[WEBRTC_CHANNEL_VERSION_LEN_MAX + 1];//!< A random number generated on every update while describing
                                                    //!< signaling channel
    singleMasterConfiguration_t singleMasterConf;
    UINT64 creationTime;//!< Timestamp of when the channel gets created
    WEBRTC_CHANNEL_ROLE_TYPE channelRole;
    WEBRTC_ENDPOINT_TYPE endPointType;
    CHAR channelEndpoint[MAX_SIGNALING_ENDPOINT_URI_LEN + 1];
} webrtcChannelInfo_t;

WEBRTC_CHANNEL_ROLE_TYPE webrtc_getChannelRoleTypeFromString(CHAR* type, UINT32 length);
CHAR* webrtc_getStringFromChannelRoleType(WEBRTC_CHANNEL_ROLE_TYPE type);


/**
 * @brief Create a Stream
 *
 * @param[in] pServiceParameter AWS Service related parameters
 * @param[in] pDeviceName Parameter of "/createStream".
 * @param[in] pStreamName Parameter of "/createStream"
 * @param[in] pMediaType Parameter of "/createStream"
 * @param[in] xDataRetentionInHours Parameter of "/createStream"
 *
 * @return KVS error code
 */
STATUS httpApiCreateSignalingChannl(PSignalingClient pSignalingClient, UINT64 time);

/**
 * @brief Describe a Stream
 *
 * Get the description of a stream to make sure the stream is available. It returns error if the stream does not exist
 * and therefore needs creation before using it.
 *
 * @param[in] pServiceParameter AWS Service related parameters
 * @param[in] pStreamName Parameter of "/describeStream"
 *
 * @return KVS error code
 */
STATUS httpApiDescribeSignalingChannel(PSignalingClient pSignalingClient, UINT64 time);


STATUS httpApiGetChannelEndpoint(PSignalingClient pSignalingClient, UINT64 time);
STATUS httpApiGetIceConfig(PSignalingClient pSignalingClient, UINT64 time);
// rsp
STATUS httpApiRspCreateChannel( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspDescribeChannel( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspGetChannelEndpoint( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
STATUS httpApiRspGetIceConfig( const CHAR * pResponseStr, UINT32 resultLen, PSignalingClient pSignalingClient);
#ifdef __cplusplus
}
#endif
#endif // #ifndef _WEBRTC_REST_API_H_