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
/*******************************************
Signaling internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_AWS_SIGNER_V4_H__
#define __KINESIS_VIDEO_WEBRTC_AWS_SIGNER_V4_H__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* (Configurable). Max length of AWS region name. */
#define MAX_REGION_NAME_LEN                     24

/* (Configurable). Max length of AWS service name. */
#define MAX_SERVICE_NAME_LEN                    48

/* The buffer length used for doing SHA256 hash check. */
#define SHA256_DIGEST_LENGTH                    32

/* The string length of "date + time" format defined by AWS Signature V4. */
#define SIGNATURE_DATE_TIME_STRING_LEN          17

/* The string length of "date" format defined by AWS Signature V4. */
#define SIGNATURE_DATE_STRING_LEN               8

/* (Configurable).  The number of HTTP headers to be signed. */
#define AWS_SIG_V4_MAX_HEADER_CNT               12

/* (Configurable).  The max length of HTTP header to be signed. */
#define AWS_SIG_V4_MAX_HEADER_LEN               64

#define AWS_SIG_V4_MAX_HEADERS_LEN              ( AWS_SIG_V4_MAX_HEADER_CNT * AWS_SIG_V4_MAX_HEADER_LEN )

/* The signature start described by AWS Signature V4. */
#define AWS_SIG_V4_SIGNATURE_START              "AWS4"

/* The signature end described by AWS Signature V4. */
#define AWS_SIG_V4_SIGNATURE_END                "aws4_request"

/* The signed algorithm. */
#define AWS_SIG_V4_ALGORITHM                    "AWS4-HMAC-SHA256"

/* The length of oct string for SHA256 hash buffer. */
#define AWS_SIG_V4_MAX_HMAC_SIZE                ( SHA256_DIGEST_LENGTH * 2 + 1 )

/* The max length of signature scope which is composed of date, time, region, service, and signature end. */
#define MAX_SCOPE_LEN                           ( SIGNATURE_DATE_TIME_STRING_LEN + 1 + \
                                                MAX_REGION_NAME_LEN + 1 + \
                                                MAX_SERVICE_NAME_LEN + 1 + \
                                                sizeof( AWS_SIG_V4_SIGNATURE_END ) )

/* The max length of signature result. */
#define MAX_SIGNED_STRING_LEN                   ( sizeof( AWS_SIG_V4_ALGORITHM ) + \
                                                SIGNATURE_DATE_TIME_STRING_LEN + 1 + \
                                                MAX_SCOPE_LEN + 1 +                 \
                                                ( SHA256_DIGEST_LENGTH * 2 + 1 ) + 1 )


typedef struct awsAccessKey
{
    PCHAR accessKeyId;
    //UINT32 accessKeyIdLen;  //!< Length of the access key id - not including NULL terminator
    PCHAR secretKey;
    //UINT32 secretKeyLen;    //!< Length of the secret key - not including NULL terminator
}awsAccessKey_t;

typedef struct sessionToken
{
    PCHAR sessionToken;     //!< Session token - NULL terminated
    //UINT32 sessionTokenLen; //!< Length of the session token - not including NULL terminator
    UINT64 expiration;      //!< Expiration in absolute time in 100ns.
}sessionToken_t;

typedef union _awsCredential{
    awsAccessKey_t accessKey;
    sessionToken_t sessionToken;
}_awsCredential_t;


struct awsCredential{
    UINT32 version;
    _awsCredential_t awsCredential;
}awsCredential_t;


/* A context that keeps the signature request and results */
typedef struct AwsSignerV4Context
{
    PCHAR pBuf;                 /* A buffer to keep the sign request header and body. */
    UINT32 uBufSize;          /* The buffer size */
    PCHAR pBufIndex;            /* The buffer index (i.e. buffer ending) */

    PCHAR pSignedHeader;        /* The HTTP headers to be signed. */
    PCHAR pCredentialScope;               /* The scope of this signature. */
    PCHAR pHmacEncoded;         /* The signature in a form of encoded HMAC SHA256 hex text */
} AwsSignerV4Context_t;

/**
 * @brief Initialize the AWS Signer V4 context.
 *
 * It initialize the AWS Signer V4 context with internal buffer with size uBufsize. The internal buffer is created from
 * dynamic memory and it's used for canonical request headers, body, and encoded results. Please assigned enough size
 * so that it won't overflow.
 *
 * @param[in] pCtx The context of AWS signer V4 to be initialized
 * @param[in] uBufsize The internal buffer size
 *
 * @return KVS error code
 */
STATUS AwsSignerV4_initContext( AwsSignerV4Context_t * pCtx, UINT32 uBufsize );

/**
 * @brief De-initialize the AWS signer V4 context.
 *
 * @param[in] pCtx The context of AWS signer V4 to be de-initialized
 */
void AwsSignerV4_terminateContext( AwsSignerV4Context_t * pCtx );

/**
 * @brief Initialize the canonical request
 *
 * A canonical request consist of these fields:
 * 1. HTTP request method
 * 2. canonical URI
 * 3. canonical query string (i.e. parameters)
 * 4. canonical headers
 * 5. signed headers
 * 6. payload with the encode results
 * 
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 * CanonicalRequest =
 * HTTPRequestMethod + '\n' +
 * CanonicalURI + '\n' +
 * CanonicalQueryString + '\n' +
 * CanonicalHeaders + '\n' +
 * SignedHeaders + '\n' +
 * HexEncode(Hash(RequestPayload))
 *
 * We initialize 1, 2, and 3 in this function because they don't change to a specific request.
 *
 * @param[in] pCtx AWS signer V4 context
 * @param[in] pMethod HTTP request method
 * @param[in] uMethodLen Length of HTTP request method
 * @param[in] pUri URI
 * @param[in] uUriLen Length of URI
 * @param[in] pParameter Parameters
 * @param[in] pParameterLen Length of parameters
 *
 * @return KVS error code
 */
STATUS AwsSignerV4_initCanonicalRequest( AwsSignerV4Context_t * pCtx,
                                          PCHAR  pMethod,
                                          UINT32 uMethodLen,
                                          PCHAR  pUri,
                                          UINT32 uUriLen,
                                          PCHAR  pParameter,
                                          UINT32 pParameterLen );

/**
 * @brief Add a HTTP header into canonical request.
 *
 * Add a HTTP header into canonical request. Please note that the header should be in lower-case and should be added
 * in sorted alphabet order.
 *
 * @param[in] pCtx AWS signer V4 context
 * @param[in] pHeader HTTP header name
 * @param[in] uHeaderLen Length of the HTTP header name
 * @param[in] pValue The value of HTTP header
 * @param[in] uValueLen Length of the value
 *
 * @return KVS error code
 */
STATUS AwsSignerV4_addCanonicalHeader( AwsSignerV4Context_t *pCtx,
                                        PCHAR pHeader,
                                        UINT32 uHeaderLen,
                                        PCHAR pValue,
                                        UINT32 uValueLen );

/**
 * @brief Add HTTP body into canonical request.
 *
 * Add HTTP body into canonical request. It's the last part of the canonical request. Please note this function is
 * required even there is no HTTP body because an empty body still has an encoded hex result which is required in
 * canonical request.
 *
 * @param[in] pCtx AWS signer V4 context
 * @param[in] pBody HTTP body
 * @param[in] uBodyLen Length of the body
 *
 * @return KVS error code
 */
STATUS AwsSignerV4_addCanonicalBody( AwsSignerV4Context_t * pCtx,
                                      uint8_t * pBody,
                                      UINT32 uBodyLen );

/**
 * @brief Sign the canonical request with key and other information
 *
 * @param[in] pCtx AWS signer V4 context
 * @param[in] pSecretKey The secret of AWS access key
 * @param[in] uSecretKeyLen Length of the secret
 * @param[in] pRegion AWS region
 * @param[in] uRegionLen Length of the region
 * @param[in] pService AWS service name
 * @param[in] uServiceLen Length of the service name
 * @param[in] pXAmzDate Date with AWS x-amz-date format
 * @param[in] uXAmzDateLen Length of the date
 *
 * @return KVS error code
 */
STATUS AwsSignerV4_sign( AwsSignerV4Context_t * pCtx,
                          PCHAR  pSecretKey,
                          UINT32 uSecretKeyLen,
                          PCHAR  pRegion,
                          UINT32 uRegionLen,
                          PCHAR  pService,
                          UINT32 uServiceLen,
                          PCHAR  pXAmzDate,
                          UINT32 uXAmzDateLen );

/**
 * @brief Get the header lists to be signed
 *
 * @param[in] pCtx AWS signer V4 context
 *
 * @return The header lists to be signed
 */
PCHAR AwsSignerV4_getSignedHeader( AwsSignerV4Context_t * pCtx );

/**
 * @brief Get the scope of the context
 *
 * Scope is a required parameter in RESTful API request. It consists of x-amz-date, region, service, and signature end.
 * A well-format scope is generated during signing process.
 *
 * @param[in] pCtx AWS signer V4 context
 *
 * @return Scope of signature
 */
PCHAR AwsSignerV4_getScope( AwsSignerV4Context_t * pCtx );

/**
 * @brief Get the encoded results of signature
 *
 * After signed, the result is stored in an encoded HEX text.
 *
 * @param pCtx AWS signer V4 context
 *
 * @return The encoded HEX text of signature
 */
PCHAR AwsSignerV4_getHmacEncoded( AwsSignerV4Context_t * pCtx );

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_AWS_SIGNER_V4_H__ */
