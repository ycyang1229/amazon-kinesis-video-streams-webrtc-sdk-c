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

#define LOG_CLASS "AwsSignerV4"
#include "../Include_i.h"


//#include <mbedtls/sha256.h>
//#include <mbedtls/md.h>

#define CANONICAL_HEADER_TEMPLATE   "%.*s:%.*s\n"
#define CANONICAL_BODY_TEMPLATE     "\n%s\n"
#define CANONICAL_SCOPE_TEMPLATE    "%.*s/%.*s/%.*s/%s"
#define CANONICAL_SIGNED_TEMPLATE   "%s\n%s\n%s\n%s"
#define SIGNATURE_START_TEMPLATE    "%s%.*s"

/*-----------------------------------------------------------*/

/**
 * @brief Encode a message into SHA256 text format
 *
 * It's a util function that encode pMsg into SHA256 HEX text format and put it in buffer pEncodeHash.
 *
 * @param[in] pMsg The message to be encoded
 * @param[in] uMsgLen The length of the message
 * @param[out] pEncodedHash The buffer to be stored the results
 *
 * @return KVS error code if error happened; Or the length of encoded length if it succeeded.
 */
static INT32 hexEncodedSha256( UINT8 * pMsg,
                                 UINT32 uMsgLen,
                                 PCHAR pEncodedHash )
{
    SIZE_T i = 0;
    PCHAR p = NULL;
    UINT8 hashBuf[ SHA256_DIGEST_LENGTH ];

    if( pMsg == NULL || pEncodedHash == NULL )
    {
        return STATUS_INVALID_ARG;
    }

    mbedtls_sha256( pMsg, uMsgLen, hashBuf, 0 );

    /* encode hash result into hex text format */

    p = pEncodedHash;
    for( i = 0; i < SHA256_DIGEST_LENGTH; i++ )
    {
        p += SPRINTF( p, "%02x", hashBuf[i] );
    }

    return p - pEncodedHash;
}

/*-----------------------------------------------------------*/

STATUS AwsSignerV4_initContext( AwsSignerV4Context_t * pCtx, UINT32 uBufsize )
{
    STATUS retStatus = STATUS_SUCCESS;

    if( pCtx == NULL )
    {
        DLOGE("Invalid Arg: AwsSignerV4Context\r\n");
        retStatus = STATUS_INVALID_ARG;
    }
    else
    {
        MEMSET( pCtx, 0, sizeof( AwsSignerV4Context_t ) );

        if( ( pCtx->pBuf = ( PCHAR )MEMALLOC( uBufsize ) ) == NULL )
        {
            DLOGE("OOM: AwsSignerV4 pBuf\r\n");
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
        }
        else if( ( pCtx->pSignedHeader = ( PCHAR )MEMALLOC( AWS_SIG_V4_MAX_HEADERS_LEN ) ) == NULL )
        {
            DLOGE("OOM: pSignedHeader\r\n");
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
        }
        else if( ( pCtx->pCredentialScope = ( PCHAR )MEMALLOC( MAX_SCOPE_LEN ) ) == NULL )
        {
            DLOGE("OOM: pCredentialScope\r\n");
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
        }
        else if( ( pCtx->pHmacEncoded = ( PCHAR )MEMALLOC( AWS_SIG_V4_MAX_HMAC_SIZE ) ) == NULL )
        {
            DLOGE("OOM: pHmacEncoded\r\n");
            retStatus = STATUS_NOT_ENOUGH_MEMORY;
        }
        else
        {
            pCtx->uBufSize = uBufsize;
            pCtx->pBufIndex = pCtx->pBuf;
            MEMSET( pCtx->pSignedHeader, 0, AWS_SIG_V4_MAX_HEADERS_LEN );
            MEMSET( pCtx->pCredentialScope, 0, MAX_SCOPE_LEN );
            MEMSET( pCtx->pHmacEncoded, 0, AWS_SIG_V4_MAX_HMAC_SIZE );
        }

        if( retStatus != STATUS_SUCCESS )
        {
            AwsSignerV4_terminateContext(pCtx);
        }
    }

    return retStatus;
}

/*-----------------------------------------------------------*/

void AwsSignerV4_terminateContext( AwsSignerV4Context_t * pCtx )
{
    if( pCtx != NULL )
    {
        if( pCtx->pBuf != NULL )
        {
            MEMFREE( pCtx->pBuf );
            pCtx->pBuf = NULL;
            pCtx->uBufSize = 0;
        }

        if( pCtx->pSignedHeader != NULL )
        {
            MEMFREE( pCtx->pSignedHeader );
            pCtx->pSignedHeader = NULL;
        }

        if( pCtx->pCredentialScope != NULL )
        {
            MEMFREE( pCtx->pCredentialScope );
            pCtx->pCredentialScope = NULL;
        }

        if( pCtx->pHmacEncoded != NULL )
        {
            MEMFREE( pCtx->pHmacEncoded );
            pCtx->pHmacEncoded = NULL;
        }
    }
}

/*-----------------------------------------------------------*/
/**
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 * CanonicalRequest =
 * HTTPRequestMethod + '\n' +
 * CanonicalURI + '\n' +
 * CanonicalQueryString + '\n' +
 * CanonicalHeaders + '\n' +
 * SignedHeaders + '\n' +
 * HexEncode(Hash(RequestPayload))
*/
STATUS AwsSignerV4_initCanonicalRequest( AwsSignerV4Context_t * pCtx,
                                          PCHAR pMethod,
                                          UINT32 uMethodLen,
                                          PCHAR pUri,
                                          UINT32 uUriLen,
                                          PCHAR pParameter,
                                          UINT32 pParameterLen )
{
    STATUS retStatus = STATUS_SUCCESS;

    if( pCtx == NULL || pCtx->pBuf == NULL || pCtx->pBufIndex == NULL )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else if( pMethod == NULL || uMethodLen == 0 || pUri == NULL || uUriLen == 0 )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else
    {
        pCtx->pBufIndex += SPRINTF( pCtx->pBufIndex, "%.*s\n", ( INT32 ) uMethodLen, pMethod );
        pCtx->pBufIndex += SPRINTF( pCtx->pBufIndex, "%.*s\n", ( INT32 ) uUriLen, pUri );

        if( pParameter == NULL || pParameterLen == 0 )
        {
            pCtx->pBufIndex += SPRINTF( pCtx->pBufIndex, "\n");
        }
        else
        {
            /* Skip the '?' character */
            pCtx->pBufIndex += SPRINTF( pCtx->pBufIndex, "%.*s\n", ( INT32 )pParameterLen - 1, pParameter + 1 );
        }
    }

    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS AwsSignerV4_addCanonicalHeader( AwsSignerV4Context_t * pCtx,
                                        PCHAR pHeader,
                                        UINT32 uHeaderLen,
                                        PCHAR pValue,
                                        UINT32 uValueLen )
{
    STATUS retStatus = STATUS_SUCCESS;
    SIZE_T uSignedHeaderLen = 0;
    if( pCtx == NULL || pCtx->pBuf == NULL || pCtx->pBufIndex == NULL )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else if( pHeader == NULL || uHeaderLen == 0 || pValue == NULL || uValueLen == 0 )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else
    {
        /* Add this canonical header into headers */
        pCtx->pBufIndex += SPRINTF( pCtx->pBufIndex, CANONICAL_HEADER_TEMPLATE,
                                    ( INT32 ) uHeaderLen, pHeader,
                                    ( INT32 ) uValueLen, pValue );

        /* Append seperator ';' if this is not the first header */
        uSignedHeaderLen = STRLEN( pCtx->pSignedHeader );
        if( uSignedHeaderLen != 0 )
        {
            pCtx->pSignedHeader[ uSignedHeaderLen++ ] = ';';
        }

        /* append this header into signed header list */
        SNPRINTF( pCtx->pSignedHeader + uSignedHeaderLen, uHeaderLen + 1, "%.*s", ( INT32 )uHeaderLen, pHeader );
    }

    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS AwsSignerV4_addCanonicalBody( AwsSignerV4Context_t * pCtx,
                                      UINT8 * pBody,
                                      UINT32 uBodyLen )
{
    STATUS retStatus = STATUS_SUCCESS;
    INT32 xEncodedLen = 0;
    CHAR pBodyHexSha256[ AWS_SIG_V4_MAX_HMAC_SIZE ];

    if ( pCtx == NULL || pCtx->pBuf == NULL || pCtx->pBufIndex == NULL )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else
    {
        /* Append signed header list into canonical request */
        pCtx->pBufIndex += SPRINTF( pCtx->pBufIndex, CANONICAL_BODY_TEMPLATE, pCtx->pSignedHeader );

        /* Append encoded sha results of message body into canonical request */
        xEncodedLen = hexEncodedSha256( pBody, uBodyLen, pBodyHexSha256 );
        if (xEncodedLen < 0 ) {
            /* Propagate the error */
            retStatus = xEncodedLen;
        }
        else
        {
            MEMCPY( pCtx->pBufIndex, pBodyHexSha256, xEncodedLen );
            pCtx->pBufIndex += xEncodedLen;
        }

    }

    return retStatus;
}

/*-----------------------------------------------------------*/

STATUS AwsSignerV4_sign( AwsSignerV4Context_t * pCtx,
                          PCHAR pSecretKey,
                          UINT32 uSecretKeyLen,
                          PCHAR pRegion,
                          UINT32 uRegionLen,
                          PCHAR pService,
                          UINT32 uServiceLen,
                          PCHAR pXAmzDate,
                          UINT32 uXAmzDateLen )
{
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR p = NULL;
    SIZE_T i = 0;
    CHAR pRequestHexSha256[ AWS_SIG_V4_MAX_HMAC_SIZE ];
    CHAR pSignedStr[ MAX_SIGNED_STRING_LEN ];
    INT32 xSignedStrLen = 0;
    const mbedtls_md_info_t * md_info = NULL;
    UINT8 pHmac[ AWS_SIG_V4_MAX_HMAC_SIZE ];
    UINT32 uHmacSize = 0;

    if( pCtx == NULL || pCtx->pBuf == NULL || pCtx->pBufIndex == NULL )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else if( pSecretKey == NULL || uSecretKeyLen == 0 || pRegion == NULL || uRegionLen == 0 || pService == NULL || uServiceLen == 0 || pXAmzDate == NULL || uXAmzDateLen == 0 )
    {
        retStatus = STATUS_INVALID_ARG;
    }
    else
    {
        /* Encoded the canonical request into HEX SHA text format. */
        retStatus = hexEncodedSha256( ( UINT8 * )( pCtx->pBuf ), STRLEN(pCtx->pBuf), pRequestHexSha256 );

        if( retStatus >= 0 )
        {
            retStatus = STATUS_SUCCESS;

            md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );

            /* Generate the scope string */
            /**
             * CredentialScope
             * Append the credential scope value, followed by a newline character.
             * This value is a string that includes the date, the Region you are targeting, the service you are requesting, 
             * and a termination string ("aws4_request") in lowercase characters. The Region and service name strings must be UTF-8 encoded.
             * ex: 20150830/us-east-1/iam/aws4_request\n
            */
            SNPRINTF( pCtx->pCredentialScope, MAX_SCOPE_LEN, CANONICAL_SCOPE_TEMPLATE, SIGNATURE_DATE_STRING_LEN, pXAmzDate, uRegionLen, pRegion, uServiceLen, pService, AWS_SIG_V4_SIGNATURE_END );
            /* Generate signed string */
            /**
             * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
             * StringToSign =
             * Algorithm + \n +
             * RequestDateTime + \n +
             * CredentialScope + \n +
             * HashedCanonicalRequest
            */
            xSignedStrLen = SPRINTF( pSignedStr, CANONICAL_SIGNED_TEMPLATE, AWS_SIG_V4_ALGORITHM, pXAmzDate, pCtx->pCredentialScope, pRequestHexSha256 );
            /* Generate the beginning of the signature */
            /**
             * https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
             * kSecret = your secret access key
             * kDate = HMAC("AWS4" + kSecret, Date)
             * kRegion = HMAC(kDate, Region)
             * kService = HMAC(kRegion, Service)
             * kSigning = HMAC(kService, "aws4_request")
             * 
             * HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,"20150830"),"us-east-1"),"iam"),"aws4_request")
             * 
            */
            SNPRINTF( ( PCHAR )pHmac, AWS_SIG_V4_MAX_HMAC_SIZE, SIGNATURE_START_TEMPLATE, AWS_SIG_V4_SIGNATURE_START, ( INT32 )uSecretKeyLen, pSecretKey );

            uHmacSize = mbedtls_md_get_size( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ) );

            if( mbedtls_md_hmac( md_info, pHmac, sizeof( AWS_SIG_V4_SIGNATURE_START ) - 1 + uSecretKeyLen, ( UINT8 * )pXAmzDate, SIGNATURE_DATE_STRING_LEN, pHmac ) != 0 )
            {
                retStatus = STATUS_AWS_SIGNER_FAIL_TO_CALCULATE_HASH;
            }
            else if( mbedtls_md_hmac( md_info, pHmac, uHmacSize, ( UINT8 * )pRegion, uRegionLen, pHmac ) != 0 )
            {
                retStatus = STATUS_AWS_SIGNER_FAIL_TO_CALCULATE_HASH;
            }
            else if( mbedtls_md_hmac( md_info, pHmac, uHmacSize, ( UINT8 * )pService, uServiceLen, pHmac ) != 0 )
            {
                retStatus = STATUS_AWS_SIGNER_FAIL_TO_CALCULATE_HASH;
            }
            else if( mbedtls_md_hmac( md_info, pHmac, uHmacSize, ( UINT8 * )AWS_SIG_V4_SIGNATURE_END, sizeof( AWS_SIG_V4_SIGNATURE_END ) - 1, pHmac ) != 0 )
            {
                retStatus = STATUS_AWS_SIGNER_FAIL_TO_CALCULATE_HASH;
            }
            /** signature = HexEncode(HMAC(derived signing key, string to sign)) */
            else if( mbedtls_md_hmac( md_info, pHmac, uHmacSize, ( UINT8 * )pSignedStr, xSignedStrLen, pHmac ) != 0 )
            {
                retStatus = STATUS_AWS_SIGNER_FAIL_TO_CALCULATE_HASH;
            }
            else
            {
                /* encode the hash result into HEX text */
                p = pCtx->pHmacEncoded;
                for( i = 0; i < uHmacSize; i++ )
                {
                    p += SPRINTF( p, "%02x", pHmac[ i ] & 0xFF );
                }
            }
        }
    }

    return retStatus;
}

/*-----------------------------------------------------------*/

PCHAR AwsSignerV4_getSignedHeader( AwsSignerV4Context_t * pCtx )
{
    if( pCtx == NULL )
    {
        return NULL;
    }
    else
    {
        return pCtx->pSignedHeader;
    }
}

/*-----------------------------------------------------------*/

PCHAR AwsSignerV4_getScope( AwsSignerV4Context_t * pCtx )
{
    if( pCtx == NULL )
    {
        return NULL;
    }
    else
    {
        return pCtx->pCredentialScope;
    }
}

/*-----------------------------------------------------------*/

PCHAR AwsSignerV4_getHmacEncoded( AwsSignerV4Context_t * pCtx )
{
    if( pCtx == NULL )
    {
        return NULL;
    }
    else
    {
        return pCtx->pHmacEncoded;
    }
}
