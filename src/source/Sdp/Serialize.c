#define LOG_CLASS "SDP"
#include "../Include_i.h"

/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.1
 *          v=  (protocol version)
 * 
 * @param[in] version the version of sdp.
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeVersion(UINT64 version, PCHAR* ppOutputData, PUINT32 pTotalWritten, PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    currentWriteSize = SNPRINTF(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                SDP_VERSION_MARKER "%" PRIu64 SDP_LINE_SEPARATOR, version);

    CHK(*ppOutputData == NULL || ((*pBufferSize - *pTotalWritten) >= currentWriteSize), STATUS_BUFFER_TOO_SMALL);
    *pTotalWritten += currentWriteSize;
    if (*ppOutputData != NULL) {
        *ppOutputData += currentWriteSize;
    }

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.2
 *          o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
 *          The "o=" field gives the originator of the session (her username and the address of the user's host) 
 *          plus a session identifier and version number
 * 
 * @param[in] pSDPOrigin
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeOrigin(PSdpOrigin pSDPOrigin, PCHAR* ppOutputData, PUINT32 pTotalWritten, PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    CHK(pSDPOrigin != NULL, STATUS_NULL_ARG);

    if (pSDPOrigin->userName[0] != '\0' && pSDPOrigin->sdpConnectionInformation.networkType[0] != '\0' &&
        pSDPOrigin->sdpConnectionInformation.addressType[0] != '\0' && pSDPOrigin->sdpConnectionInformation.connectionAddress[0] != '\0') {
        currentWriteSize = SNPRINTF(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                    SDP_ORIGIN_MARKER "%s %" PRIu64 " %" PRIu64 " %s %s %s" SDP_LINE_SEPARATOR, pSDPOrigin->userName,
                                    pSDPOrigin->sessionId, pSDPOrigin->sessionVersion, pSDPOrigin->sdpConnectionInformation.networkType,
                                    pSDPOrigin->sdpConnectionInformation.addressType, pSDPOrigin->sdpConnectionInformation.connectionAddress);

        CHK(*ppOutputData == NULL || ((*pBufferSize - *pTotalWritten) >= currentWriteSize), STATUS_BUFFER_TOO_SMALL);
        *pTotalWritten += currentWriteSize;
        if (*ppOutputData != NULL) {
            *ppOutputData += currentWriteSize;
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.3
 *          s=<session name>
 * 
 * @param[in] sessionName
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeSessionName(PCHAR sessionName, PCHAR* ppOutputData, PUINT32 pTotalWritten, PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    if (sessionName[0] != '\0') {
        currentWriteSize = SNPRINTF(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                    SDP_SESSION_NAME_MARKER "%s" SDP_LINE_SEPARATOR, sessionName);

        CHK(*ppOutputData == NULL || ((*pBufferSize - *pTotalWritten) >= currentWriteSize), STATUS_BUFFER_TOO_SMALL);
        *pTotalWritten += currentWriteSize;
        if (*ppOutputData != NULL) {
            *ppOutputData += currentWriteSize;
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.9
 *        t=<start-time> <stop-time>
 *          These values are the decimal representation of Network Time Protocol (NTP) time values in seconds since 1900 [13].
 *      To convert these values to UNIX time, subtract decimal 2208988800.
 * 
 * @param[in] pSDPTimeDescription
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeTimeDescription(PSdpTimeDescription pSDPTimeDescription, PCHAR* ppOutputData, PUINT32 pTotalWritten, PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    currentWriteSize = SNPRINTF(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                SDP_TIME_DESCRIPTION_MARKER "%" PRIu64 " %" PRIu64 SDP_LINE_SEPARATOR, pSDPTimeDescription->startTime,
                                pSDPTimeDescription->stopTime);

    *pTotalWritten += currentWriteSize;
    if (*ppOutputData != NULL) {
        *ppOutputData += currentWriteSize;
    }

    LEAVES();
    return retStatus;
}

/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.13
 *          a=<attribute>
 *          a=<attribute>:<value>
 * 
 * @param[in] pSDPAttributes
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeAttribute(PSdpAttributes pSDPAttributes, PCHAR* ppOutputData, PUINT32 pTotalWritten, PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    if (pSDPAttributes->attributeValue[0] == '\0') {
        currentWriteSize = SNPRINTF(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                    SDP_ATTRIBUTE_MARKER "%s" SDP_LINE_SEPARATOR, pSDPAttributes->attributeName);
    } else {
        currentWriteSize = snprintf(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                    SDP_ATTRIBUTE_MARKER "%s:%s" SDP_LINE_SEPARATOR, pSDPAttributes->attributeName, pSDPAttributes->attributeValue);
    }

    *pTotalWritten += currentWriteSize;
    if (*ppOutputData != NULL) {
        *ppOutputData += currentWriteSize;
    }

    LEAVES();
    return retStatus;
}

/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.14
 *          m=<media> <port> <proto> <fmt> ...
 * 
 * @param[in] pMediaName
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeMediaName(PCHAR pMediaName, PCHAR* ppOutputData, PUINT32 pTotalWritten, PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    if (pMediaName[0] != '\0') {
        currentWriteSize = snprintf(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                    SDP_MEDIA_NAME_MARKER "%s" SDP_LINE_SEPARATOR, pMediaName);

        CHK(*ppOutputData == NULL || ((*pBufferSize - *pTotalWritten) >= currentWriteSize), STATUS_BUFFER_TOO_SMALL);
        *pTotalWritten += currentWriteSize;
        if (*ppOutputData != NULL) {
            *ppOutputData += currentWriteSize;
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}

/**
 * @brief https://tools.ietf.org/html/rfc4566#section-5.7
 *          c=<nettype> <addrtype> <connection-address>
 * 
 * @param[in] pSdpConnectionInformation
 * @param[out] ppOutputData the output buffer. this api will move the pointer to this buffer.
 * @param[out] pTotalWritten add the incremental size into this parameter.
 * @param[in] the size of this output buffer.
*/
STATUS serializeMediaConnectionInformation(PSdpConnectionInformation pSdpConnectionInformation, PCHAR* ppOutputData, PUINT32 pTotalWritten,
                                           PUINT32 pBufferSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 currentWriteSize = 0;

    if (pSdpConnectionInformation->networkType[0] != '\0') {
        currentWriteSize = SNPRINTF(*ppOutputData, (*ppOutputData) == NULL ? 0 : *pBufferSize - *pTotalWritten,
                                    SDP_CONNECTION_INFORMATION_MARKER "%s %s %s" SDP_LINE_SEPARATOR, pSdpConnectionInformation->networkType,
                                    pSdpConnectionInformation->addressType, pSdpConnectionInformation->connectionAddress);

        CHK(*ppOutputData == NULL || ((*pBufferSize - *pTotalWritten) >= currentWriteSize), STATUS_BUFFER_TOO_SMALL);
        *pTotalWritten += currentWriteSize;
        if (*ppOutputData != NULL) {
            *ppOutputData += currentWriteSize;
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief 
 * 
 * @param[in] pSessionDescription
 * @param[out] sdpBytes the output buffer.
 * @param[in/out] sdpBytesLength the buffer size. It will be used buffer size after this api.
*/
STATUS serializeSessionDescription(PSessionDescription pSessionDescription, PCHAR sdpBytes, PUINT32 sdpBytesLength)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR curr = sdpBytes;
    UINT32 i, j, bufferSize = 0;

    CHK(pSessionDescription != NULL && sdpBytesLength != NULL, STATUS_NULL_ARG);

    bufferSize = *sdpBytesLength;
    *sdpBytesLength = 0;

    CHK_STATUS(serializeVersion(pSessionDescription->version, &curr, sdpBytesLength, &bufferSize));
    CHK_STATUS(serializeOrigin(&pSessionDescription->sdpOrigin, &curr, sdpBytesLength, &bufferSize));
    CHK_STATUS(serializeSessionName(pSessionDescription->sessionName, &curr, sdpBytesLength, &bufferSize));
    for (i = 0; i < pSessionDescription->timeDescriptionCount; i++) {
        CHK_STATUS(serializeTimeDescription(&pSessionDescription->sdpTimeDescription[i], &curr, sdpBytesLength, &bufferSize));
    }
    for (i = 0; i < pSessionDescription->sessionAttributesCount; i++) {
        CHK_STATUS(serializeAttribute(&pSessionDescription->sdpAttributes[i], &curr, sdpBytesLength, &bufferSize));
    }

    for (i = 0; i < pSessionDescription->mediaCount; i++) {
        CHK_STATUS(serializeMediaName(pSessionDescription->mediaDescriptions[i].mediaName, &curr, sdpBytesLength, &bufferSize));
        CHK_STATUS(serializeMediaConnectionInformation(&(pSessionDescription->mediaDescriptions[i].sdpConnectionInformation), &curr, sdpBytesLength,
                                                       &bufferSize));
        for (j = 0; j < pSessionDescription->mediaDescriptions[i].mediaAttributesCount; j++) {
            CHK_STATUS(serializeAttribute(&pSessionDescription->mediaDescriptions[i].sdpAttributes[j], &curr, sdpBytesLength, &bufferSize));
        }
    }

    *sdpBytesLength += 1; // NULL terminator

CleanUp:
    LEAVES();
    return retStatus;
}
