#define LOG_CLASS "Stun"
#include "../Include_i.h"

STATUS stunPackageIpAddr(PStunHeader pStunHeader, STUN_ATTRIBUTE_TYPE type, PKvsIpAddress pAddress, PBYTE pBuffer, PUINT32 pDataLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 dataLen = 0;
    UINT16 size;
    PBYTE pCurBufPos = pBuffer;
    CHK(pDataLen != NULL && pAddress != NULL, STATUS_NULL_ARG);
    KvsIpAddress ipAddress;
    PKvsIpAddress pIndirected = pAddress;

    // Check if we are asked for size only and early return if so
    CHK(pAddress != NULL && pDataLen != NULL && pStunHeader != NULL, STATUS_NULL_ARG);

    /**
     * Mapped address attribute structure
     * https://tools.ietf.org/html/rfc5389#section-15.1
     * - 2 byte attribute type
     * - 2 byte attribute data len
     * - 2 byte address family
     * - 2 byte port
     * - 4 byte or 16 byte ip address
     */
    dataLen += STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_ADDRESS_HEADER_LEN;
    dataLen += IS_IPV4_ADDR(pIndirected) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH;

    // Check if we are asked for size only and early return if so
    CHK(pBuffer != NULL, STATUS_SUCCESS);

    // Check if a large enough buffer had been passed in
    CHK(*pDataLen >= dataLen, STATUS_NOT_ENOUGH_MEMORY);

    // Fix-up the address and port number for the XOR type
    // NOTE: We are not doing it in place to not "dirty" the original
    if (type == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS || type == STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS) {
        // Copy the struct forward so we can mutate
        ipAddress = *pAddress;

        CHK_STATUS(xorIpAddress(&ipAddress, pStunHeader->transactionId));

        pIndirected = &ipAddress;
    }

    size = (UINT16)(dataLen - STUN_ATTRIBUTE_HEADER_LEN);
    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, type, size);
    pCurBufPos += STUN_ATTRIBUTE_HEADER_LEN;

    putInt16((PINT16)(pCurBufPos), pIndirected->family);
    pCurBufPos += STUN_ATTRIBUTE_ADDRESS_FAMILY_LEN;

    // port is already in network byte order
    MEMCPY(pCurBufPos, (PBYTE) &pIndirected->port, SIZEOF(pIndirected->port));
    pCurBufPos += SIZEOF(pIndirected->port);

    MEMCPY(pCurBufPos, pIndirected->address, IS_IPV4_ADDR(pIndirected) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH);

CleanUp:

    if (STATUS_SUCCEEDED(retStatus) && pDataLen != NULL) {
        *pDataLen = dataLen;
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief 
 * 
 * @param[]
*/
STATUS serializeStunPacket(PStunPacket pStunPacket,
                           PBYTE password,
                           UINT32 passwordLen,
                           BOOL generateMessageIntegrity,
                           BOOL generateFingerprint,
                           PBYTE pBuffer,
                           PUINT32 pSize)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i, encodedLen = 0, packetSize = 0, remaining = 0, crc32, hmacLen;
    UINT16 size;
    PBYTE pCurBufPos = pBuffer;
    PStunAttributeHeader pStunAttrHdr;
    PStunAttributeAddress pStunAttrAddr;
    PStunAttributeUsername pStunAttrUsrName;
    PStunAttributePriority pStunAttrPri;
    PStunAttributeLifetime pStunAttrLifetime;
    PStunAttributeChangeRequest pStunAttrChangeReq;
    PStunAttributeRequestedTransport pStunAttrRequestedTransport;
    PStunAttributeRealm pStunAttrRealm;
    PStunAttributeNonce pStunAttrNonce;
    PStunAttributeErrorCode pStunAttrErrCode;
    PStunAttributeIceControl pStunAttrCtrl;
    PStunAttributeData pStunAttrData;
    PStunAttributeChannelNumber pStunAttrChNum;
    BOOL fingerprintFound = FALSE, messaageIntegrityFound = FALSE;
    INT64 data64;

    CHK(pStunPacket != NULL && (!generateMessageIntegrity || password != NULL) && pSize != NULL, STATUS_NULL_ARG);
    CHK(password == NULL || passwordLen != 0, STATUS_INVALID_ARG);
    CHK(pStunPacket->header.magicCookie == STUN_HEADER_MAGIC_COOKIE, STATUS_STUN_MAGIC_COOKIE_MISMATCH);

    packetSize += STUN_HEADER_LEN;
    if (pBuffer != NULL) {
        // If the buffer is specified then we use the length
        packetSize = *pSize;

        // Set the remaining size first
        remaining = packetSize;

        CHK(remaining >= STUN_HEADER_LEN, STATUS_NOT_ENOUGH_MEMORY);

        // Package the STUN packet header
        putInt16((PINT16)(pCurBufPos), pStunPacket->header.stunMessageType);
        pCurBufPos += STUN_HEADER_TYPE_LEN;

        // Skip the length - it will be added at the end
        pCurBufPos += STUN_HEADER_DATA_LEN;

        putInt32((PINT32) pCurBufPos, STUN_HEADER_MAGIC_COOKIE);
        pCurBufPos += STUN_HEADER_MAGIC_COOKIE_LEN;

        MEMCPY(pCurBufPos, pStunPacket->header.transactionId, STUN_HEADER_TRANSACTION_ID_LEN);
        pCurBufPos += STUN_HEADER_TRANSACTION_ID_LEN;

        remaining -= STUN_HEADER_LEN;
    }

    for (i = 0; i < pStunPacket->attributesCount; i++) {
        // Get the next attribute
        pStunAttrHdr = pStunPacket->attributeList[i];

        // Set the encoded length to zero before iteration
        encodedLen = 0;

        switch (pStunAttrHdr->type) {
            case STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_REFLECTED_FROM:
            case STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS:

                // Set the size before proceeding - this will get reset by the actual required size
                encodedLen = remaining;

                // TODO refactor this check, we have it for every attribute.
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                pStunAttrAddr = (PStunAttributeAddress) pStunAttrHdr;
                CHK_STATUS(stunPackageIpAddr(&pStunPacket->header, (STUN_ATTRIBUTE_TYPE) pStunAttrHdr->type, &pStunAttrAddr->address,
                                             pCurBufPos, &encodedLen));
                break;

            case STUN_ATTRIBUTE_TYPE_USERNAME:

                pStunAttrUsrName = (PStunAttributeUsername) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + pStunAttrUsrName->paddedLength;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the user name
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrUsrName + 1, pStunAttrUsrName->paddedLength);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_PRIORITY:

                pStunAttrPri = (PStunAttributePriority) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_PRIORITY_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the value
                    putInt32((PINT32)(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN), pStunAttrPri->priority);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
            case STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT:

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_LIFETIME:

                pStunAttrLifetime = (PStunAttributeLifetime) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_LIFETIME_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the value
                    putInt32((PINT32)(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN), pStunAttrLifetime->lifetime);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST:

                pStunAttrChangeReq = (PStunAttributeChangeRequest) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_CHANGE_REQUEST_FLAG_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the value
                    putInt32((PINT32)(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN), pStunAttrChangeReq->changeFlag);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT:

                pStunAttrRequestedTransport = (PStunAttributeRequestedTransport) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the value
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrRequestedTransport->protocol,
                           STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_REALM:

                pStunAttrRealm = (PStunAttributeRealm) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + pStunAttrRealm->paddedLength;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the realm
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrRealm->realm, pStunAttrRealm->paddedLength);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_NONCE:

                pStunAttrNonce = (PStunAttributeNonce) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + pStunAttrNonce->paddedLength;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the nonce
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrNonce->nonce, pStunAttrNonce->paddedLength);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_ERROR_CODE:

                pStunAttrErrCode = (PStunAttributeErrorCode) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + pStunAttrErrCode->paddedLength;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the error code
                    putInt16((PINT16) pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrErrCode->errorCode);

                    // Package the error phrase
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN + SIZEOF(pStunAttrErrCode->errorCode),
                           pStunAttrErrCode->errorPhrase, pStunAttrErrCode->paddedLength);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED:
            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING:

                pStunAttrCtrl = (PStunAttributeIceControl) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_ICE_CONTROL_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the value
                    MEMCPY(&data64, (PBYTE) pStunAttrCtrl + STUN_ATTRIBUTE_HEADER_LEN, SIZEOF(INT64));
                    putInt64(&data64, data64);
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, &data64, SIZEOF(INT64));
                }

                break;

            case STUN_ATTRIBUTE_TYPE_DATA:

                pStunAttrData = (PStunAttributeData) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + pStunAttrData->paddedLength;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the nonce
                    MEMCPY(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrData->data, pStunAttrData->paddedLength);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER:

                pStunAttrChNum = (PStunAttributeChannelNumber) pStunAttrHdr;

                encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_CHANNEL_NUMBER_LEN;

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                if (pBuffer != NULL) {
                    CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

                    // Package the message header first
                    PACKAGE_STUN_ATTR_HEADER(pCurBufPos, pStunAttrHdr->type, pStunAttrHdr->length);

                    // Package the value
                    putInt16((PINT16)(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN), pStunAttrChNum->channelNumber);

                    putInt16((PINT16)(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN + SIZEOF(INT16)), pStunAttrChNum->reserve);
                }

                break;

            case STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:

                // Validate that the integrity is the last one or comes before fingerprint and ignore the attribute
                CHK(i == pStunPacket->attributesCount - 1 || i == pStunPacket->attributesCount - 2, STATUS_STUN_MESSAGE_INTEGRITY_NOT_LAST);

                CHK(!messaageIntegrityFound, STATUS_STUN_MULTIPLE_MESSAGE_INTEGRITY_ATTRIBUTES);
                CHK(!fingerprintFound, STATUS_STUN_MESSAGE_INTEGRITY_AFTER_FINGERPRINT);

                messaageIntegrityFound = TRUE;
                break;

            case STUN_ATTRIBUTE_TYPE_FINGERPRINT:

                // Validate that the fingerprint is the last and ignore the attribute
                CHK(i == pStunPacket->attributesCount - 1, STATUS_STUN_FINGERPRINT_NOT_LAST);
                CHK(!fingerprintFound, STATUS_STUN_MULTIPLE_FINGERPRINT_ATTRIBUTES);

                fingerprintFound = TRUE;
                break;

            default:
                // Do nothing
                break;
        }

        if (pBuffer != NULL) {
            // Advance the current ptr needed
            pCurBufPos += encodedLen;

            // Decrement the remaining size
            remaining -= encodedLen;
        } else {
            // Increment the overall package size
            packetSize += encodedLen;
        }
    }

    // Check if we need to generate the message integrity attribute
    if (generateMessageIntegrity) {
        encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_HMAC_VALUE_LEN;

        if (pBuffer != NULL) {
            CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

            // Package the header first
            PACKAGE_STUN_ATTR_HEADER(pCurBufPos, STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY, STUN_HMAC_VALUE_LEN);

            // Fix-up the packet length with message integrity and without the STUN header
            size = (UINT16)(pCurBufPos + encodedLen - pBuffer - STUN_HEADER_LEN);
            putInt16((PINT16)(pBuffer + STUN_HEADER_TYPE_LEN), size);

            // The size of the message size in bytes should be a multiple of 64 per rfc
            // CHK((size & 0x003f) == 0, STATUS_WEBRTC_STUN_MESSAGE_INTEGRITY_SIZE_ALIGNMENT);

            // Calculate the HMAC for the integrity of the packet including STUN header and excluding the integrity attribute
            size = (UINT16)(pCurBufPos - pBuffer);
            KVS_SHA1_HMAC(password, (INT32) passwordLen, pBuffer, size, pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN, &hmacLen);

            // Advance the current position
            pCurBufPos += encodedLen;

            // Decrement the remaining size
            remaining -= encodedLen;
        } else {
            packetSize += encodedLen;
        }
    }

    // Check if we need to generate the fingerprint attribute
    if (generateFingerprint) {
        encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_FINGERPRINT_LEN;

        if (pBuffer != NULL) {
            CHK(remaining >= encodedLen, STATUS_NOT_ENOUGH_MEMORY);

            // Package the header first
            PACKAGE_STUN_ATTR_HEADER(pCurBufPos, STUN_ATTRIBUTE_TYPE_FINGERPRINT, STUN_ATTRIBUTE_FINGERPRINT_LEN);

            // Fix-up the packet length with message integrity and without the STUN header
            size = (UINT16)(pCurBufPos + encodedLen - pBuffer - STUN_HEADER_LEN);
            putInt16((PINT16)(pBuffer + STUN_HEADER_TYPE_LEN), size);

            // Calculate the fingerprint including STUN header and excluding the fingerprint attribute
            size = (UINT16)(pCurBufPos - pBuffer);

            crc32 = COMPUTE_CRC32(pBuffer, (UINT32) size) ^ STUN_FINGERPRINT_ATTRIBUTE_XOR_VALUE;

            // Write out the CRC value
            putInt32((PINT32)(pCurBufPos + STUN_ATTRIBUTE_HEADER_LEN), crc32);

            // Advance the current position
            pCurBufPos += encodedLen;

            // Decrement the remaining size
            remaining -= encodedLen;
        } else {
            packetSize += encodedLen;
        }
    }

    // Package the length if buffer is not NULL
    if (pBuffer != NULL) {
        encodedLen = (UINT16)(packetSize - STUN_HEADER_LEN);
        putInt16((PINT16)(pBuffer + STUN_HEADER_TYPE_LEN), (UINT16) encodedLen);
    }

    // Validate the overall size if buffer is specified
    CHK_ERR(pBuffer == NULL || packetSize == (UINT32)(pCurBufPos - pBuffer), STATUS_INTERNAL_ERROR,
            "Internal error: Invalid offset calculation.");

CleanUp:

    if (STATUS_SUCCEEDED(retStatus) && pSize != NULL) {
        *pSize = packetSize;
    }

    //LEAVES();
    return retStatus;
}

STATUS deserializeStunPacket(PBYTE pStunBuffer, UINT32 bufferSize, PBYTE password, UINT32 passwordLen, PStunPacket* ppStunPacket)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 attributeCount = 0, allocationSize, attributeSize, i = 0, j, magicCookie, hmacLen, crc32, data;
    UINT32 stunMagicCookie = STUN_HEADER_MAGIC_COOKIE;
    UINT16 size, paddedLength, ipFamily, messageLength;
    INT64 data64;
    PStunAttributeHeader pStunAttrHdr, pStunAttributes, pDestAttribute;
    PStunHeader pStunHeader = (PStunHeader) pStunBuffer;
    PStunPacket pStunPacket = NULL;
    StunAttributeHeader stunAttributeHeader;
    PStunAttributeAddress pStunAttrAddr;
    PStunAttributeUsername pStunAttrUsrName;
    PStunAttributeMessageIntegrity pStunAttributeMessageIntegrity;
    PStunAttributeFingerprint pStunAttributeFingerprint;
    PStunAttributePriority pStunAttrPri;
    PStunAttributeLifetime pStunAttrLifetime;
    PStunAttributeChangeRequest pStunAttrChangeReq;
    PStunAttributeRequestedTransport pStunAttrRequestedTransport;
    PStunAttributeRealm pStunAttrRealm;
    PStunAttributeNonce pStunAttrNonce;
    PStunAttributeErrorCode pStunAttrErrCode;
    PStunAttributeIceControl pStunAttrCtrl;
    PStunAttributeData pStunAttrData;
    PStunAttributeChannelNumber pStunAttrChNum;
    BOOL fingerprintFound = FALSE, messaageIntegrityFound = FALSE;
    PBYTE pData, pTransaction;

    CHK(pStunBuffer != NULL && ppStunPacket != NULL, STATUS_NULL_ARG);
    CHK(bufferSize >= STUN_HEADER_LEN, STATUS_INVALID_ARG);

    if (!isBigEndian()) {
        stunMagicCookie = STUN_HEADER_MAGIC_COOKIE_LE;
    }

    // Copy and fix-up the header
    messageLength = (UINT16) getInt16(*(PUINT16)((PBYTE) pStunHeader + STUN_HEADER_TYPE_LEN));
    magicCookie = (UINT32) getInt32(*(PUINT32)((PBYTE) pStunHeader + STUN_HEADER_TYPE_LEN + STUN_HEADER_DATA_LEN));

    // Validate the specified size
    CHK(bufferSize >= messageLength + STUN_HEADER_LEN, STATUS_INVALID_ARG);

    // Validate the magic cookie
    CHK(magicCookie == STUN_HEADER_MAGIC_COOKIE, STATUS_STUN_MAGIC_COOKIE_MISMATCH);

    // Calculate the required size by getting the number of attributes
    pStunAttributes = (PStunAttributeHeader)(pStunBuffer + STUN_HEADER_LEN);
    pStunAttrHdr = pStunAttributes;
    allocationSize = SIZEOF(StunPacket);
    while ((PBYTE) pStunAttrHdr < (PBYTE) pStunAttributes + messageLength) {
        // Copy/Swap tne attribute header
        stunAttributeHeader.type = (STUN_ATTRIBUTE_TYPE) getInt16(*(PUINT16) pStunAttrHdr);
        stunAttributeHeader.length = (UINT16) getInt16(*(PUINT16)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_TYPE_LEN));

        // Zero out for before iteration
        attributeSize = 0;

        // Calculate the padded size
        paddedLength = (UINT16) ROUND_UP(stunAttributeHeader.length, 4);

        // Check the type, get the allocation size and validate the length for each attribute
        switch (stunAttributeHeader.type) {
            case STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_REFLECTED_FROM:
            case STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS:
                attributeSize = SIZEOF(StunAttributeAddress);

                // Cast, swap and get the size
                pStunAttrAddr = (PStunAttributeAddress) pStunAttrHdr;
                ipFamily = (UINT16) getInt16(pStunAttrAddr->address.family) & (UINT16) 0x00ff;

                // Address family and the port
                size = STUN_ATTRIBUTE_ADDRESS_HEADER_LEN + ((ipFamily == KVS_IP_FAMILY_TYPE_IPV4) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH);

                CHK(stunAttributeHeader.length == size, STATUS_STUN_INVALID_ADDRESS_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);
                break;

            case STUN_ATTRIBUTE_TYPE_USERNAME:
                attributeSize = SIZEOF(StunAttributeUsername);

                // Validate the size of the length against the max value of username
                CHK(stunAttributeHeader.length <= STUN_MAX_USERNAME_LEN, STATUS_STUN_INVALID_USERNAME_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                // Add the length of the string itself
                attributeSize += paddedLength;
                break;

            case STUN_ATTRIBUTE_TYPE_PRIORITY:
                attributeSize = SIZEOF(StunAttributePriority);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_PRIORITY_LEN, STATUS_STUN_INVALID_PRIORITY_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
            case STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT:
                attributeSize = SIZEOF(StunAttributeFlag);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_FLAG_LEN, STATUS_STUN_INVALID_USE_CANDIDATE_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_LIFETIME:
                attributeSize = SIZEOF(StunAttributeLifetime);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_LIFETIME_LEN, STATUS_STUN_INVALID_LIFETIME_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST:
                attributeSize = SIZEOF(StunAttributeChangeRequest);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_CHANGE_REQUEST_FLAG_LEN, STATUS_STUN_INVALID_CHANGE_REQUEST_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT:
                attributeSize = SIZEOF(StunAttributeRequestedTransport);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN,
                    STATUS_STUN_INVALID_REQUESTED_TRANSPORT_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_REALM:
                attributeSize = SIZEOF(StunAttributeRealm);

                // Validate the size of the length against the max value of realm
                CHK(stunAttributeHeader.length <= STUN_MAX_REALM_LEN, STATUS_STUN_INVALID_REALM_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                // Add the length of the string itself
                attributeSize += paddedLength;
                break;

            case STUN_ATTRIBUTE_TYPE_NONCE:
                attributeSize = SIZEOF(StunAttributeNonce);

                // Validate the size of the length against the max value of nonce
                CHK(stunAttributeHeader.length <= STUN_MAX_NONCE_LEN, STATUS_STUN_INVALID_NONCE_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                // Add the length of the string itself
                attributeSize += paddedLength;
                break;

            case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
                attributeSize = SIZEOF(StunAttributeErrorCode);

                // Validate the size of the length against the max value of error phrase
                CHK(stunAttributeHeader.length <= STUN_MAX_ERROR_PHRASE_LEN, STATUS_STUN_INVALID_ERROR_CODE_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                // Add the length of the string itself
                attributeSize += paddedLength;
                break;

            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED:
            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING:
                attributeSize = SIZEOF(StunAttributeIceControl);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_ICE_CONTROL_LEN, STATUS_STUN_INVALID_ICE_CONTROL_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_DATA:
                attributeSize = SIZEOF(StunAttributeData);

                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                // Add the length of the data itself
                attributeSize += paddedLength;
                break;

            case STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER:
                attributeSize = SIZEOF(StunAttributeChannelNumber);

                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_CHANNEL_NUMBER_LEN, STATUS_STUN_INVALID_CHANNEL_NUMBER_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

                break;

            case STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:
                attributeSize = SIZEOF(StunAttributeMessageIntegrity);
                CHK(stunAttributeHeader.length == STUN_HMAC_VALUE_LEN, STATUS_STUN_INVALID_MESSAGE_INTEGRITY_ATTRIBUTE_LENGTH);
                CHK(!messaageIntegrityFound, STATUS_STUN_MULTIPLE_MESSAGE_INTEGRITY_ATTRIBUTES);
                CHK(!fingerprintFound, STATUS_STUN_MESSAGE_INTEGRITY_AFTER_FINGERPRINT);
                messaageIntegrityFound = TRUE;
                break;

            case STUN_ATTRIBUTE_TYPE_FINGERPRINT:
                attributeSize = SIZEOF(StunAttributeFingerprint);
                CHK(stunAttributeHeader.length == STUN_ATTRIBUTE_FINGERPRINT_LEN, STATUS_STUN_INVALID_FINGERPRINT_ATTRIBUTE_LENGTH);
                CHK(!fingerprintFound, STATUS_STUN_MULTIPLE_FINGERPRINT_ATTRIBUTES);
                fingerprintFound = TRUE;
                break;

            default:
                // Do nothing - skip and decrement the count as it will be incremented below anyway
                attributeCount--;
                break;
        }

        allocationSize += attributeSize;
        attributeCount++;

        CHK(attributeCount <= STUN_ATTRIBUTE_MAX_COUNT, STATUS_STUN_MAX_ATTRIBUTE_COUNT);

        // Increment the attributes pointer and account for the length
        pStunAttrHdr = (PStunAttributeHeader)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + paddedLength);
    }

    // Account for the attribute pointer array
    allocationSize += attributeCount * SIZEOF(PStunAttributeHeader);

    // Allocate the necessary storage and set the pointers for the attributes
    CHK(NULL != (pStunPacket = MEMCALLOC(1, allocationSize)), STATUS_NOT_ENOUGH_MEMORY);

    // Copy/swap the header
    pStunPacket->header.stunMessageType = (UINT16) getInt16(pStunHeader->stunMessageType);
    pStunPacket->header.messageLength = messageLength;
    pStunPacket->header.magicCookie = magicCookie;
    MEMCPY(pStunPacket->header.transactionId, pStunHeader->transactionId, STUN_TRANSACTION_ID_LEN);

    // Store the actual allocation size
    pStunPacket->allocationSize = allocationSize;

    // Set the attribute array pointer
    pStunPacket->attributeList = (PStunAttributeHeader*) (pStunPacket + 1);

    // Set the count of the processed attributes only
    pStunPacket->attributesCount = attributeCount;

    // Set the attribute buffer start
    pDestAttribute = (PStunAttributeHeader)(pStunPacket->attributeList + attributeCount);

    // Reset the attributes to go over the array and convert
    pStunAttrHdr = pStunAttributes;

    // Start packaging the attributes
    while (((PBYTE) pStunAttrHdr < (PBYTE) pStunAttributes + pStunPacket->header.messageLength) && i < attributeCount) {
        // Set the array entry first
        pStunPacket->attributeList[i++] = pDestAttribute;

        // Copy/Swap tne attribute header
        pDestAttribute->type = (STUN_ATTRIBUTE_TYPE) getInt16(pStunAttrHdr->type);
        pDestAttribute->length = (UINT16) getInt16(pStunAttrHdr->length);

        // Zero out for before iteration
        attributeSize = 0;

        // Calculate the padded size
        paddedLength = (UINT16) ROUND_UP(pDestAttribute->length, 4);

        switch (pDestAttribute->type) {
            case STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_REFLECTED_FROM:
            case STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS:
            case STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS:
                pStunAttrAddr = (PStunAttributeAddress) pDestAttribute;

                // Copy the entire structure and swap
                MEMCPY(&pStunAttrAddr->address, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN,
                       pStunAttrAddr->attribute.length);
                pStunAttrAddr->address.family = (UINT16) getInt16(pStunAttrAddr->address.family) & (UINT16) 0x00ff;
                attributeSize = SIZEOF(StunAttributeAddress);

                // Special handling for the XOR mapped address
                if (pStunAttrAddr->attribute.type == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS ||
                    pStunAttrAddr->attribute.type == STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS) {
                    // XOR the port with high-bits of the magic cookie
                    pStunAttrAddr->address.port ^= (UINT16) stunMagicCookie;

                    // Perform the XOR-ing
                    data = *(PUINT32) pStunAttrAddr->address.address;
                    data ^= stunMagicCookie;
                    *(PUINT32) pStunAttrAddr->address.address = data;

                    if (pStunAttrAddr->address.family == KVS_IP_FAMILY_TYPE_IPV6) {
                        // Process the rest of 12 bytes for IPv6
                        pData = &pStunAttrAddr->address.address[SIZEOF(UINT32)];
                        pTransaction = pStunPacket->header.transactionId;
                        for (j = 0; j < STUN_TRANSACTION_ID_LEN; j++) {
                            *pData++ ^= *pTransaction++;
                        }
                    }
                }

                break;

            case STUN_ATTRIBUTE_TYPE_USERNAME:
                pStunAttrUsrName = (PStunAttributeUsername) pDestAttribute;

                // Set the padded length
                pStunAttrUsrName->paddedLength = paddedLength;

                // Set the pointer following the structure
                pStunAttrUsrName->userName = (PCHAR)(pStunAttrUsrName + 1);

                // Copy the padded user name
                MEMCPY(pStunAttrUsrName->userName, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN,
                       pStunAttrUsrName->paddedLength);
                attributeSize = SIZEOF(StunAttributeUsername) + pStunAttrUsrName->paddedLength;

                break;

            case STUN_ATTRIBUTE_TYPE_PRIORITY:
                pStunAttrPri = (PStunAttributePriority) pDestAttribute;

                pStunAttrPri->priority = (UINT32) getInt32(*(PUINT32)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN));

                attributeSize = SIZEOF(StunAttributePriority);

                break;

            case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
            case STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT:
                attributeSize = SIZEOF(StunAttributeFlag);

                break;

            case STUN_ATTRIBUTE_TYPE_LIFETIME:
                pStunAttrLifetime = (PStunAttributeLifetime) pDestAttribute;

                pStunAttrLifetime->lifetime = (UINT32) getInt32(*(PUINT32)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN));

                attributeSize = SIZEOF(StunAttributeLifetime);

                break;

            case STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST:
                pStunAttrChangeReq = (PStunAttributeChangeRequest) pDestAttribute;

                pStunAttrChangeReq->changeFlag = (UINT32) getInt32(*(PUINT32)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN));

                attributeSize = SIZEOF(StunAttributeChangeRequest);

                break;

            case STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT:
                pStunAttrRequestedTransport = (PStunAttributeRequestedTransport) pDestAttribute;

                MEMCPY(pStunAttrRequestedTransport->protocol, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN,
                       STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN);

                attributeSize = SIZEOF(StunAttributeRequestedTransport);

                break;

            case STUN_ATTRIBUTE_TYPE_REALM:
                pStunAttrRealm = (PStunAttributeRealm) pDestAttribute;

                // Set the padded length
                pStunAttrRealm->paddedLength = paddedLength;

                // Set the pointer following the structure
                pStunAttrRealm->realm = (PCHAR)(pStunAttrRealm + 1);

                // Copy the padded realm
                MEMCPY(pStunAttrRealm->realm, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrRealm->paddedLength);
                attributeSize = SIZEOF(StunAttributeRealm) + pStunAttrRealm->paddedLength;

                break;

            case STUN_ATTRIBUTE_TYPE_NONCE:
                pStunAttrNonce = (PStunAttributeNonce) pDestAttribute;

                // Set the padded length
                pStunAttrNonce->paddedLength = paddedLength;

                // Set the pointer following the structure
                pStunAttrNonce->nonce = (PBYTE)(pStunAttrNonce + 1);

                // Copy the padded nonce
                MEMCPY(pStunAttrNonce->nonce, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrNonce->paddedLength);
                attributeSize = SIZEOF(StunAttributeNonce) + pStunAttrNonce->paddedLength;

                break;

            case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
                pStunAttrErrCode = (PStunAttributeErrorCode) pDestAttribute;

                // Set the padded length
                pStunAttrErrCode->paddedLength = paddedLength;

                // swap the error code
                pStunAttrErrCode->errorCode =
                    GET_STUN_ERROR_CODE(((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + STUN_ERROR_CODE_PACKET_ERROR_CLASS_OFFSET),
                                        ((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + STUN_ERROR_CODE_PACKET_ERROR_CODE_OFFSET));

                // Set the pointer following the structure
                pStunAttrErrCode->errorPhrase = (PCHAR)(pStunAttrErrCode + 1);

                // Copy the padded error phrase
                MEMCPY(pStunAttrErrCode->errorPhrase,
                       ((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET),
                       pStunAttrErrCode->paddedLength - STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET);
                attributeSize = SIZEOF(StunAttributeErrorCode) + pStunAttrErrCode->paddedLength;

                break;

            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED:
            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING:
                pStunAttrCtrl = (PStunAttributeIceControl) pDestAttribute;

                // Deal with the alignment
                MEMCPY(&data64, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN, SIZEOF(INT64));
                data64 = (INT64) getInt64(data64);

                // Swap the bits
                MEMCPY((PBYTE) pStunAttrCtrl + SIZEOF(StunAttributeIceControl) - SIZEOF(UINT64), &data64, SIZEOF(INT64));

                attributeSize = SIZEOF(StunAttributeIceControl);

                break;

            case STUN_ATTRIBUTE_TYPE_DATA:
                pStunAttrData = (PStunAttributeData) pDestAttribute;

                // Set the padded length
                pStunAttrData->paddedLength = paddedLength;

                // Set the pointer following the structure
                pStunAttrData->data = (PBYTE)(pStunAttrData + 1);

                // Copy the padded nonce
                MEMCPY(pStunAttrData->data, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN, pStunAttrData->paddedLength);
                attributeSize = SIZEOF(StunAttributeData) + pStunAttrData->paddedLength;

                break;

            case STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER:
                pStunAttrChNum = (PStunAttributeChannelNumber) pDestAttribute;

                pStunAttrChNum->channelNumber = (UINT16) getInt16(*(PUINT16)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN));

                pStunAttrChNum->reserve = 0;

                attributeSize = SIZEOF(StunAttributeChannelNumber);

                break;

            case STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:
                CHK(password != NULL, STATUS_NULL_ARG);
                CHK(passwordLen != 0, STATUS_INVALID_ARG);

                pStunAttributeMessageIntegrity = (PStunAttributeMessageIntegrity) pDestAttribute;

                // Copy the message integrity
                attributeSize = SIZEOF(StunAttributeMessageIntegrity);

                // Validate the HMAC
                // Fix-up the packet length
                size = (UINT16)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + STUN_HMAC_VALUE_LEN - pStunBuffer - STUN_HEADER_LEN);
                putInt16((PINT16)(pStunBuffer + STUN_HEADER_TYPE_LEN), size);

                // The size of the message size in bytes should be a multiple of 64 per rfc
                // CHK((size & 0x003f) == 0, STATUS_WEBRTC_STUN_MESSAGE_INTEGRITY_SIZE_ALIGNMENT);

                // Calculate the HMAC for the integrity of the packet including STUN header and excluding the integrity attribute
                size = (UINT16)((PBYTE) pStunAttrHdr - pStunBuffer);
                KVS_SHA1_HMAC(password, (INT32) passwordLen, pStunBuffer, size, pStunAttributeMessageIntegrity->messageIntegrity, &hmacLen);

                // Reset the original size in the buffer
                putInt16((PINT16)(pStunBuffer + STUN_HEADER_TYPE_LEN), pStunPacket->header.messageLength);

                // Validate the HMAC
                CHK(0 ==
                        MEMCMP(pStunAttributeMessageIntegrity->messageIntegrity, (PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN,
                               STUN_HMAC_VALUE_LEN),
                    STATUS_STUN_MESSAGE_INTEGRITY_MISMATCH);

                break;

            case STUN_ATTRIBUTE_TYPE_FINGERPRINT:
                pStunAttributeFingerprint = (PStunAttributeFingerprint) pDestAttribute;

                // Copy the use fingerprint value
                pStunAttributeFingerprint->crc32Fingerprint = (UINT32) getInt32(*(PUINT32)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN));
                attributeSize = SIZEOF(StunAttributeFingerprint);

                // Validate the Fingerprint
                // Fix-up the packet length
                size = (UINT16)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_FINGERPRINT_LEN - pStunBuffer -
                                STUN_HEADER_LEN);
                putInt16((PINT16)(pStunBuffer + STUN_HEADER_TYPE_LEN), size);

                // Calculate the fingerprint
                size = (UINT16)((PBYTE) pStunAttrHdr - pStunBuffer);

                crc32 = COMPUTE_CRC32(pStunBuffer, (UINT32) size) ^ STUN_FINGERPRINT_ATTRIBUTE_XOR_VALUE;

                // Reset the original size in the buffer
                putInt16((PINT16)(pStunBuffer + STUN_HEADER_TYPE_LEN), pStunPacket->header.messageLength);

                // Validate the fingerprint
                CHK(crc32 == pStunAttributeFingerprint->crc32Fingerprint, STATUS_STUN_FINGERPRINT_MISMATCH);

                break;

            default:
                // Skip over the unknown attributes
                break;
        }

        // Increment the attributes pointer and account for the length
        pStunAttrHdr = (PStunAttributeHeader)((PBYTE) pStunAttrHdr + STUN_ATTRIBUTE_HEADER_LEN + paddedLength);

        // Set the destination
        pDestAttribute = (PStunAttributeHeader)((PBYTE) pDestAttribute + attributeSize);
    }

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeStunPacket(&pStunPacket);
    }

    if (ppStunPacket != NULL) {
        *ppStunPacket = pStunPacket;
    }

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

STATUS freeStunPacket(PStunPacket* ppStunPacket)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(ppStunPacket != NULL, STATUS_NULL_ARG);

    SAFE_MEMFREE(*ppStunPacket);

CleanUp:

    //LEAVES();
    return retStatus;
}
/**
 * @brief create one stun packet according to the stun message type.
 * 
 * @param[in] stunPacketType stun message type.
 * @param[in] transactionId the transactino id. set it randonly if it is null.
 * @param[out] return the buffer pointer of this stun packet.
*/
STATUS createStunPacket(STUN_PACKET_TYPE stunPacketType, PBYTE transactionId, PStunPacket* ppStunPacket)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    PStunPacket pStunPacket = NULL;

    CHK(ppStunPacket != NULL, STATUS_NULL_ARG);
    /** #memory, the default size of stun packet is 2kB.*/
    CHK(NULL != (pStunPacket = (PStunPacket) MEMCALLOC(1, STUN_PACKET_ALLOCATION_SIZE)), STATUS_NOT_ENOUGH_MEMORY);
    pStunPacket->attributesCount = 0;
    pStunPacket->header.messageLength = 0;
    pStunPacket->header.magicCookie = STUN_HEADER_MAGIC_COOKIE;
    pStunPacket->header.stunMessageType = stunPacketType;

    // Generate the transaction id if none is specified
    if (transactionId == NULL) {
        for (i = 0; i < STUN_TRANSACTION_ID_LEN; i++) {
            pStunPacket->header.transactionId[i] = (BYTE)(RAND() % 0xFF);
        }
    } else {
        MEMCPY(pStunPacket->header.transactionId, transactionId, STUN_TRANSACTION_ID_LEN);
    }

    // Set the address - calloc should have NULL-ified the actual pointers
    pStunPacket->attributeList = (PStunAttributeHeader*) (pStunPacket + 1);

    // Store the actual allocation size
    pStunPacket->allocationSize = STUN_PACKET_ALLOCATION_SIZE;

    *ppStunPacket = pStunPacket;

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeStunPacket(&pStunPacket);
    }

    if (ppStunPacket != NULL) {
        *ppStunPacket = pStunPacket;
    }

    //LEAVES();
    return retStatus;
}

STATUS appendStunAddressAttribute(PStunPacket pStunPacket, STUN_ATTRIBUTE_TYPE addressAttributeType, PKvsIpAddress pAddress)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeAddress pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK(pAddress != NULL, STATUS_NULL_ARG);
    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeAddress) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeAddress), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_ADDRESS_HEADER_LEN + (IS_IPV4_ADDR(pAddress) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH);
    pAttribute->attribute.type = addressAttributeType;

    // Copy the attribute entirely
    pAttribute->address = *pAddress;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunUsernameAttribute(PStunPacket pStunPacket, PCHAR userName)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeUsername pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;
    UINT16 length, paddedLength;

    CHK(userName != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeUsername) pAttributeHeader;

    length = (UINT16) STRNLEN(userName, STUN_MAX_USERNAME_LEN);
    paddedLength = (UINT16) ROUND_UP(length, 4);

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(paddedLength + SIZEOF(StunAttributeUsername), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = length;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_USERNAME;

    // Set the padded length
    pAttribute->paddedLength = paddedLength;

    // Set the pointer following the structure
    pAttribute->userName = (PCHAR)(pAttribute + 1);

    MEMCPY(pAttribute->userName, userName, length * SIZEOF(CHAR));

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    CHK_LOG_ERR(retStatus);

    //LEAVES();
    return retStatus;
}

STATUS getStunAttribute(PStunPacket pStunPacket, STUN_ATTRIBUTE_TYPE attributeType, PStunAttributeHeader* ppStunAttribute)
{
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeHeader pTargetAttribute = NULL;
    UINT32 i;

    CHK(pStunPacket != NULL && ppStunAttribute != NULL, STATUS_NULL_ARG);

    for (i = 0; i < pStunPacket->attributesCount && pTargetAttribute == NULL; ++i) {
        if (pStunPacket->attributeList[i]->type == attributeType) {
            pTargetAttribute = pStunPacket->attributeList[i];
        }
    }

CleanUp:

    if (ppStunAttribute != NULL) {
        *ppStunAttribute = pTargetAttribute;
    }

    return retStatus;
}

STATUS xorIpAddress(PKvsIpAddress pAddress, PBYTE pTransactionId)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 data;
    PBYTE pData;
    UINT32 i;

    CHK(pAddress != NULL, STATUS_NULL_ARG);
    CHK(IS_IPV4_ADDR(pAddress) || pTransactionId != NULL, STATUS_INVALID_ARG);

    // Perform the XOR-ing
    pAddress->port = (UINT16)(getInt16(STUN_HEADER_MAGIC_COOKIE >> 16)) ^ pAddress->port;

    data = (UINT32) getInt32(*(PINT32) pAddress->address);
    data ^= STUN_HEADER_MAGIC_COOKIE;
    putInt32((PINT32) pAddress->address, data);

    if (pAddress->family == KVS_IP_FAMILY_TYPE_IPV6) {
        // Process the rest of 12 bytes
        pData = &pAddress->address[SIZEOF(UINT32)];
        for (i = 0; i < STUN_TRANSACTION_ID_LEN; i++) {
            *pData++ ^= *pTransactionId++;
        }
    }

CleanUp:

    return retStatus;
}

STATUS appendStunPriorityAttribute(PStunPacket pStunPacket, UINT32 priority)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributePriority pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributePriority) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributePriority), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_PRIORITY_LEN;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_PRIORITY;

    // Set the priority
    pAttribute->priority = priority;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunFlagAttribute(PStunPacket pStunPacket, STUN_ATTRIBUTE_TYPE attrType)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeFlag pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeFlag) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeFlag), 8), STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_FLAG_LEN;
    pAttribute->attribute.type = attrType;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunLifetimeAttribute(PStunPacket pStunPacket, UINT32 lifetime)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeLifetime pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeLifetime) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeLifetime), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_LIFETIME_LEN;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_LIFETIME;

    // Set the lifetime
    pAttribute->lifetime = lifetime;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunChangeRequestAttribute(PStunPacket pStunPacket, UINT32 changeFlag)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeChangeRequest pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeChangeRequest) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeChangeRequest), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_CHANGE_REQUEST_FLAG_LEN;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST;

    // Set the change flag
    pAttribute->changeFlag = changeFlag;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunRequestedTransportAttribute(PStunPacket pStunPacket, UINT8 protocol)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeRequestedTransport pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeRequestedTransport) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeRequestedTransport), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT;

    // Set the protocol
    MEMSET(pAttribute->protocol, 0x00, STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN);
    *pAttribute->protocol = (BYTE) protocol;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunRealmAttribute(PStunPacket pStunPacket, PCHAR realm)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeRealm pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;
    UINT16 length, paddedLength;

    CHK(realm != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeRealm) pAttributeHeader;

    length = (UINT16) STRNLEN(realm, STUN_MAX_REALM_LEN);
    paddedLength = (UINT16) ROUND_UP(length, 4);

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(paddedLength + SIZEOF(StunAttributeRealm), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = length;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_REALM;

    // Set the padded length
    pAttribute->paddedLength = paddedLength;

    // Set the pointer following the structure
    pAttribute->realm = (PCHAR)(pAttribute + 1);

    MEMCPY(pAttribute->realm, realm, length * SIZEOF(CHAR));

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS appendStunNonceAttribute(PStunPacket pStunPacket, PBYTE nonce, UINT16 nonceLen)
{
    //ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeNonce pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;
    UINT16 paddedLength;

    CHK(nonce != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeNonce) pAttributeHeader;

    paddedLength = (UINT16) ROUND_UP(nonceLen, 4);

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(paddedLength + SIZEOF(StunAttributeNonce), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = nonceLen;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_NONCE;

    // Set the padded length
    pAttribute->paddedLength = paddedLength;

    // Set the pointer following the structure
    pAttribute->nonce = (PBYTE)(pAttribute + 1);

    MEMCPY(pAttribute->nonce, nonce, nonceLen);

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    //LEAVES();
    return retStatus;
}

STATUS updateStunNonceAttribute(PStunPacket pStunPacket, PBYTE nonce, UINT16 nonceLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeNonce pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK(pStunPacket != NULL && nonce != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_NONCE, &pAttributeHeader));
    // do nothing if nonce attribute not found
    CHK(pAttributeHeader != NULL, retStatus);

    pAttribute = (PStunAttributeNonce) pAttributeHeader;

    // not expecting nonce length to change while streaming
    CHK_WARN(pAttributeHeader->length == nonceLen, STATUS_INVALID_ARG, "Nonce length should not change");

    MEMCPY(pAttribute->nonce, nonce, nonceLen);

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

STATUS appendStunErrorCodeAttribute(PStunPacket pStunPacket, PCHAR errorPhrase, UINT16 errorCode)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeErrorCode pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;
    UINT16 length, paddedLength;

    CHK(errorPhrase != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeErrorCode) pAttributeHeader;

    length = (UINT16) STRNLEN(errorPhrase, STUN_MAX_ERROR_PHRASE_LEN);
    paddedLength = (UINT16) ROUND_UP(length, 4);

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(paddedLength + SIZEOF(StunAttributeErrorCode), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = length;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_ERROR_CODE;

    // Set the padded length
    pAttribute->paddedLength = paddedLength;

    pAttribute->errorCode = errorCode;

    // Set the pointer following the structure
    pAttribute->errorPhrase = (PCHAR)(pAttribute + 1);

    MEMCPY(pAttribute->errorPhrase, errorPhrase, length * SIZEOF(CHAR));

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS appendStunIceControllAttribute(PStunPacket pStunPacket, STUN_ATTRIBUTE_TYPE attributeType, UINT64 tieBreaker)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeIceControl pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK(attributeType == STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING || attributeType == STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED, STATUS_INVALID_ARG);

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeIceControl) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeIceControl), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_ICE_CONTROL_LEN;
    pAttribute->attribute.type = attributeType;

    // Set the tiebreaker
    MEMCPY((PBYTE) pAttribute + STUN_ATTRIBUTE_HEADER_LEN, &tieBreaker, SIZEOF(UINT64));

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS appendStunDataAttribute(PStunPacket pStunPacket, PBYTE data, UINT16 dataLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeData pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;
    UINT16 paddedLength;

    CHK(data != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeData) pAttributeHeader;

    paddedLength = (UINT16) ROUND_UP(dataLen, 4);

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(paddedLength + SIZEOF(StunAttributeData), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = dataLen;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_DATA;

    // Set the padded length
    pAttribute->paddedLength = paddedLength;

    // Set the pointer following the structure
    pAttribute->data = (PBYTE)(pAttribute + 1);

    MEMCPY(pAttribute->data, data, dataLen);

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS appendStunChannelNumberAttribute(PStunPacket pStunPacket, UINT16 channelNumber)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeChannelNumber pAttribute = NULL;
    PStunAttributeHeader pAttributeHeader = NULL;

    CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
    pAttribute = (PStunAttributeChannelNumber) pAttributeHeader;

    // Validate the overall size
    CHK((PBYTE) pStunPacket + pStunPacket->allocationSize >= (PBYTE) pAttribute + ROUND_UP(SIZEOF(StunAttributeChannelNumber), 8),
        STATUS_NOT_ENOUGH_MEMORY);

    // Set up the new entry and copy data over
    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pAttribute;

    pAttribute->attribute.length = STUN_ATTRIBUTE_CHANNEL_NUMBER_LEN;
    pAttribute->attribute.type = STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER;

    // Set the channel number and reserve
    pAttribute->channelNumber = channelNumber;
    pAttribute->reserve = 0;

    // Fix-up the STUN header message length
    pStunPacket->header.messageLength += pAttribute->attribute.length + STUN_ATTRIBUTE_HEADER_LEN;

CleanUp:

    LEAVES();
    return retStatus;
}

UINT16 getPackagedStunAttributeSize(PStunAttributeHeader pStunAttrHdr)
{
    UINT16 length;

    switch (pStunAttrHdr->type) {
        case STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS:
        case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
        case STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS:
        case STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS:
        case STUN_ATTRIBUTE_TYPE_REFLECTED_FROM:
        case STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS:
        case STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS:
            length = SIZEOF(StunAttributeAddress);
            break;
        case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
        case STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT:
            length = SIZEOF(StunAttributeFlag);
            break;
        case STUN_ATTRIBUTE_TYPE_PRIORITY:
            length = SIZEOF(StunAttributePriority);
            break;
        case STUN_ATTRIBUTE_TYPE_LIFETIME:
            length = SIZEOF(StunAttributeLifetime);
            break;
        case STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST:
            length = SIZEOF(StunAttributeChangeRequest);
            break;
        case STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT:
            length = SIZEOF(StunAttributeRequestedTransport);
            break;
        case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED:
        case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING:
            length = SIZEOF(StunAttributeIceControl);
            break;
        case STUN_ATTRIBUTE_TYPE_REALM:
            length = SIZEOF(StunAttributeRealm) + ((PStunAttributeRealm) pStunAttrHdr)->paddedLength;
            break;
        case STUN_ATTRIBUTE_TYPE_NONCE:
            length = SIZEOF(StunAttributeNonce) + ((PStunAttributeNonce) pStunAttrHdr)->paddedLength;
            break;
        case STUN_ATTRIBUTE_TYPE_DATA:
            length = SIZEOF(StunAttributeData) + ((PStunAttributeData) pStunAttrHdr)->paddedLength;
            break;
        case STUN_ATTRIBUTE_TYPE_USERNAME:
            length = SIZEOF(StunAttributeUsername) + ((PStunAttributeUsername) pStunAttrHdr)->paddedLength;
            break;
        case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
            length = SIZEOF(StunAttributeErrorCode) + ((PStunAttributeErrorCode) pStunAttrHdr)->paddedLength;
            break;
        case STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER:
            length = SIZEOF(StunAttributeChannelNumber);
            break;
        default:
            length = STUN_ATTRIBUTE_HEADER_LEN + pStunAttrHdr->length;
    }

    return (UINT16) ROUND_UP(length, 8);
}

STATUS getFirstAvailableStunAttribute(PStunPacket pStunPacket, PStunAttributeHeader* ppStunAttribute)
{
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributeHeader pAttribute = NULL;

    CHK(pStunPacket != NULL && ppStunAttribute != NULL, STATUS_NULL_ARG);
    CHK(pStunPacket->attributesCount <= STUN_ATTRIBUTE_MAX_COUNT, STATUS_STUN_MAX_ATTRIBUTE_COUNT);

    if (pStunPacket->attributesCount != 0) {
        // Get the next address pointer
        pAttribute = pStunPacket->attributeList[pStunPacket->attributesCount - 1];

        // Validate if we have a terminal attribute
        CHK(pAttribute->type != STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY && pAttribute->type != STUN_ATTRIBUTE_TYPE_FINGERPRINT,
            STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

        // Calculate the first available address
        pAttribute = (PStunAttributeHeader)(((PBYTE) pAttribute) + getPackagedStunAttributeSize(pAttribute));

        // Validate we are still within the allocation
        CHK((PBYTE) pStunPacket + pStunPacket->allocationSize > (PBYTE) pAttribute, STATUS_NOT_ENOUGH_MEMORY);
    } else {
        // Set the attribute to the first one
        pAttribute = (PStunAttributeHeader)(pStunPacket->attributeList + STUN_ATTRIBUTE_MAX_COUNT);
    }

    *ppStunAttribute = pAttribute;

CleanUp:

    LEAVES();
    return retStatus;
}
