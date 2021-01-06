/**
 * Kinesis Video Producer Ice Utils
 */
#define LOG_CLASS "IceUtils"
#include "../Include_i.h"



/**
 * @brief create the buffer recording the transaction id. 
 *          For current design, ice agent, ice candidate pair, and turn will create one transaction id buffer.
 * 
 * @param[in] maxIdCount the maximum number of transaction id.
 * @param[out] ppTransactionIdStore the pointer of buffer.
*/
STATUS createTransactionIdStore(UINT32 maxIdCount, PTransactionIdStore* ppTransactionIdStore)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTransactionIdStore pTransactionIdStore = NULL;

    CHK(ppTransactionIdStore != NULL, STATUS_ICE_NULL_ARG);
    CHK(maxIdCount < MAX_STORED_TRANSACTION_ID_COUNT && maxIdCount > 0, STATUS_ICE_NULL_ARG);

    pTransactionIdStore = (PTransactionIdStore) MEMCALLOC(1, SIZEOF(TransactionIdStore) + STUN_TRANSACTION_ID_LEN * maxIdCount);
    CHK(pTransactionIdStore != NULL, STATUS_ICE_NOT_ENOUGH_MEMORY);

    pTransactionIdStore->transactionIds = (PBYTE)(pTransactionIdStore + 1);
    pTransactionIdStore->maxTransactionIdsCount = maxIdCount;

CleanUp:

    if (STATUS_FAILED(retStatus) && pTransactionIdStore != NULL) {
        MEMFREE(pTransactionIdStore);
        pTransactionIdStore = NULL;
    }

    if (ppTransactionIdStore != NULL) {
        *ppTransactionIdStore = pTransactionIdStore;
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief free the buffer of transaction id.
 * 
 * @param[in]
*/
STATUS freeTransactionIdStore(PTransactionIdStore* ppTransactionIdStore)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTransactionIdStore pTransactionIdStore = NULL;

    CHK(ppTransactionIdStore != NULL, STATUS_NULL_ARG);
    pTransactionIdStore = *ppTransactionIdStore;
    CHK(pTransactionIdStore != NULL, retStatus);

    SAFE_MEMFREE(pTransactionIdStore);

    *ppTransactionIdStore = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief insert the transaction id into the database. #YC_TBD, this needs to be enhanced.
 * 
 * @param[in]
 * @param[in]
*/
VOID transactionIdStoreInsert(PTransactionIdStore pTransactionIdStore, PBYTE transactionId)
{
    PBYTE storeLocation = NULL;

    CHECK(pTransactionIdStore != NULL);

    // get the available buffer.
    storeLocation = pTransactionIdStore->transactionIds +
        ((pTransactionIdStore->nextTransactionIdIndex % pTransactionIdStore->maxTransactionIdsCount) * STUN_TRANSACTION_ID_LEN);
    MEMCPY(storeLocation, transactionId, STUN_TRANSACTION_ID_LEN);
    // move the next index.
    pTransactionIdStore->nextTransactionIdIndex = (pTransactionIdStore->nextTransactionIdIndex + 1) % pTransactionIdStore->maxTransactionIdsCount;
    // #YC_TBD, need to enhance.  Based on the current coding, no need to code it.
    if (pTransactionIdStore->nextTransactionIdIndex == pTransactionIdStore->earliestTransactionIdIndex) {
        pTransactionIdStore->earliestTransactionIdIndex =
            (pTransactionIdStore->earliestTransactionIdIndex + 1) % pTransactionIdStore->maxTransactionIdsCount;
    }

    pTransactionIdStore->transactionIdCount = MIN(pTransactionIdStore->transactionIdCount + 1, pTransactionIdStore->maxTransactionIdsCount);
}
/**
 * @brief
 * 
 * @param[]
 * @param[]
*/
BOOL transactionIdStoreHasId(PTransactionIdStore pTransactionIdStore, PBYTE transactionId)
{
    BOOL idFound = FALSE;
    UINT32 i, j;

    CHECK(pTransactionIdStore != NULL);

    for (i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount && !idFound; ++j) {
        if (MEMCMP(transactionId, pTransactionIdStore->transactionIds + i * STUN_TRANSACTION_ID_LEN, STUN_TRANSACTION_ID_LEN) == 0) {
            idFound = TRUE;
        }

        i = (i + 1) % pTransactionIdStore->maxTransactionIdsCount;
    }

    return idFound;
}
/**
 * @brief reset the buffer of transaction id.
 * 
 * @param[in]
*/
VOID transactionIdStoreClear(PTransactionIdStore pTransactionIdStore)
{
    CHECK(pTransactionIdStore != NULL);

    pTransactionIdStore->nextTransactionIdIndex = 0;
    pTransactionIdStore->earliestTransactionIdIndex = 0;
    pTransactionIdStore->transactionIdCount = 0;
}
/**
 * @brief generate the transaction id. 
 * 
 * #YC_TBD, this should be take care. According to rfc5389, 
 * As such, the transaction ID MUST be uniformlyand randomly chosen from the interval 0 .. 2**96-1, 
 * and SHOULD be cryptographically random.
 * 
*/
STATUS iceUtilsGenerateTransactionId(PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;

    CHK(pBuffer != NULL, STATUS_NULL_ARG);
    CHK(bufferLen == STUN_TRANSACTION_ID_LEN, STATUS_INVALID_ARG);

    for (i = 0; i < STUN_TRANSACTION_ID_LEN; ++i) {
        pBuffer[i] = ((BYTE)(RAND() % 0x100));
    }

CleanUp:

    return retStatus;
}
/**
 * @brief   prepare the stun packet for sending it out.
 * 
 * @param[in] pStunPacket
 * @param[in] password
 * @param[in] passwordLen
 * @param[in, out] pBuffer the pointer of this serialized stun packet.
 * @param[in, out] pBufferLen the length of this serialized stun packet.
 * 
 * @return 
*/
STATUS iceUtilsPackageStunPacket(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, PBYTE pBuffer, PUINT32 pBufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 stunPacketSize = 0;
    BOOL addMessageIntegrity = FALSE;

    CHK(pStunPacket != NULL && pBuffer != NULL && pBufferLen != NULL, STATUS_NULL_ARG);
    CHK((password == NULL && passwordLen == 0) || (password != NULL && passwordLen > 0), STATUS_INVALID_ARG);

    if (password != NULL) {
        addMessageIntegrity = TRUE;
    }

    CHK_STATUS(serializeStunPacket(pStunPacket, password, passwordLen, addMessageIntegrity, TRUE, NULL, &stunPacketSize));
    CHK(stunPacketSize <= *pBufferLen, STATUS_BUFFER_TOO_SMALL);
    CHK_STATUS(serializeStunPacket(pStunPacket, password, passwordLen, addMessageIntegrity, TRUE, pBuffer, &stunPacketSize));
    *pBufferLen = stunPacketSize;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}
/**
 * @brief   packsend the stun packet and send the stun packet.
 * 
 * @param[in]
 * @param[in]
 * @param[in]
 * @param[in]
 * @param[in]
 * @param[in]
 * 
 * @return 
*/
STATUS iceUtilsSendStunPacket(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, PKvsIpAddress pDest, PSocketConnection pSocketConnection,
                              PTurnConnection pTurnConnection, BOOL useTurn)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 stunPacketSize = STUN_PACKET_ALLOCATION_SIZE;
    PBYTE stunPacketBuffer = NULL;
    // #memory, #heap. #YC_TBD.
    CHK(NULL != (stunPacketBuffer = (PBYTE) MEMALLOC(STUN_PACKET_ALLOCATION_SIZE)), STATUS_NOT_ENOUGH_MEMORY);
    //DLOGD("%s, ip: %d.%d.%d.%d", useTurn == TRUE ? "turn":"non-turn", pDest->address[0], pDest->address[1], pDest->address[2], pDest->address[3]);
    CHK_STATUS(iceUtilsPackageStunPacket(pStunPacket, password, passwordLen, stunPacketBuffer, &stunPacketSize));
    CHK_STATUS(iceUtilsSendData(stunPacketBuffer, stunPacketSize, pDest, pSocketConnection, pTurnConnection, useTurn));

CleanUp:
    SAFE_MEMFREE(stunPacketBuffer);
    CHK_LOG_ERR(retStatus);

    return retStatus;
}
/**
 * @brief   send the packet via the socket of the selected ice candidate.
 * 
 * @param[in] buffer
 * @param[in] size 
 * @param[in] pDest the destination ip.
 * @param[in] pSocketConnection the socket handler.
 * @param[in] pTurnConnection  the turn connection handler.
 * @param[in] useTurn indicate this remote candidate belongs to the turn connection.
 * 
*/
STATUS iceUtilsSendData(PBYTE buffer, UINT32 size, PKvsIpAddress pDest, PSocketConnection pSocketConnection, PTurnConnection pTurnConnection,
                        BOOL useTurn)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK((pSocketConnection != NULL && !useTurn) || (pTurnConnection != NULL && useTurn), STATUS_INVALID_ARG);
    // if you are using turn connection, you need to transfer the ip of this destination.
    if (useTurn) {
        retStatus = turnConnectionSendData(pTurnConnection, buffer, size, pDest);
    } else {
        retStatus = socketConnectionSendData(pSocketConnection, buffer, size, pDest);
    }

    // Fix-up the not-yet-ready socket
    CHK(STATUS_SUCCEEDED(retStatus) || retStatus == STATUS_SOCKET_CONNECTION_NOT_READY_TO_SEND, retStatus);
    retStatus = STATUS_SUCCESS;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}
/**
 * 
 * #YC_TBD, consider to change this api, but it is not a bottleneck.
 * 
*/
STATUS parseIceServer(PIceServer pIceServer, PCHAR url, PCHAR username, PCHAR credential)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR separator = NULL, urlNoPrefix = NULL, paramStart = NULL;
    UINT32 port = ICE_STUN_DEFAULT_PORT;

    // username and credential is only mandatory for turn server
    CHK(url != NULL && pIceServer != NULL, STATUS_NULL_ARG);
    //DLOGD("url:%s", url);
    if (STRNCMP(ICE_URL_PREFIX_STUN, url, STRLEN(ICE_URL_PREFIX_STUN)) == 0) {
        urlNoPrefix = STRCHR(url, ':') + 1;
        pIceServer->isTurn = FALSE;
    } else if (STRNCMP(ICE_URL_PREFIX_TURN, url, STRLEN(ICE_URL_PREFIX_TURN)) == 0 ||
               STRNCMP(ICE_URL_PREFIX_TURN_SECURE, url, STRLEN(ICE_URL_PREFIX_TURN_SECURE)) == 0) {

        CHK(username != NULL && username[0] != '\0', STATUS_ICE_URL_TURN_MISSING_USERNAME);
        CHK(credential != NULL && credential[0] != '\0', STATUS_ICE_URL_TURN_MISSING_CREDENTIAL);

        // TODO after getIceServerConfig no longer give turn: ips, do TLS only for turns:
        STRNCPY(pIceServer->username, username, MAX_ICE_CONFIG_USER_NAME_LEN);
        STRNCPY(pIceServer->credential, credential, MAX_ICE_CONFIG_CREDENTIAL_LEN);
        urlNoPrefix = STRCHR(url, ':') + 1;
        pIceServer->isTurn = TRUE;
        pIceServer->isSecure = STRNCMP(ICE_URL_PREFIX_TURN_SECURE, url, STRLEN(ICE_URL_PREFIX_TURN_SECURE)) == 0;

        pIceServer->transport = KVS_SOCKET_PROTOCOL_NONE;
        if (STRSTR(url, ICE_URL_TRANSPORT_UDP) != NULL) {
            pIceServer->transport = KVS_SOCKET_PROTOCOL_UDP;
        } else if (STRSTR(url, ICE_URL_TRANSPORT_TCP) != NULL) {
            pIceServer->transport = KVS_SOCKET_PROTOCOL_TCP;
        }

    } else {
        CHK(FALSE, STATUS_ICE_URL_INVALID_PREFIX);
    }

    if ((separator = STRCHR(urlNoPrefix, ':')) != NULL) {
        separator++;
        paramStart = STRCHR(urlNoPrefix, '?');
        CHK_STATUS(STRTOUI32(separator, paramStart, 10, &port));
        STRNCPY(pIceServer->url, urlNoPrefix, separator - urlNoPrefix - 1);
        // need to null terminate since we are not copying the entire urlNoPrefix
        pIceServer->url[separator - urlNoPrefix - 1] = '\0';
    } else {
        STRNCPY(pIceServer->url, urlNoPrefix, MAX_ICE_CONFIG_URI_LEN);
    }
    //DLOGD("pIceServer->url:%s(%d):%d", pIceServer->url, port, pIceServer->transport);
    CHK_STATUS(getIpWithHostName(pIceServer->url, &pIceServer->ipAddress));
    //DLOGD("getipwithhostname:%d.%d.%d.%d.", pIceServer->ipAddress.address[0],
    //            pIceServer->ipAddress.address[1],
    //            pIceServer->ipAddress.address[2],
    //            pIceServer->ipAddress.address[3]);
    pIceServer->ipAddress.port = (UINT16) getInt16((INT16) port);

CleanUp:

    LEAVES();

    return retStatus;
}
