/**
 * Kinesis Video Tcp
 */
#define LOG_CLASS "SocketConnection"
#include "../Include_i.h"


/**
 * @brief   Create a SocketConnection object and store it in PSocketConnection. creates a socket based on KVS_SOCKET_PROTOCOL
 *          specified, and bind it to the host ip address. If the protocol is tcp, then peer ip address is required and it will
 *          try to establish the tcp connection.
 *
 * @param[in] familyType Family for the socket. Must be one of KVS_IP_FAMILY_TYPE
 * @param[in] protocol socket protocol. TCP or UDP
 * @param[in] pBindAddr host ip address to bind to (OPTIONAL)
 * @param[in] pPeerIpAddr peer ip address to connect in case of TCP (OPTIONAL)
 * @param[in] customData data available callback custom data
 * @param[in] pfDataAvailableFn data available callback (OPTIONAL)
 * @param[in] sendBufSize send buffer size in bytes
 * @param[in, out] ppSocketConnection the resulting SocketConnection struct
 *
 * @return - STATUS - status of execution
 */
STATUS createSocketConnection(  KVS_IP_FAMILY_TYPE familyType,
                                KVS_SOCKET_PROTOCOL protocol,
                                PKvsIpAddress pBindAddr,
                                PKvsIpAddress pPeerIpAddr,
                                UINT64 customData,
                                ConnectionDataAvailableFunc pfDataAvailableFn,
                                UINT32 sendBufSize,
                                PSocketConnection* ppSocketConnection)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSocketConnection pSocketConnection = NULL;

    CHK(ppSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(protocol == KVS_SOCKET_PROTOCOL_UDP || pPeerIpAddr != NULL, STATUS_INVALID_ARG);

    pSocketConnection = (PSocketConnection) MEMCALLOC(1, SIZEOF(SocketConnection));
    CHK(pSocketConnection != NULL, STATUS_NOT_ENOUGH_MEMORY);

    pSocketConnection->lock = MUTEX_CREATE(FALSE);
    CHK(pSocketConnection->lock != INVALID_MUTEX_VALUE, STATUS_INVALID_OPERATION);

    CHK_STATUS(createSocket(familyType, protocol, sendBufSize, &pSocketConnection->localSocket));
    if (pBindAddr) {
        CHK_STATUS(socketBind(pBindAddr, pSocketConnection->localSocket));
        pSocketConnection->hostIpAddr = *pBindAddr;
    }

    pSocketConnection->secureConnection = FALSE;
    pSocketConnection->protocol = protocol;
    if (protocol == KVS_SOCKET_PROTOCOL_TCP) {
        pSocketConnection->peerIpAddr = *pPeerIpAddr;
        CHK_STATUS(socketConnect(pPeerIpAddr, pSocketConnection->localSocket));
    }
    ATOMIC_STORE_BOOL(&pSocketConnection->connectionClosed, FALSE);
    ATOMIC_STORE_BOOL(&pSocketConnection->receiveData, FALSE);
    pSocketConnection->dataAvailableCallbackCustomData = customData;
    pSocketConnection->dataAvailableCallbackFn = pfDataAvailableFn;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pSocketConnection != NULL) {
        freeSocketConnection(&pSocketConnection);
        pSocketConnection = NULL;
    }

    if (ppSocketConnection != NULL) {
        *ppSocketConnection = pSocketConnection;
    }

    LEAVES();
    return retStatus;
}

STATUS freeSocketConnection(PSocketConnection* ppSocketConnection)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSocketConnection pSocketConnection = NULL;

    CHK(ppSocketConnection != NULL, STATUS_NULL_ARG);
    pSocketConnection = *ppSocketConnection;
    CHK(pSocketConnection != NULL, retStatus);
    ATOMIC_STORE_BOOL(&pSocketConnection->connectionClosed, TRUE);

    if (IS_VALID_MUTEX_VALUE(pSocketConnection->lock)) {
        MUTEX_FREE(pSocketConnection->lock);
    }

    if (pSocketConnection->pTlsSession != NULL) {
        freeTlsSession(&pSocketConnection->pTlsSession);
    }

    CHK_STATUS(closeSocket(pSocketConnection->localSocket));

    MEMFREE(pSocketConnection);

    *ppSocketConnection = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS socketConnectionTlsSessionOutBoundPacket(UINT64 customData, PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSocketConnection pSocketConnection = NULL;
    CHK(customData != 0, STATUS_NULL_ARG);

    pSocketConnection = (PSocketConnection) customData;
    CHK_STATUS(socketSendDataWithRetry(pSocketConnection, pBuffer, bufferLen, NULL, NULL));

CleanUp:
    return retStatus;
}

VOID socketConnectionTlsSessionOnStateChange(UINT64 customData, TLS_SESSION_STATE state)
{
    PSocketConnection pSocketConnection = NULL;
    if (customData == 0) {
        return;
    }

    pSocketConnection = (PSocketConnection) customData;
    switch (state) {
        case TLS_SESSION_STATE_NEW:
            pSocketConnection->tlsHandshakeStartTime = INVALID_TIMESTAMP_VALUE;
            break;
        case TLS_SESSION_STATE_CONNECTING:
            pSocketConnection->tlsHandshakeStartTime = GETTIME();
            break;
        case TLS_SESSION_STATE_CONNECTED:
            if (IS_VALID_TIMESTAMP(pSocketConnection->tlsHandshakeStartTime)) {
                DLOGD("TLS handshake done. Time taken %" PRIu64 " ms",
                      (GETTIME() - pSocketConnection->tlsHandshakeStartTime) / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
                pSocketConnection->tlsHandshakeStartTime = INVALID_TIMESTAMP_VALUE;
            }
            break;
        case TLS_SESSION_STATE_CLOSED:
            ATOMIC_STORE_BOOL(&pSocketConnection->connectionClosed, TRUE);
            break;
    }
}
/**
 * Given a created SocketConnection, initialize TLS or DTLS handshake depending on the socket protocol
 *
 * @param - PSocketConnection - IN - the SocketConnection struct
 * @param - BOOL - IN - will SocketConnection act as server during the TLS or DTLS handshake
 *
 * @return - STATUS - status of execution
 */
STATUS socketConnectionInitSecureConnection(PSocketConnection pSocketConnection, BOOL isServer)
{
    ENTERS();
    TlsSessionCallbacks callbacks;
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(pSocketConnection->pTlsSession == NULL, STATUS_INVALID_ARG);

    callbacks.outBoundPacketFnCustomData = callbacks.stateChangeFnCustomData = (UINT64) pSocketConnection;
    callbacks.outboundPacketFn = socketConnectionTlsSessionOutBoundPacket;
    callbacks.stateChangeFn = socketConnectionTlsSessionOnStateChange;

    CHK_STATUS(createTlsSession(&callbacks, &pSocketConnection->pTlsSession));
    CHK_STATUS(tlsSessionStart(pSocketConnection->pTlsSession, isServer));
    pSocketConnection->secureConnection = TRUE;

CleanUp:
    if (STATUS_FAILED(retStatus) && pSocketConnection->pTlsSession != NULL) {
        freeTlsSession(&pSocketConnection->pTlsSession);
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief   Given a created SocketConnection, send data through the underlying socket.
 *          If socket type is UDP, then destination address is required. 
 *          If socket type is tcp, destination address is ignored and data is send to the peer address provided
 *          at SocketConnection creation. If socketConnectionInitSecureConnection has been called then data will be encrypted,
 *          otherwise data will be sent as is.
 *
 * @param[in] pSocketConnection the SocketConnection struct
 * @param[in] pBuf buffer containing unencrypted data
 * @param[in] bufLen length of buffer
 * @param[in] pDestIp destination address. Required only if socket type is UDP.
 *
 * @return - STATUS - status of execution
 */
STATUS socketConnectionSendData(PSocketConnection pSocketConnection, PBYTE pBuf, UINT32 bufLen, PKvsIpAddress pDestIp)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK((pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_TCP || pDestIp != NULL), STATUS_INVALID_ARG);

    // Using a single CHK_WARN might output too much spew in bad network conditions
    if (ATOMIC_LOAD_BOOL(&pSocketConnection->connectionClosed)) {
        DLOGD("Warning: Failed to send data. Socket closed already");
        CHK(FALSE, STATUS_SOCKET_CONNECTION_CLOSED_ALREADY);
    }

    MUTEX_LOCK(pSocketConnection->lock);
    locked = TRUE;

    /* Should have a valid buffer */
    CHK(pBuf != NULL && bufLen > 0, STATUS_SOCKET_INVALID_ARG);
    //DLOGD("socket send:%d", pSocketConnection->protocol);
    if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_TCP && pSocketConnection->secureConnection) {
        CHK_STATUS(tlsSessionPutApplicationData(pSocketConnection->pTlsSession, pBuf, bufLen));
    } else if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_TCP) {
        CHK_STATUS(retStatus = socketSendDataWithRetry(pSocketConnection, pBuf, bufLen, NULL, NULL));
    } else if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
        CHK_STATUS(retStatus = socketSendDataWithRetry(pSocketConnection, pBuf, bufLen, pDestIp, NULL));
    } else {
        CHECK_EXT(FALSE, "socketConnectionSendData should not reach here. Nothing is sent.");
    }

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pSocketConnection->lock);
    }

    return retStatus;
}
/**
 * If PSocketConnection is not secure then nothing happens, otherwise assuming the bytes passed in are encrypted, and
 * the encryted data will be replaced with unencrypted data at function return.
 *
 * @param[in] - PSocketConnection - IN - the SocketConnection struct
 * @param[in/out] - PBYTE - IN/OUT - buffer containing encrypted data. Will contain unencrypted on successful return
 * @param[in] - UINT32 - IN - available length of buffer
 * @param[in/out] - PUINT32 - IN/OUT - length of encrypted data. Will contain length of decrypted data on successful return
 *
 * @return - STATUS - status of execution
 */
STATUS socketConnectionReadData(PSocketConnection pSocketConnection, PBYTE pBuf, UINT32 bufferLen, PUINT32 pDataLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pSocketConnection != NULL && pBuf != NULL && pDataLen != NULL, STATUS_NULL_ARG);
    CHK(bufferLen != 0, STATUS_INVALID_ARG);

    MUTEX_LOCK(pSocketConnection->lock);
    locked = TRUE;

    // return early if connection is not secure
    CHK(pSocketConnection->secureConnection, retStatus);

    CHK_STATUS(tlsSessionProcessPacket(pSocketConnection->pTlsSession, pBuf, bufferLen, pDataLen));

CleanUp:

    // CHK_LOG_ERR might be too verbose
    if (STATUS_FAILED(retStatus)) {
        DLOGD("Warning: reading socket data failed with 0x%08x", retStatus);
    }

    if (locked) {
        MUTEX_UNLOCK(pSocketConnection->lock);
    }

    return retStatus;
}

STATUS socketConnectionClosed(PSocketConnection pSocketConnection)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pSocketConnection->connectionClosed), retStatus);
    MUTEX_LOCK(pSocketConnection->lock);
    DLOGD("Close socket %d", pSocketConnection->localSocket);
    ATOMIC_STORE_BOOL(&pSocketConnection->connectionClosed, TRUE);
    if (pSocketConnection->pTlsSession != NULL) {
        tlsSessionShutdown(pSocketConnection->pTlsSession);
    }
    MUTEX_UNLOCK(pSocketConnection->lock);

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

BOOL socketConnectionIsClosed(PSocketConnection pSocketConnection)
{
    if (pSocketConnection == NULL) {
        return TRUE;
    } else {
        return ATOMIC_LOAD_BOOL(&pSocketConnection->connectionClosed);
    }
}

/**
 * Return whether socket has been connected. Return TRUE for UDP sockets.
 * Return TRUE for TCP sockets once the connection has been established, otherwise return FALSE.
 *
 * @param - PSocketConnection - IN - the SocketConnection struct
 *
 * @return - STATUS - status of execution
 */
BOOL socketConnectionIsConnected(PSocketConnection pSocketConnection)
{
    INT32 retVal;
    struct sockaddr* peerSockAddr = NULL;
    socklen_t addrLen;
    struct sockaddr_in ipv4PeerAddr;
    struct sockaddr_in6 ipv6PeerAddr;

    CHECK(pSocketConnection != NULL);

    if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
        return TRUE;
    }

    if (pSocketConnection->peerIpAddr.family == KVS_IP_FAMILY_TYPE_IPV4) {
        addrLen = SIZEOF(struct sockaddr_in);
        MEMSET(&ipv4PeerAddr, 0x00, SIZEOF(ipv4PeerAddr));
        ipv4PeerAddr.sin_family = AF_INET;
        ipv4PeerAddr.sin_port = pSocketConnection->peerIpAddr.port;
        MEMCPY(&ipv4PeerAddr.sin_addr, pSocketConnection->peerIpAddr.address, IPV4_ADDRESS_LENGTH);
        peerSockAddr = (struct sockaddr*) &ipv4PeerAddr;
    } else {
        addrLen = SIZEOF(struct sockaddr_in6);
        MEMSET(&ipv6PeerAddr, 0x00, SIZEOF(ipv6PeerAddr));
        ipv6PeerAddr.sin6_family = AF_INET6;
        ipv6PeerAddr.sin6_port = pSocketConnection->peerIpAddr.port;
        MEMCPY(&ipv6PeerAddr.sin6_addr, pSocketConnection->peerIpAddr.address, IPV6_ADDRESS_LENGTH);
        peerSockAddr = (struct sockaddr*) &ipv6PeerAddr;
    }

    retVal = connect(pSocketConnection->localSocket, peerSockAddr, addrLen);
    if (retVal == 0 || getErrorCode() == EISCONN) {
        return TRUE;
    }

    DLOGW("socket connection check failed with errno %s", getErrorString(getErrorCode()));
    return FALSE;
}
/**
 * @brief 
 * 
 * @param[in] pSocketConnection
 * @param[in] buf
 * @param[in] bufLen
 * @param[in] pDestIp
 * @param[in, out] pBytesWritten the number of written bytes.
 * 
 * @return
*/
STATUS socketSendDataWithRetry(PSocketConnection pSocketConnection, PBYTE buf, UINT32 bufLen, PKvsIpAddress pDestIp, PUINT32 pBytesWritten)
{
    STATUS retStatus = STATUS_SUCCESS;
    INT32 socketWriteAttempt = 0;
    SSIZE_T result = 0;
    UINT32 bytesWritten = 0;
    INT32 errorNum = 0;

    fd_set wfds;
    struct timeval tv;
    socklen_t addrLen = 0;
    struct sockaddr* destAddr = NULL;
    struct sockaddr_in* pIpv4Addr = NULL;
    struct sockaddr_in6* pIpv6Addr = NULL;

    CHK(pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(buf != NULL && bufLen > 0, STATUS_INVALID_ARG);

    if (pDestIp != NULL) {
        if (IS_IPV4_ADDR(pDestIp)) {
            CHK(NULL != (pIpv4Addr =(struct sockaddr_in*) (PCHAR) MEMALLOC(SIZEOF(struct sockaddr_in))), STATUS_NOT_ENOUGH_MEMORY);
            addrLen = SIZEOF(struct sockaddr_in);
            MEMSET(pIpv4Addr, 0x00, SIZEOF(struct sockaddr_in));
            pIpv4Addr->sin_family = AF_INET;
            pIpv4Addr->sin_port = pDestIp->port;
            MEMCPY(&pIpv4Addr->sin_addr, pDestIp->address, IPV4_ADDRESS_LENGTH);
            destAddr = (struct sockaddr*) pIpv4Addr;

        } else {
            CHK(NULL != (pIpv6Addr = (struct sockaddr_in6*) (PCHAR) MEMALLOC(SIZEOF(struct sockaddr_in6))), STATUS_NOT_ENOUGH_MEMORY);
            addrLen = SIZEOF(struct sockaddr_in6);
            MEMSET(pIpv6Addr, 0x00, SIZEOF(struct sockaddr_in6));
            pIpv6Addr->sin6_family = AF_INET6;
            pIpv6Addr->sin6_port = pDestIp->port;
            MEMCPY(&pIpv6Addr->sin6_addr, pDestIp->address, IPV6_ADDRESS_LENGTH);
            destAddr = (struct sockaddr*) pIpv6Addr;
        }
    }

    while (socketWriteAttempt < MAX_SOCKET_WRITE_RETRY && bytesWritten < bufLen) {
        // #socket.
        result = sendto(pSocketConnection->localSocket, buf, bufLen, NO_SIGNAL, destAddr, addrLen);
        if (result < 0) {
            errorNum = getErrorCode();
            if (errorNum == EAGAIN || errorNum == EWOULDBLOCK) {
                FD_ZERO(&wfds);
                FD_SET(pSocketConnection->localSocket, &wfds);
                tv.tv_sec = 0;
                tv.tv_usec = SOCKET_SEND_RETRY_TIMEOUT_MICRO_SECOND;
                result = select(pSocketConnection->localSocket + 1, NULL, &wfds, NULL, &tv);

                if (result == 0) {
                    /* loop back and try again */
                    DLOGD("select() timed out");
                } else if (result < 0) {
                    DLOGD("select() failed with errno %s", getErrorString(getErrorCode()));
                    break;
                }
            } else if (errorNum == EINTR) {
                /* nothing need to be done, just retry */
            } else {
                /* fatal error from send() */
                DLOGD("sendto() failed with errno %s", getErrorString(errorNum));
                break;
            }
        } else {
            bytesWritten += result;
        }
        socketWriteAttempt++;
    }

    if (
         != NULL) {
        *pBytesWritten = bytesWritten;
    }

    if (result < 0) {
        // CLOSE_SOCKET_IF_CANT_RETRY(errorNum, pSocketConnection);
    }

    if (bytesWritten < bufLen) {
        DLOGD("Failed to send data. Bytes sent %u. Data len %u. Retry count %u", bytesWritten, bufLen, socketWriteAttempt);
        retStatus = STATUS_SEND_DATA_FAILED;
    }

CleanUp:
    SAFE_MEMFREE(pIpv4Addr);
    SAFE_MEMFREE(pIpv6Addr);
    // CHK_LOG_ERR might be too verbose in this case
    if (STATUS_FAILED(retStatus)) {
        DLOGD("Warning: Send data failed with 0x%08x", retStatus);
    }

    return retStatus;
}
