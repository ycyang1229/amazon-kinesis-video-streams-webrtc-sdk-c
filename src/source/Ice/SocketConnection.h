/*******************************************
Socket Connection internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_SOCKET_CONNECTION__
#define __KINESIS_VIDEO_WEBRTC_SOCKET_CONNECTION__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define SOCKET_SEND_RETRY_TIMEOUT_MICRO_SECOND 500000
#define MAX_SOCKET_WRITE_RETRY                 3

#define CLOSE_SOCKET_IF_CANT_RETRY(e, ps)                                                                                                            \
    if ((e) != EAGAIN && (e) != EWOULDBLOCK && (e) != EINTR && (e) != EINPROGRESS && (e) != EPERM && (e) != EALREADY && (e) != ENETUNREACH) {        \
        DLOGD("Close socket %d", (ps)->localSocket);                                                                                                 \
        ATOMIC_STORE_BOOL(&(ps)->connectionClosed, TRUE);                                                                                            \
    }

typedef STATUS (*ConnectionDataAvailableFunc)(UINT64, struct __SocketConnection*, PBYTE, UINT32, PKvsIpAddress, PKvsIpAddress);

typedef struct __SocketConnection SocketConnection;
struct __SocketConnection {
    /* Indicate whether this socket is marked for cleanup */
    volatile ATOMIC_BOOL connectionClosed;
    /* Process incoming bits */
    volatile ATOMIC_BOOL receiveData;
    INT32 localSocket;
    KVS_SOCKET_PROTOCOL protocol;
    KvsIpAddress peerIpAddr;
    KvsIpAddress hostIpAddr;

    BOOL secureConnection;//!< indicate this socket connectino is secure or not.
    PTlsSession pTlsSession;

    MUTEX lock;//!< 

    ConnectionDataAvailableFunc dataAvailableCallbackFn;//!< the callback when the data is ready.
    UINT64 dataAvailableCallbackCustomData;
    UINT64 tlsHandshakeStartTime;
};
typedef struct __SocketConnection* PSocketConnection;

STATUS createSocketConnection(KVS_IP_FAMILY_TYPE, KVS_SOCKET_PROTOCOL, PKvsIpAddress, PKvsIpAddress, UINT64, ConnectionDataAvailableFunc, UINT32,
                              PSocketConnection*);

/**
 * Free the SocketConnection struct
 *
 * @param - PSocketConnection* - IN - SocketConnection to be freed
 *
 * @return - STATUS - status of execution
 */
STATUS freeSocketConnection(PSocketConnection*);

/**
 * Given a created SocketConnection, initialize TLS or DTLS handshake depending on the socket protocol
 *
 * @param - PSocketConnection - IN - the SocketConnection struct
 * @param - BOOL - IN - will SocketConnection act as server during the TLS or DTLS handshake
 *
 * @return - STATUS - status of execution
 */
STATUS socketConnectionInitSecureConnection(PSocketConnection, BOOL);

STATUS socketConnectionSendData(PSocketConnection, PBYTE, UINT32, PKvsIpAddress);

/**
 * If PSocketConnection is not secure then nothing happens, otherwise assuming the bytes passed in are encrypted, and
 * the encryted data will be replaced with unencrypted data at function return.
 *
 * @param - PSocketConnection - IN - the SocketConnection struct
 * @param - PBYTE - IN/OUT - buffer containing encrypted data. Will contain unencrypted on successful return
 * @param - UINT32 - IN - available length of buffer
 * @param - PUINT32 - IN/OUT - length of encrypted data. Will contain length of decrypted data on successful return
 *
 * @return - STATUS - status of execution
 */
STATUS socketConnectionReadData(PSocketConnection, PBYTE, UINT32, PUINT32);

/**
 * Mark PSocketConnection as closed
 *
 * @param - PSocketConnection - IN - the SocketConnection struct
 *
 * @return - STATUS - status of execution
 */
STATUS socketConnectionClosed(PSocketConnection);

/**
 * Check if PSocketConnection is closed
 *
 * @param - PSocketConnection - IN - the SocketConnection struct
 *
 * @return - BOOL - whether connection is closed
 */
BOOL socketConnectionIsClosed(PSocketConnection);

BOOL socketConnectionIsConnected(PSocketConnection);

// internal functions
STATUS socketSendDataWithRetry(PSocketConnection, PBYTE, UINT32, PKvsIpAddress, PUINT32);
STATUS socketConnectionTlsSessionOutBoundPacket(UINT64, PBYTE, UINT32);
VOID socketConnectionTlsSessionOnStateChange(UINT64, TLS_SESSION_STATE);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_SOCKET_CONNECTION__ */
