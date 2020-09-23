#if (ENABLE_DATA_CHANNEL)

#define LOG_CLASS "SCTP"
#include "../Include_i.h"

/**
 * @brief   setup the parameter of sctp socket.
 * 
 * @param[in] pSctpSession the sctp session.
 * @param[in] sconn the parameter of the sctp socket.
*/
STATUS initSctpAddrConn(PSctpSession pSctpSession, struct sockaddr_conn* sconn)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    sconn->sconn_family = AF_CONN;
    putInt16((PINT16) &sconn->sconn_port, SCTP_ASSOCIATION_DEFAULT_PORT);
    sconn->sconn_addr = pSctpSession;

    LEAVES();
    return retStatus;
}
/**
 * @brief   setup the sctp socket.
 * 
 * @param[in] the handler of socket.
*/
STATUS configureSctpSocket(struct socket* socket)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    struct linger linger_opt;
    struct sctp_event event;
    UINT32 i;
    UINT32 valueOn = 1;
    UINT16 event_types[] = {SCTP_ASSOC_CHANGE,
                            SCTP_PEER_ADDR_CHANGE,
                            SCTP_REMOTE_ERROR,
                            SCTP_SHUTDOWN_EVENT,
                            SCTP_ADAPTATION_INDICATION,
                            SCTP_PARTIAL_DELIVERY_EVENT};

    CHK(usrsctp_set_non_blocking(socket, 1) == 0, STATUS_SCTP_SO_NON_BLOCKING_FAILED);

    // onSctpOutboundPacket must not be called after close
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 0;
    CHK(usrsctp_setsockopt(socket, SOL_SOCKET, SO_LINGER, &linger_opt, SIZEOF(linger_opt)) == 0, STATUS_SCTP_SO_LINGER_FAILED);

    // packets are generally sent as soon as possible and no unnecessary
    // delays are introduced, at the cost of more packets in the network.
    CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_NODELAY, &valueOn, SIZEOF(valueOn)) == 0, STATUS_SCTP_SO_NODELAY_FAILED);
    /**
     * https://tools.ietf.org/html/rfc6458#section-6.2.2
    */
    MEMSET(&event, 0, SIZEOF(event));
    event.se_assoc_id = SCTP_FUTURE_ASSOC;
    event.se_on = 1;
    for (i = 0; i < (UINT32)(SIZEOF(event_types) / SIZEOF(UINT16)); i++) {
        event.se_type = event_types[i];
        CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_EVENT, &event, SIZEOF(struct sctp_event)) == 0, STATUS_SCTP_EVENT_FAILED);
    }
    /**
     * https://tools.ietf.org/html/rfc6458#section-5.3.1
     * SCTP Initiation Structure (SCTP_INIT)
     * +--------------+-----------+---------------------+
     * | cmsg_level   | cmsg_type | cmsg_data[]         |
     * +--------------+-----------+---------------------+
     * | IPPROTO_SCTP | SCTP_INIT | struct sctp_initmsg |
     * +--------------+-----------+---------------------+
     * sinit_max_attempts:  This integer specifies how many attempts the SCTP endpoint should make at resending the INIT.
     * sinit_max_init_timeo:  This value represents the largest timeout or retransmission timeout (RTO) value (in milliseconds) to use in attempting an INIT.
     *                        A default value of 0 indicates the use of the endpoint's default value.  This is normally set to the system's 'RTO.Max' value (60 seconds).
    */
    struct sctp_initmsg initmsg;
    MEMSET(&initmsg, 0, SIZEOF(struct sctp_initmsg));
    initmsg.sinit_num_ostreams = 300;//!< This is an integer representing the number of streams to which the application wishes to be able to send
    initmsg.sinit_max_instreams = 300;//!< his value represents the maximum number of inbound streams the application is prepared to support.
    
    CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, SIZEOF(struct sctp_initmsg)) == 0, STATUS_SCTP_INITMSG_FAILED);

CleanUp:
    LEAVES();
    return retStatus;
}
/**
 * @brief the initilization of the sctp session. 
 * 
*/
STATUS initSctpSession()
{
    STATUS retStatus = STATUS_SUCCESS;
    /** 
     * this sctp will start one thread to handle sctp. 
     * If you do not want to start another thread, you can use usrsctp_init_nothreads().
     * 
     *  This local UDP port is set with the parameter udp_port. The default value is 9899, the standard UDP encapsulation port. 
     * If UDP encapsulation is not necessary, the UDP port has to be set to 0.
     */
    usrsctp_init(0, &onSctpOutboundPacket, printf);

    // Disable Explicit Congestion Notification
    usrsctp_sysctl_set_sctp_ecn_enable(0);

    return retStatus;
}

VOID deinitSctpSession()
{
    // need to block until usrsctp_finish or sctp thread could be calling free objects and cause segfault
    while (usrsctp_finish() != 0) {
        THREAD_SLEEP(DEFAULT_USRSCTP_TEARDOWN_POLLING_INTERVAL);
    }
}
/**
 * @brief   create the sctp session including opening stcp socket.
 * 
 * @param[]
 * @param[]
*/
STATUS createSctpSession(PSctpSessionCallbacks pSctpSessionCallbacks, PSctpSession* ppSctpSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = NULL;
    /** #memory. this should be fine. */
    struct sockaddr_conn localConn, remoteConn;
    struct sctp_paddrparams params;
    INT32 connectStatus = 0;

    CHK(ppSctpSession != NULL && pSctpSessionCallbacks != NULL, STATUS_NULL_ARG);
    /** #memory. */
    pSctpSession = (PSctpSession) MEMALLOC(SIZEOF(SctpSession));
    CHK(pSctpSession != NULL, STATUS_NOT_ENOUGH_MEMORY);

    MEMSET(&params, 0x00, SIZEOF(struct sctp_paddrparams));
    MEMSET(&localConn, 0x00, SIZEOF(struct sockaddr_conn));
    MEMSET(&remoteConn, 0x00, SIZEOF(struct sockaddr_conn));

    ATOMIC_STORE(&pSctpSession->shutdownStatus, SCTP_SESSION_ACTIVE);
    pSctpSession->sctpSessionCallbacks = *pSctpSessionCallbacks;
    /** setup the parameter of sctp socket. */
    CHK_STATUS(initSctpAddrConn(pSctpSession, &localConn));
    CHK_STATUS(initSctpAddrConn(pSctpSession, &remoteConn));

    CHK((pSctpSession->socket = usrsctp_socket(AF_CONN,//!< domain
                                               SOCK_STREAM,//!< type
                                               IPPROTO_SCTP,//!< protocol
                                               onSctpInboundPacket,//!< receive_cb
                                               NULL,//!< send_cb
                                               0,//!< sb_threshold
                                               pSctpSession)) != NULL, STATUS_SCTP_SO_CREATE_FAILED);//!< ulp_info
    usrsctp_register_address(pSctpSession);
    CHK_STATUS(configureSctpSocket(pSctpSession->socket));

    CHK(usrsctp_bind(pSctpSession->socket, (struct sockaddr*) &localConn, SIZEOF(localConn)) == 0, STATUS_SCTP_SO_BIND_FAILED);

    connectStatus = usrsctp_connect(pSctpSession->socket, (struct sockaddr*) &remoteConn, SIZEOF(remoteConn));
    CHK(connectStatus >= 0 || errno == EINPROGRESS, STATUS_SCTP_SO_CONNECT_FAILED);

    memcpy(&params.spp_address, &remoteConn, SIZEOF(remoteConn));
    params.spp_flags = SPP_PMTUD_DISABLE;
    params.spp_pathmtu = SCTP_MTU;
    CHK(usrsctp_setsockopt(pSctpSession->socket,
                           IPPROTO_SCTP,
                           SCTP_PEER_ADDR_PARAMS,
                           &params,
                           SIZEOF(params)) == 0, STATUS_SCTP_PEER_ADDR_PARAMS_FAILED);

CleanUp:
    if (STATUS_FAILED(retStatus)) {
        freeSctpSession(&pSctpSession);
    }

    *ppSctpSession = pSctpSession;

    LEAVES();
    return retStatus;
}

STATUS freeSctpSession(PSctpSession* ppSctpSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession;
    UINT64 shutdownTimeout;

    CHK(ppSctpSession != NULL, STATUS_NULL_ARG);

    pSctpSession = *ppSctpSession;

    CHK(pSctpSession != NULL, retStatus);

    usrsctp_deregister_address(pSctpSession);
    /* handle issue mentioned here: https://github.com/sctplab/usrsctp/issues/147
     * the change in shutdownStatus will trigger onSctpOutboundPacket to return -1 */
    ATOMIC_STORE(&pSctpSession->shutdownStatus, SCTP_SESSION_SHUTDOWN_INITIATED);

    if (pSctpSession->socket != NULL) {
        usrsctp_set_ulpinfo(pSctpSession->socket, NULL);
        usrsctp_shutdown(pSctpSession->socket, SHUT_RDWR);
        usrsctp_close(pSctpSession->socket);
    }

    shutdownTimeout = GETTIME() + DEFAULT_SCTP_SHUTDOWN_TIMEOUT;
    while (ATOMIC_LOAD(&pSctpSession->shutdownStatus) != SCTP_SESSION_SHUTDOWN_COMPLETED && GETTIME() < shutdownTimeout) {
        THREAD_SLEEP(DEFAULT_USRSCTP_TEARDOWN_POLLING_INTERVAL);
    }

    SAFE_MEMFREE(*ppSctpSession);

    *ppSctpSession = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief send data over the sctp session.
 * 
 * @param[in] pSctpSession the object of sctp session.
 * @param[in] streamId the stream id of sctp session.
 * @param[in] isBinary binary or string.
 * @param[in] pMessage the buffer of message.
 * @param[in] pMessageLen the lengthe of the messgae buffer.
*/
STATUS sctpSessionWriteMessage(PSctpSession pSctpSession, UINT32 streamId, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSctpSession != NULL && pMessage != NULL, STATUS_NULL_ARG);

    MEMSET(&pSctpSession->spa, 0x00, SIZEOF(struct sctp_sendv_spa));

    pSctpSession->spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
    pSctpSession->spa.sendv_sndinfo.snd_sid = streamId;

    if ((pSctpSession->packet[1] & DCEP_DATA_CHANNEL_RELIABLE_UNORDERED) != 0) {
        /** 
         * This flag requests the unordered delivery of the message. 
         * If this flag is clear, the datagram is considered an ordered send. 
         */
        pSctpSession->spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
    }
    /** https://tools.ietf.org/html/rfc6458#section-5.3.7 
     * This cmsghdr structure specifies SCTP options for sendmsg().
     * +--------------+-------------+--------------------+
     * | cmsg_level   | cmsg_type   | cmsg_data[]        |
     * +--------------+-------------+--------------------+
     * | IPPROTO_SCTP | SCTP_PRINFO | struct sctp_prinfo |
     * +--------------+-------------+--------------------+
    */
    if ((pSctpSession->packet[1] & DCEP_DATA_CHANNEL_REXMIT) != 0) {
        pSctpSession->spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
        pSctpSession->spa.sendv_prinfo.pr_value = getUnalignedInt32BigEndian((PINT32)(pSctpSession->packet + SIZEOF(UINT32)));
    }
    if ((pSctpSession->packet[1] & DCEP_DATA_CHANNEL_TIMED) != 0) {
        pSctpSession->spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
        pSctpSession->spa.sendv_prinfo.pr_value = getUnalignedInt32BigEndian((PINT32)(pSctpSession->packet + SIZEOF(UINT32)));
    }
    /** protocol identifier. */
    putInt32((PINT32) &pSctpSession->spa.sendv_sndinfo.snd_ppid, isBinary ? SCTP_PPID_BINARY : SCTP_PPID_STRING);
    /** 
     * SCTP_SENDV_NOINFO
     * SCTP_SENDV_SNDINFO
     * SCTP_SENDV_PRINFO
     * SCTP_SENDV_SPA (For additional information please refer to RFC 6458.)
    */
    CHK(usrsctp_sendv(pSctpSession->socket,
                      pMessage,
                      pMessageLen,
                      NULL,
                      0,
                      &pSctpSession->spa,
                      SIZEOF(pSctpSession->spa),
                      SCTP_SENDV_SPA, 
                      0) > 0, STATUS_INTERNAL_ERROR);

CleanUp:
    LEAVES();
    return retStatus;
}

// https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09#section-5.1
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |  Message Type |  Channel Type |            Priority           |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                    Reliability Parameter                      |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |         Label Length          |       Protocol Length         |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     |                             Label                             |
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     |                            Protocol                           |
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/**
 * @brief
*/
STATUS sctpSessionWriteDcep(PSctpSession pSctpSession, 
                            UINT32 streamId,
                            PCHAR pChannelName,
                            UINT32 pChannelNameLen,//!< #YC_TBD, code convention.
                            PRtcDataChannelInit pRtcDataChannelInit)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSctpSession != NULL && pChannelName != NULL, STATUS_NULL_ARG);

    MEMSET(&pSctpSession->spa, 0x00, SIZEOF(struct sctp_sendv_spa));
    MEMSET(pSctpSession->packet, 0x00, SIZEOF(pSctpSession->packet));
    pSctpSession->packetSize = SCTP_DCEP_HEADER_LENGTH + pChannelNameLen;
    /* Setting the fields of DATA_CHANNEL_OPEN message */
    /** #YC_TBD, need to improve. */
    pSctpSession->packet[0] = DCEP_DATA_CHANNEL_OPEN; // message type

    // Set Channel type based on supplied parameters
    pSctpSession->packet[1] = DCEP_DATA_CHANNEL_RELIABLE_ORDERED;

    //   Set channel type and reliability parameters based on input
    //   SCTP allows fine tuning the channel robustness:
    //      1. Ordering: The data packets can be sent out in an ordered/unordered fashion
    //      2. Reliability: This determines how the retransmission of packets is handled.
    //   There are 2 parameters that can be fine tuned to achieve this:
    //      a. Number of retransmits
    //      b. Packet lifetime
    //   Default values for the parameters is 0. This falls back to reliable channel

    if (!pRtcDataChannelInit->ordered) {
        pSctpSession->packet[1] |= DCEP_DATA_CHANNEL_RELIABLE_UNORDERED;
    }
    /**
     * Reliability Parameter: 4 bytes (unsigned integer)
     * +------------------------------------------------+------------------+
     * | Channel Type                                   | Reliability      |
     * |                                                | Parameter        |
     * +------------------------------------------------+------------------+
     * | DATA_CHANNEL_RELIABLE                          | Ignored          |
     * | DATA_CHANNEL_RELIABLE_UNORDERED                | Ignored          |
     * | DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT           | Number of RTX    |
     * | DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED | Number of RTX    |
     * | DATA_CHANNEL_PARTIAL_RELIABLE_TIMED            | Lifetime in ms   |
     * | DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED  | Lifetime in ms   |
     * +------------------------------------------------+------------------+
    */
    if (pRtcDataChannelInit->maxRetransmits.value >= 0 && pRtcDataChannelInit->maxRetransmits.isNull == FALSE) {
        pSctpSession->packet[1] |= DCEP_DATA_CHANNEL_REXMIT;
        putUnalignedInt32BigEndian(pSctpSession->packet + SIZEOF(UINT32), pRtcDataChannelInit->maxRetransmits.value);
    } else if (pRtcDataChannelInit->maxPacketLifeTime.value >= 0 && pRtcDataChannelInit->maxPacketLifeTime.isNull == FALSE) {
        pSctpSession->packet[1] |= DCEP_DATA_CHANNEL_TIMED;
        putUnalignedInt32BigEndian(pSctpSession->packet + SIZEOF(UINT32), pRtcDataChannelInit->maxPacketLifeTime.value);
    }
    /** Label Length: 2 bytes (unsigned integer) */
    putUnalignedInt16BigEndian(pSctpSession->packet + SCTP_DCEP_LABEL_LEN_OFFSET, pChannelNameLen);
    MEMCPY(pSctpSession->packet + SCTP_DCEP_LABEL_OFFSET, pChannelName, pChannelNameLen);
    /**
     * @brief https://tools.ietf.org/html/rfc6458#section-5.3.4
     * This cmsghdr structure specifies SCTP options for sendmsg().
     * +--------------+--------------+---------------------+
     * | cmsg_level   | cmsg_type    | cmsg_data[]         |
     * +--------------+--------------+---------------------+
     * | IPPROTO_SCTP | SCTP_SNDINFO | struct sctp_sndinfo |
     * +--------------+--------------+---------------------+
    */
    pSctpSession->spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
    pSctpSession->spa.sendv_sndinfo.snd_sid = streamId;

    putInt32((PINT32) &pSctpSession->spa.sendv_sndinfo.snd_ppid, SCTP_PPID_DCEP);
    /** 
     * SCTP_SENDV_NOINFO
     * SCTP_SENDV_SNDINFO
     * SCTP_SENDV_PRINFO
     * SCTP_SENDV_SPA (For additional information please refer to RFC 6458.)
    */
    CHK(usrsctp_sendv(pSctpSession->socket,
                      pSctpSession->packet,
                      pSctpSession->packetSize,
                      NULL,
                      0,
                      &pSctpSession->spa,
                      SIZEOF(pSctpSession->spa),
                      SCTP_SENDV_SPA, 
                      0) > 0, STATUS_INTERNAL_ERROR);
CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief the callback of outbound sctp packets for the libusrsctp.
 * 
 * @param[]
 * @param[]
 * @param[]
 * @param[]
 * @param[]
*/
INT32 onSctpOutboundPacket(PVOID addr, PVOID data, ULONG length, UINT8 tos, UINT8 set_df)
{
    UNUSED_PARAM(tos);
    UNUSED_PARAM(set_df);

    PSctpSession pSctpSession = (PSctpSession) addr;

    if (pSctpSession == NULL || 
        ATOMIC_LOAD(&pSctpSession->shutdownStatus) == SCTP_SESSION_SHUTDOWN_INITIATED ||
        pSctpSession->sctpSessionCallbacks.outboundPacketFunc == NULL) {
        if (pSctpSession != NULL) {
            ATOMIC_STORE(&pSctpSession->shutdownStatus, SCTP_SESSION_SHUTDOWN_COMPLETED);
        }
        return -1;
    }

    pSctpSession->sctpSessionCallbacks.outboundPacketFunc(pSctpSession->sctpSessionCallbacks.customData, data, length);

    return 0;
}
/**
 * @brief the handler of receiving sctp packets.
 * 
 * @param[]
 * @param[]
 * @param[]
*/
STATUS putSctpPacket(PSctpSession pSctpSession, PBYTE buf, UINT32 bufLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    //usrsctp_recvv
    usrsctp_conninput(pSctpSession, buf, bufLen, 0);

    LEAVES();
    return retStatus;
}
/**
 * @brief the handler of inbound packets for libusrsctp. Data Channel Establishment Protocol (DCEP)
 * 
 * @param[in] pSctpSession 
 * @param[in] streamId 
 * @param[in] data 
 * @param[in] length 
*/
STATUS handleDcepPacket(PSctpSession pSctpSession, UINT32 streamId, PBYTE data, SIZE_T length)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT16 labelLength = 0;

    // Assert that is DCEP of type DataChannelOpen
    CHK(length > SCTP_DCEP_HEADER_LENGTH && data[0] == DCEP_DATA_CHANNEL_OPEN, STATUS_SUCCESS);
    /** retrieve the label*/
    MEMCPY(&labelLength, data + 8, SIZEOF(UINT16));
    putInt16((PINT16) &labelLength, labelLength);

    CHK((labelLength + SCTP_DCEP_HEADER_LENGTH) >= length, STATUS_SCTP_INVALID_DCEP_PACKET);

    pSctpSession->sctpSessionCallbacks.dataChannelOpenFunc(pSctpSession->sctpSessionCallbacks.customData,
                                                            streamId,
                                                            data + SCTP_DCEP_HEADER_LENGTH,
                                                            labelLength);

CleanUp:
    LEAVES();
    return retStatus;
}
/**
 * @brief the callback for libusrsctp. the packet handler of sctp packets.
 * 
 * @param[] 
 * @param[] 
 * @param[] 
 * @param[]
 * @param[]
*/
INT32 onSctpInboundPacket(struct socket* sock,
                          union sctp_sockstore addr,
                          PVOID data,
                          ULONG length,
                          struct sctp_rcvinfo rcv,
                          INT32 flags,
                          PVOID ulp_info)
{
    UNUSED_PARAM(sock);
    UNUSED_PARAM(addr);
    UNUSED_PARAM(flags);
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = (PSctpSession) ulp_info;
    BOOL isBinary = FALSE;

    rcv.rcv_ppid = ntohl(rcv.rcv_ppid);
    switch (rcv.rcv_ppid) {
        case SCTP_PPID_DCEP:
            CHK_STATUS(handleDcepPacket(pSctpSession, rcv.rcv_sid, data, length));
            break;
        case SCTP_PPID_BINARY:
        case SCTP_PPID_BINARY_EMPTY:
            isBinary = TRUE;
            // fallthrough
        case SCTP_PPID_STRING:
        case SCTP_PPID_STRING_EMPTY:
            pSctpSession->sctpSessionCallbacks.dataChannelMessageFunc(pSctpSession->sctpSessionCallbacks.customData, rcv.rcv_sid, isBinary, data,
                                                                      length);
            break;
        default:
            DLOGI("Unhandled PPID on incoming SCTP message %d", rcv.rcv_ppid);
            break;
    }

CleanUp:

    /*
     * IMPORTANT!!! The allocation is done in the sctp library using default allocator
     * so we need to use the default free API.
     */
    if (data != NULL) {
        free(data);
    }

    return 1;
}
#endif