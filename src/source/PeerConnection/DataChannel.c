#ifdef ENABLE_DATA_CHANNEL

#define LOG_CLASS "DataChannel"

#include "../Include_i.h"

STATUS connectLocalDataChannel()
{
    return STATUS_SUCCESS;
}

/**
 * @brief createDataChannel creates a new RtcDataChannel object with the given label.
 *
 * NOTE: The RtcDataChannelInit dictionary can be used to configure properties of the underlying
 * channel such as data reliability.
 * NOTE: Data channel can be created only before signaling for now
 *
 * Reference: https://www.w3.org/TR/webrtc/#methods-11
 *
 * @param[in] PRtcPeerConnection Initialized RtcPeerConnection
 * @param[in] PCHAR Data channel Name
 * @param[in] PRtcDataChannelInit Allowed to be NULL/defines underlying channel properties
 * @param[out] PRtcDataChannel* Created data channel with supplied channel name
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS createDataChannel(PRtcPeerConnection pPeerConnection, 
                         PCHAR pDataChannelName,
                         PRtcDataChannelInit pRtcDataChannelInit,
                         PRtcDataChannel* ppRtcDataChannel)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsPeerConnection pKvsPeerConnection = (PKvsPeerConnection) pPeerConnection;
    UINT32 channelId = 0;
    PKvsDataChannel pKvsDataChannel = NULL;

    CHK(pKvsPeerConnection != NULL && pDataChannelName != NULL && ppRtcDataChannel != NULL, STATUS_NULL_ARG);

    // Only support creating DataChannels before signaling for now
    CHK(pKvsPeerConnection->pSctpSession == NULL, STATUS_INTERNAL_ERROR);
    /** #memory. */
    CHK((pKvsDataChannel = (PKvsDataChannel) MEMCALLOC(1, SIZEOF(KvsDataChannel))) != NULL, STATUS_NOT_ENOUGH_MEMORY);
    STRNCPY(pKvsDataChannel->dataChannel.name, pDataChannelName, MAX_DATA_CHANNEL_NAME_LEN);
    pKvsDataChannel->pRtcPeerConnection = (PRtcPeerConnection) pKvsPeerConnection;

    /** passed by user. */
    if (pRtcDataChannelInit != NULL) {
        // Setting negotiated to false. Not supporting at the moment
        pRtcDataChannelInit->negotiated = FALSE;
        pKvsDataChannel->rtcDataChannelInit = *pRtcDataChannelInit;
    }
    /** the default setting. */
    else {
        // If nothing is set, set default to ordered mode
        pKvsDataChannel->rtcDataChannelInit.ordered = FALSE;
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxPacketLifeTime);
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxRetransmits);
    }

    CHK_STATUS(hashTableGetCount(pKvsPeerConnection->pDataChannels, &channelId));
    CHK_STATUS(hashTablePut(pKvsPeerConnection->pDataChannels, channelId, (UINT64) pKvsDataChannel));

CleanUp:
    if (STATUS_SUCCEEDED(retStatus)) {
        *ppRtcDataChannel = (PRtcDataChannel) pKvsDataChannel;
    } else {
        SAFE_MEMFREE(pKvsDataChannel);
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief Send data via the PRtcDataChannel
 *
 * Reference: https://www.w3.org/TR/webrtc/#dfn-send
 *
 * @param[in] PRtcDataChannel Configured and connected PRtcDataChannel
 * @param[in] BOOL Is message binary, if false will be delivered as a string
 * @param[in] PBYTE Data that you wish to send
 * @param[in] UINT32 Length of the PBYTE you wish to send
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 *
 */
STATUS dataChannelSend(PRtcDataChannel pRtcDataChannel, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = NULL;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && pMessage != NULL, STATUS_NULL_ARG);

    pSctpSession = ((PKvsPeerConnection) pKvsDataChannel->pRtcPeerConnection)->pSctpSession;

    CHK_STATUS(sctpSessionWriteMessage(pSctpSession, pKvsDataChannel->channelId, isBinary, pMessage, pMessageLen));

CleanUp:

    return retStatus;
}
/**
 * @brief Set a callback for receiving data channel message
 *
 * @param[in] PRtcDataChannel Data channel struct created by createDataChannel()
 * @param[in] UINT64 User customData that will be passed along when RtcOnMessage is called
 * @param[in] RtcOnMessage User RtcOnMessage callback
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS dataChannelOnMessage(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnMessage rtcOnMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnMessage != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onMessage = rtcOnMessage;
    pKvsDataChannel->onMessageCustomData = customData;

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief Set a callback for data channel open
 *
 * @param[in] PRtcDataChannel Data channel struct created by createDataChannel()
 * @param[in] UINT64 User customData that will be passed along when RtcOnOpen is called
 * @param[in] RtcOnOpen User RtcOnOpen callback
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS dataChannelOnOpen(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnOpen rtcOnOpen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnOpen != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onOpen = rtcOnOpen;
    pKvsDataChannel->onOpenCustomData = customData;

CleanUp:

    LEAVES();
    return retStatus;
}
#endif