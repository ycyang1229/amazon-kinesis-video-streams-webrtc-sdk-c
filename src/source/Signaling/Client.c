#define LOG_CLASS "SignalingClient"
#include "../Include_i.h"


STATUS createSignalingClientSync(PSignalingClientInfo pClientInfo, 
                                PChannelInfo pChannelInfo, 
                                PSignalingClientCallbacks pCallbacks,
                                PAwsCredentialProvider pCredentialProvider, 
                                PSIGNALING_CLIENT_HANDLE pSignalingHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = NULL;
    PSignalingClientInfoInternal pSignalingClientInfoInternal = NULL;

    DLOGI("Creating Signaling Client Sync");
    CHK(pSignalingHandle != NULL && pClientInfo != NULL, STATUS_NULL_ARG);
    CHK(NULL != (pSignalingClientInfoInternal = (PSignalingClientInfoInternal) MEMALLOC(SIZEOF(SignalingClientInfoInternal))),
        STATUS_NOT_ENOUGH_MEMORY);

    // Convert the client info to the internal structure with empty values
    MEMSET(pSignalingClientInfoInternal, 0x00, SIZEOF(SignalingClientInfoInternal));
    pSignalingClientInfoInternal->signalingClientInfo = *pClientInfo;

    CHK_STATUS(createSignalingSync(pSignalingClientInfoInternal, pChannelInfo, pCallbacks, pCredentialProvider, &pSignalingClient));

    *pSignalingHandle = TO_SIGNALING_CLIENT_HANDLE(pSignalingClient);

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeSignaling(&pSignalingClient);
    }
    SAFE_MEMFREE(pSignalingClientInfoInternal);
    LEAVES();
    return retStatus;
}

STATUS freeSignalingClient(PSIGNALING_CLIENT_HANDLE pSignalingHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient;

    DLOGI("Freeing Signaling Client");
    CHK(pSignalingHandle != NULL, STATUS_NULL_ARG);

    // Get the client handle
    pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(*pSignalingHandle);

    CHK_STATUS(freeSignaling(&pSignalingClient));

    // Set the signaling client handle pointer to invalid
    *pSignalingHandle = INVALID_SIGNALING_CLIENT_HANDLE_VALUE;

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief Send a message through a Signaling client.
 *
 * NOTE: The call will fail if the client is not in the CONNECTED state.
 * NOTE: This is a synchronous call. It will block and wait for sending the data and await for the ACK from the service.
 *
 * @param[in] SIGNALING_CLIENT_HANDLE Signaling client handle
 * @param[in] PSignalingMessage Message to send.
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
/**
 * Basically, we only use this to send offer, answer, and ice candidates.
*/
STATUS signalingClientSendMessageSync(SIGNALING_CLIENT_HANDLE signalingClientHandle, PSignalingMessage pSignalingMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGI("Signaling Client Sending Message Sync");

    CHK_STATUS(signalingSendMessageSync(pSignalingClient, pSignalingMessage));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}

STATUS signalingClientConnectSync(SIGNALING_CLIENT_HANDLE signalingClientHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGI("Signaling Client Connect Sync");

    CHK_STATUS(signalingConnectSync(pSignalingClient));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}

STATUS signalingClientDisconnectSync(SIGNALING_CLIENT_HANDLE signalingClientHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGI("Signaling Client Disconnect Sync");

    CHK_STATUS(signalingDisconnectSync(pSignalingClient));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}

STATUS signalingClientDeleteSync(SIGNALING_CLIENT_HANDLE signalingClientHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGI("Signaling Client Delete Sync");

    CHK_STATUS(signalingDeleteSync(pSignalingClient));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}
/**
 * @brief get the number of ice configurations.
 * 
 * @param[in] signalingClientHandle the handle of signaling client.
 * @param[out] pIceConfigCount the number of ice configurations.
 * 
*/
STATUS signalingClientGetIceConfigInfoCount(SIGNALING_CLIENT_HANDLE signalingClientHandle, PUINT32 pIceConfigCount)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGI("Signaling Client Get ICE Config Info Count");

    CHK_STATUS(signalingGetIceConfigInfoCout(pSignalingClient, pIceConfigCount));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}
/**
 * @brief get the information of ice servers. 
 * 
 * @param[in] the handle of this signaling client.
 * @param[in] the index of ice servers, it may have more than one server.
 * @param[out] the pointer of ice server information.
 * 
*/
STATUS signalingClientGetIceConfigInfo(SIGNALING_CLIENT_HANDLE signalingClientHandle, UINT32 index, PIceConfigInfo* ppIceConfigInfo)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGI("Signaling Client Get ICE Config Info");

    CHK_STATUS(signalingGetIceConfigInfo(pSignalingClient, index, ppIceConfigInfo));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}

STATUS signalingClientGetCurrentState(SIGNALING_CLIENT_HANDLE signalingClientHandle, PSIGNALING_CLIENT_STATE pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    SIGNALING_CLIENT_STATE state = SIGNALING_CLIENT_STATE_UNKNOWN;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);
    PStateMachineState pStateMachineState;

    DLOGV("Signaling Client Get Current State");

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_NULL_ARG);

    CHK_STATUS(getStateMachineCurrentState(pSignalingClient->pStateMachine, &pStateMachineState));
    state = getSignalingStateFromStateMachineState(pStateMachineState->state);

CleanUp:

    if (pState != NULL) {
        *pState = state;
    }

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}

STATUS signalingClientGetStateString(SIGNALING_CLIENT_STATE state, PCHAR* ppStateStr)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(ppStateStr != NULL, STATUS_NULL_ARG);

    switch (state) {
        case SIGNALING_CLIENT_STATE_NEW:
            *ppStateStr = SIGNALING_CLIENT_STATE_NEW_STR;
            break;

        case SIGNALING_CLIENT_STATE_GET_CREDENTIALS:
            *ppStateStr = SIGNALING_CLIENT_STATE_GET_CREDENTIALS_STR;
            break;

        case SIGNALING_CLIENT_STATE_DESCRIBE:
            *ppStateStr = SIGNALING_CLIENT_STATE_DESCRIBE_STR;
            break;

        case SIGNALING_CLIENT_STATE_CREATE:
            *ppStateStr = SIGNALING_CLIENT_STATE_CREATE_STR;
            break;

        case SIGNALING_CLIENT_STATE_GET_ENDPOINT:
            *ppStateStr = SIGNALING_CLIENT_STATE_GET_ENDPOINT_STR;
            break;

        case SIGNALING_CLIENT_STATE_GET_ICE_CONFIG:
            *ppStateStr = SIGNALING_CLIENT_STATE_GET_ICE_CONFIG_STR;
            break;

        case SIGNALING_CLIENT_STATE_READY:
            *ppStateStr = SIGNALING_CLIENT_STATE_READY_STR;
            break;

        case SIGNALING_CLIENT_STATE_CONNECTING:
            *ppStateStr = SIGNALING_CLIENT_STATE_CONNECTING_STR;
            break;

        case SIGNALING_CLIENT_STATE_CONNECTED:
            *ppStateStr = SIGNALING_CLIENT_STATE_CONNECTED_STR;
            break;

        case SIGNALING_CLIENT_STATE_DISCONNECTED:
            *ppStateStr = SIGNALING_CLIENT_STATE_DISCONNECTED_STR;
            break;

        case SIGNALING_CLIENT_STATE_DELETE:
            *ppStateStr = SIGNALING_CLIENT_STATE_DELETE_STR;
            break;

        case SIGNALING_CLIENT_STATE_DELETED:
            *ppStateStr = SIGNALING_CLIENT_STATE_DELETED_STR;
            break;

        case SIGNALING_CLIENT_STATE_MAX_VALUE:
        case SIGNALING_CLIENT_STATE_UNKNOWN:
            // Explicit fall-through
        default:
            *ppStateStr = SIGNALING_CLIENT_STATE_UNKNOWN_STR;
    }

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS signalingClientGetMetrics(SIGNALING_CLIENT_HANDLE signalingClientHandle, PSignalingClientMetrics pSignalingClientMetrics)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = FROM_SIGNALING_CLIENT_HANDLE(signalingClientHandle);

    DLOGV("Signaling Client Get Metrics");

    CHK_STATUS(signalingGetMetrics(pSignalingClient, pSignalingClientMetrics));

CleanUp:

    SIGNALING_UPDATE_ERROR_COUNT(pSignalingClient, retStatus);
    LEAVES();
    return retStatus;
}
