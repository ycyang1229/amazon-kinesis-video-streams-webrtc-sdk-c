/**
 * Implementation of a ice agent states machine callbacks
 */
#define LOG_CLASS "IceAgentState"
#include "../Include_i.h"

/**
 * Static definitions of the states
 */
#define ICE_AGENT_STATE_UNLIMIT_RETRY         (INFINITE_RETRY_COUNT_SENTINEL)
#define ICE_AGENT_STATE_NEW_REQUIRED          (ICE_AGENT_STATE_NONE | ICE_AGENT_STATE_NEW)
#define ICE_AGENT_STATE_CHECK_CONN_REQUIRED   (ICE_AGENT_STATE_NEW | ICE_AGENT_STATE_CHECK_CONNECTION)
#define ICE_AGENT_STATE_CONNECTED_REQUIRED    (ICE_AGENT_STATE_CHECK_CONNECTION | ICE_AGENT_STATE_CONNECTED)
#define ICE_AGENT_STATE_NOMINATING_REQUIRED   (ICE_AGENT_STATE_CONNECTED | ICE_AGENT_STATE_NOMINATING)
#define ICE_AGENT_STATE_READY_REQUIRED        (ICE_AGENT_STATE_CONNECTED | ICE_AGENT_STATE_NOMINATING | ICE_AGENT_STATE_READY | ICE_AGENT_STATE_DISCONNECTED)
#define ICE_AGENT_STATE_DISCONNECTED_REQUIRED (ICE_AGENT_STATE_CHECK_CONNECTION | ICE_AGENT_STATE_CONNECTED | ICE_AGENT_STATE_NOMINATING | ICE_AGENT_STATE_READY | ICE_AGENT_STATE_DISCONNECTED)
#define ICE_AGENT_STATE_FAILED_REQUIRED       (ICE_AGENT_STATE_CHECK_CONNECTION | ICE_AGENT_STATE_CONNECTED | ICE_AGENT_STATE_NOMINATING | ICE_AGENT_STATE_READY | ICE_AGENT_STATE_DISCONNECTED | ICE_AGENT_STATE_FAILED)

StateMachineState ICE_AGENT_STATE_MACHINE_STATES[] = {
    {ICE_AGENT_STATE_NEW,              ICE_AGENT_STATE_NEW_REQUIRED,        iceAgentFsmLeaveNew,             iceAgentFsmNew,             ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
    {ICE_AGENT_STATE_CHECK_CONNECTION, ICE_AGENT_STATE_CHECK_CONN_REQUIRED, iceAgentFsmLeaveCheckConnection, iceAgentFsmCheckConnection, ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
    {ICE_AGENT_STATE_CONNECTED,        ICE_AGENT_STATE_CONNECTED_REQUIRED,  iceAgentFsmLeaveConnected,       iceAgentFsmConnected,       ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
    {ICE_AGENT_STATE_NOMINATING,       ICE_AGENT_STATE_NOMINATING_REQUIRED, iceAgentFsmLeaveNominating,      iceAgentFsmNominating,      ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
    {ICE_AGENT_STATE_READY,            ICE_AGENT_STATE_READY_REQUIRED,      iceAgentFsmLeaveReady,           iceAgentFsmReady,           ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
    {ICE_AGENT_STATE_DISCONNECTED,     ICE_AGENT_STATE_DISCONNECTED_REQUIRED, iceAgentFsmLeaveDisconnected,  iceAgentFsmDisconnected,    ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
    {ICE_AGENT_STATE_FAILED,           ICE_AGENT_STATE_FAILED_REQUIRED,      iceAgentFsmLeaveFailed,         iceAgentFsmFailed,          ICE_AGENT_STATE_UNLIMIT_RETRY, STATUS_ICE_INVALID_STATE},
};

UINT32 ICE_AGENT_STATE_MACHINE_STATE_COUNT = ARRAY_SIZE(ICE_AGENT_STATE_MACHINE_STATES);
/**
 * @brief advance the fsm of the ice agent.
 * 
 * @param[in] the object of the ice agent.
*/
STATUS iceAgentFsmAdvance(PIceAgent pIceAgent)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 oldState;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);

    oldState = pIceAgent->iceAgentState;

    CHK_STATUS(stepStateMachine(pIceAgent->pStateMachine));

    // if any failure happened and state machine is not in failed state, stepStateMachine again into failed state.
    if (pIceAgent->iceAgentState != ICE_AGENT_STATE_FAILED && STATUS_FAILED(pIceAgent->iceAgentStatus)) {
        CHK_STATUS(stepStateMachine(pIceAgent->pStateMachine));
    }

    if (oldState != pIceAgent->iceAgentState) {
        if (pIceAgent->iceAgentCallbacks.connectionStateChangedFn != NULL) {
            DLOGD("Ice agent state changed from %s to %s.", iceAgentStateToString(oldState), iceAgentStateToString(pIceAgent->iceAgentState));
            pIceAgent->iceAgentCallbacks.connectionStateChangedFn(pIceAgent->iceAgentCallbacks.customData, pIceAgent->iceAgentState);
        }
    } else {
        // state machine retry is not used. resetStateMachineRetryCount just to avoid
        // state machine retry grace period overflow warning.
        DLOGD("weird situation");
        CHK_STATUS(resetStateMachineRetryCount(pIceAgent->pStateMachine));
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

STATUS acceptIceAgentMachineState(PIceAgent pIceAgent, UINT64 state)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // Step the state machine
    CHK_STATUS(acceptStateMachineState(pIceAgent->pStateMachine, state));

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    LEAVES();
    return retStatus;
}

/*
 * This function is supposed to be called from within IceAgentStateMachine callbacks. Assume holding IceAgent->lock
 */
STATUS iceAgentFsmCheckDisconnection(PIceAgent pIceAgent, PUINT64 pNextState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 currentTime;

    CHK(pIceAgent != NULL && pNextState != NULL, STATUS_NULL_ARG);

    currentTime = GETTIME();
    if (!pIceAgent->detectedDisconnection && IS_VALID_TIMESTAMP(pIceAgent->lastDataReceivedTime) &&
        pIceAgent->lastDataReceivedTime + KVS_ICE_ENTER_STATE_DISCONNECTION_GRACE_PERIOD <= currentTime) {
        *pNextState = ICE_AGENT_STATE_DISCONNECTED;
    } else if (pIceAgent->detectedDisconnection) {
        if (IS_VALID_TIMESTAMP(pIceAgent->lastDataReceivedTime) &&
            pIceAgent->lastDataReceivedTime + KVS_ICE_ENTER_STATE_DISCONNECTION_GRACE_PERIOD > currentTime) {
            // recovered from disconnection
            DLOGD("recovered from disconnection");
            pIceAgent->detectedDisconnection = FALSE;
            if (pIceAgent->iceAgentCallbacks.connectionStateChangedFn != NULL) {
                pIceAgent->iceAgentCallbacks.connectionStateChangedFn(pIceAgent->iceAgentCallbacks.customData, pIceAgent->iceAgentState);
            }
        } else if (currentTime >= pIceAgent->disconnectionGracePeriodEndTime) {
            CHK(FALSE, STATUS_ICE_FAILED_TO_RECOVER_FROM_DISCONNECTION);
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief the transformation between state and string. #YC_TBD. 
 * 
 * @param[in] state 
*/
PCHAR iceAgentStateToString(UINT64 state)
{
    PCHAR stateStr = NULL;
    switch (state) {
        case ICE_AGENT_STATE_NONE:
            stateStr = ICE_AGENT_STATE_NONE_STR;
            break;
        case ICE_AGENT_STATE_NEW:
            stateStr = ICE_AGENT_STATE_NEW_STR;
            break;
        case ICE_AGENT_STATE_CHECK_CONNECTION:
            stateStr = ICE_AGENT_STATE_CHECK_CONNECTION_STR;
            break;
        case ICE_AGENT_STATE_CONNECTED:
            stateStr = ICE_AGENT_STATE_CONNECTED_STR;
            break;
        case ICE_AGENT_STATE_NOMINATING:
            stateStr = ICE_AGENT_STATE_NOMINATING_STR;
            break;
        case ICE_AGENT_STATE_READY:
            stateStr = ICE_AGENT_STATE_READY_STR;
            break;
        case ICE_AGENT_STATE_DISCONNECTED:
            stateStr = ICE_AGENT_STATE_DISCONNECTED_STR;
            break;
        case ICE_AGENT_STATE_FAILED:
            stateStr = ICE_AGENT_STATE_FAILED_STR;
            break;
    }

    return stateStr;
}

///////////////////////////////////////////////////////////////////////////
// State machine callback functions
///////////////////////////////////////////////////////////////////////////
STATUS iceAgentFsmLeaveNew(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    UINT64 state;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    // go directly to next state
    state = ICE_AGENT_STATE_CHECK_CONNECTION;

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmNew(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);
    // return early if we are already in ICE_AGENT_STATE_GATHERING
    CHK(pIceAgent->iceAgentState != ICE_AGENT_STATE_NEW, retStatus);

    pIceAgent->iceAgentState = ICE_AGENT_STATE_NEW;

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief move to another state from the state of ICE_AGENT_STATE_CHECK_CONNECTION.
 * 
 * @param[in] the object of the ice agent.
 * @param[out] pState the next state
*/
STATUS iceAgentFsmLeaveCheckConnection(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    UINT64 state = ICE_AGENT_STATE_CHECK_CONNECTION; // original state
    BOOL connectedCandidatePairFound = FALSE;
    UINT64 currentTime = GETTIME();
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // move to failed state if any error happened.
    CHK_STATUS(pIceAgent->iceAgentStatus);

    // return early if changing to disconnected state
    CHK(state != ICE_AGENT_STATE_DISCONNECTED, retStatus);

    // connected pair found ? go to ICE_AGENT_STATE_CONNECTED : timeout ? go to error : remain in ICE_AGENT_STATE_CHECK_CONNECTION
    /**
     * search the first candidate pair with succeeded state.
    */
    CHK_STATUS(doubleListGetHeadNode(pIceAgent->iceCandidatePairs, &pCurNode));
    while (pCurNode != NULL && !connectedCandidatePairFound) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            connectedCandidatePairFound = TRUE;
            state = ICE_AGENT_STATE_CONNECTED;
        }
    }

    // return error if no connected pair found within timeout
    if (!connectedCandidatePairFound && currentTime >= pIceAgent->stateEndTime) {
        retStatus = STATUS_ICE_NO_CONNECTED_CANDIDATE_PAIR;
    }

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        state = ICE_AGENT_STATE_FAILED;
        pIceAgent->iceAgentStatus = retStatus;
        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    if (pState != NULL) {
        *pState = state;
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief send the stun packet on all the valid candidate pair. 
 *          make sure you already have candidate pair.
 * 
 * @param[]
 * @param[]
 * 
*/
STATUS iceAgentFsmCheckConnection(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);
    MUTEX_LOCK(pIceAgent->lock);
    UINT32 iceCandidatePairCount = 0;
    CHK_STATUS(doubleListGetNodeCount(pIceAgent->iceCandidatePairs, &iceCandidatePairCount));
    MUTEX_UNLOCK(pIceAgent->lock);
    /** reduce the effort if we are already in the state of check_connection. */
    if (pIceAgent->iceAgentState != ICE_AGENT_STATE_CHECK_CONNECTION || iceCandidatePairCount==0) {
        CHK_STATUS(iceAgentCheckConnectionStateSetup(pIceAgent));
        pIceAgent->iceAgentState = ICE_AGENT_STATE_CHECK_CONNECTION;
    }
    /** send the stun packet to probe the ice candidate pair. */
    CHK_STATUS(iceAgentCheckCandidatePairConnection(pIceAgent));

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        pIceAgent->iceAgentStatus = retStatus;

        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmLeaveConnected(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    UINT64 state = ICE_AGENT_STATE_CONNECTED; // original state
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // move to failed state if any error happened.
    CHK_STATUS(pIceAgent->iceAgentStatus);

    // return early if changing to disconnected state
    CHK(state != ICE_AGENT_STATE_DISCONNECTED, retStatus);

    // Go directly to nominating state from connected state.
    state = ICE_AGENT_STATE_NOMINATING;

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        state = ICE_AGENT_STATE_FAILED;
        pIceAgent->iceAgentStatus = retStatus;
        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    if (pState != NULL) {
        *pState = state;
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmConnected(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);

    CHK_STATUS(iceAgentConnectedStateSetup(pIceAgent));

    pIceAgent->iceAgentState = ICE_AGENT_STATE_CONNECTED;

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        pIceAgent->iceAgentStatus = retStatus;

        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmLeaveNominating(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    UINT64 state = ICE_AGENT_STATE_NOMINATING; // original state
    UINT64 currentTime = GETTIME();
    BOOL nominatedAndValidCandidatePairFound = FALSE, locked = FALSE;
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // move to failed state if any error happened.
    CHK_STATUS(pIceAgent->iceAgentStatus);

    // return early if changing to disconnected state
    CHK(state != ICE_AGENT_STATE_DISCONNECTED, retStatus);

    // has a nominated and connected pair ? go to ICE_AGENT_STATE_READY : timeout ? go to failed state : remain in ICE_AGENT_STATE_NOMINATING

    CHK_STATUS(doubleListGetHeadNode(pIceAgent->iceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->nominated && pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            nominatedAndValidCandidatePairFound = TRUE;
            break;
        }
    }

    if (nominatedAndValidCandidatePairFound) {
        state = ICE_AGENT_STATE_READY;
    } else if (currentTime >= pIceAgent->stateEndTime) {
        CHK(FALSE, STATUS_ICE_FAILED_TO_NOMINATE_CANDIDATE_PAIR);
    }

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        state = ICE_AGENT_STATE_FAILED;
        pIceAgent->iceAgentStatus = retStatus;
        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    if (pState != NULL) {
        *pState = state;
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief 
 * 
 * @param[]
 * @param[]
 * 
*/
STATUS iceAgentFsmNominating(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);

    if (pIceAgent->iceAgentState != ICE_AGENT_STATE_NOMINATING) {
        CHK_STATUS(iceAgentNominatingStateSetup(pIceAgent));
        pIceAgent->iceAgentState = ICE_AGENT_STATE_NOMINATING;
    }

    if (pIceAgent->isControlling) {
        CHK_STATUS(iceAgentSendCandidateNomination(pIceAgent));
    } else {
        // if not controlling, keep sending connection checks and wait for peer
        // to nominate a pair.
        CHK_STATUS(iceAgentCheckCandidatePairConnection(pIceAgent));
    }

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        pIceAgent->iceAgentStatus = retStatus;

        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief 
 * 
 * @param[]
 * @param[]
*/
STATUS iceAgentFsmLeaveReady(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    UINT64 state = ICE_AGENT_STATE_READY; // original state
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // move to failed state if any error happened.
    CHK_STATUS(pIceAgent->iceAgentStatus);

    CHK_STATUS(iceAgentFsmCheckDisconnection(pIceAgent, &state));
    // return early if changing to disconnected state
    CHK(state != ICE_AGENT_STATE_DISCONNECTED, retStatus);

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        state = ICE_AGENT_STATE_FAILED;
        pIceAgent->iceAgentStatus = retStatus;
        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    if (pState != NULL) {
        *pState = state;
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmReady(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);

    if (pIceAgent->iceAgentState != ICE_AGENT_STATE_READY) {
        CHK_STATUS(iceAgentReadyStateSetup(pIceAgent));
        pIceAgent->iceAgentState = ICE_AGENT_STATE_READY;
    }

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        pIceAgent->iceAgentStatus = retStatus;

        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmLeaveDisconnected(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    UINT64 state = pIceAgent->iceAgentState; // state before ICE_AGENT_STATE_DISCONNECTED
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // move to failed state if any error happened.
    CHK_STATUS(pIceAgent->iceAgentStatus);

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        state = ICE_AGENT_STATE_FAILED;
        pIceAgent->iceAgentStatus = retStatus;
        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    if (pState != NULL) {
        *pState = state;
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    LEAVES();
    return retStatus;
}
/**
 * @brief 
 * @param[]
 * @param[]
*/
STATUS iceAgentFsmDisconnected(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);
    CHK(pIceAgent->iceAgentState != ICE_AGENT_STATE_DISCONNECTED, retStatus);

    // not stopping timer task from previous state as we want it to continue and perhaps recover.
    // not setting pIceAgent->iceAgentState as it stores the previous state and we want to step back into it to continue retry
    DLOGD("Ice agent detected disconnection. current state %s. Last data received time %" PRIu64 " s",
          iceAgentStateToString(pIceAgent->iceAgentState), pIceAgent->lastDataReceivedTime / HUNDREDS_OF_NANOS_IN_A_SECOND);
    pIceAgent->detectedDisconnection = TRUE;

    // after detecting disconnection, store disconnectionGracePeriodEndTime and when it is reached and ice still hasnt recover
    // then go to failed state.
    pIceAgent->disconnectionGracePeriodEndTime = GETTIME() + KVS_ICE_ENTER_STATE_FAILED_GRACE_PERIOD;

    if (pIceAgent->iceAgentCallbacks.connectionStateChangedFn != NULL) {
        pIceAgent->iceAgentCallbacks.connectionStateChangedFn(pIceAgent->iceAgentCallbacks.customData, ICE_AGENT_STATE_DISCONNECTED);
    }

    // step out of disconnection state to retry. Do not use stepIceAgentState machine because lock is not re-entrant.
    CHK_STATUS(stepStateMachine(pIceAgent->pStateMachine));

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        pIceAgent->iceAgentStatus = retStatus;

        // fix up retStatus so we can successfully transition to failed state.
        retStatus = STATUS_SUCCESS;
    }

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmLeaveFailed(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL && pState != NULL, STATUS_NULL_ARG);

    // FAILED state is terminal.
    *pState = ICE_AGENT_STATE_FAILED;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS iceAgentFsmFailed(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    const PCHAR errMsgPrefix = (PCHAR) "IceAgent fatal error:";

    CHK(pIceAgent != NULL, STATUS_NULL_ARG);
    CHK(pIceAgent->iceAgentState != ICE_AGENT_STATE_FAILED, retStatus);

    pIceAgent->iceAgentState = ICE_AGENT_STATE_FAILED;

    // log some debug info about the failure once.
    switch (pIceAgent->iceAgentStatus) {
        case STATUS_ICE_NO_AVAILABLE_ICE_CANDIDATE_PAIR:
            DLOGE("%s No ice candidate pairs available to make connection.", errMsgPrefix);
            break;
        default:
            DLOGE("IceAgent failed with 0x%08x", pIceAgent->iceAgentStatus);
            break;
    }

CleanUp:

    LEAVES();
    return retStatus;
}
