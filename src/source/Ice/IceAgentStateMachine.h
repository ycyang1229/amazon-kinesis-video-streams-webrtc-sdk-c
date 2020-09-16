/*******************************************
Signaling State Machine internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_ICE_STATE_MACHINE__
#define __KINESIS_VIDEO_WEBRTC_ICE_STATE_MACHINE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Ice states definitions
 *
 * ICE_AGENT_STATE_NONE:                        Dummy state
 * ICE_AGENT_STATE_NEW:                         State at creation
 * ICE_AGENT_STATE_CHECK_CONNECTION:            Checking candidate pair connectivity
 * ICE_AGENT_STATE_CONNECTED:                   At least one working candidate pair
 * ICE_AGENT_STATE_NOMINATING:                  Waiting for connectivity check to succeed for the nominated cadidate pair
 * ICE_AGENT_STATE_READY:                       Selected candidate pair is now final
 * ICE_AGENT_STATE_DISCONNECTED:                Lost connection after ICE_AGENT_STATE_READY
 * ICE_AGENT_STATE_FAILED:                      Terminal state with an error stored in iceAgentStatus
 */
#define ICE_AGENT_STATE_NONE             ((UINT64) 0)
#define ICE_AGENT_STATE_NEW              ((UINT64)(1 << 0))
#define ICE_AGENT_STATE_CHECK_CONNECTION ((UINT64)(1 << 1))
#define ICE_AGENT_STATE_CONNECTED        ((UINT64)(1 << 2))
#define ICE_AGENT_STATE_NOMINATING       ((UINT64)(1 << 3))
#define ICE_AGENT_STATE_READY            ((UINT64)(1 << 4))
#define ICE_AGENT_STATE_DISCONNECTED     ((UINT64)(1 << 5))
#define ICE_AGENT_STATE_FAILED           ((UINT64)(1 << 6))

#define ICE_AGENT_STATE_NONE_STR             (PCHAR) "ICE_AGENT_STATE_NONE"
#define ICE_AGENT_STATE_NEW_STR              (PCHAR) "ICE_AGENT_STATE_NEW"
#define ICE_AGENT_STATE_CHECK_CONNECTION_STR (PCHAR) "ICE_AGENT_STATE_CHECK_CONNECTION"
#define ICE_AGENT_STATE_CONNECTED_STR        (PCHAR) "ICE_AGENT_STATE_CONNECTED"
#define ICE_AGENT_STATE_NOMINATING_STR       (PCHAR) "ICE_AGENT_STATE_NOMINATING"
#define ICE_AGENT_STATE_READY_STR            (PCHAR) "ICE_AGENT_STATE_READY"
#define ICE_AGENT_STATE_DISCONNECTED_STR     (PCHAR) "ICE_AGENT_STATE_DISCONNECTED"
#define ICE_AGENT_STATE_FAILED_STR           (PCHAR) "ICE_AGENT_STATE_FAILED"

// Whether to step the state machine
STATUS iceAgentFsmAdvance(PIceAgent);
STATUS acceptIceAgentMachineState(PIceAgent, UINT64);
STATUS iceAgentFsmCheckDisconnection(PIceAgent, PUINT64);
PCHAR iceAgentStateToString(UINT64);

/**
 * Signaling state machine callbacks
 */
STATUS iceAgentFsmLeaveNew(UINT64, PUINT64);
STATUS iceAgentFsmNew(UINT64, UINT64);
STATUS iceAgentFsmLeaveCheckConnection(UINT64, PUINT64);
STATUS iceAgentFsmCheckConnection(UINT64, UINT64);
STATUS iceAgentFsmLeaveConnected(UINT64, PUINT64);
STATUS iceAgentFsmConnected(UINT64, UINT64);
STATUS iceAgentFsmLeaveNominating(UINT64, PUINT64);
STATUS iceAgentFsmNominating(UINT64, UINT64);
STATUS iceAgentFsmLeaveReady(UINT64, PUINT64);
STATUS iceAgentFsmReady(UINT64, UINT64);
STATUS iceAgentFsmLeaveDisconnected(UINT64, PUINT64);
STATUS iceAgentFsmDisconnected(UINT64, UINT64);
STATUS iceAgentFsmLeaveFailed(UINT64, PUINT64);
STATUS iceAgentFsmFailed(UINT64, UINT64);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_ICE_STATE_MACHINE__ */
