/*******************************************
Signaling State Machine internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_SIGNALING_STATE_MACHINE__
#define __KINESIS_VIDEO_WEBRTC_SIGNALING_STATE_MACHINE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Signaling states definitions
 */
#define SIGNALING_STATE_NONE           ((UINT64) 0)
#define SIGNALING_STATE_NEW            ((UINT64)(1 << 0))
#define SIGNALING_STATE_GET_TOKEN      ((UINT64)(1 << 1))
#define SIGNALING_STATE_DESCRIBE       ((UINT64)(1 << 2))
#define SIGNALING_STATE_CREATE         ((UINT64)(1 << 3))
#define SIGNALING_STATE_GET_ENDPOINT   ((UINT64)(1 << 4))
#define SIGNALING_STATE_GET_ICE_CONFIG ((UINT64)(1 << 5))
#define SIGNALING_STATE_READY          ((UINT64)(1 << 6))
#define SIGNALING_STATE_CONNECT        ((UINT64)(1 << 7))
#define SIGNALING_STATE_CONNECTED      ((UINT64)(1 << 8))
#define SIGNALING_STATE_DISCONNECTED   ((UINT64)(1 << 9))
#define SIGNALING_STATE_DELETE         ((UINT64)(1 << 10))
#define SIGNALING_STATE_DELETED        ((UINT64)(1 << 11))

// Indicates infinite retries
#define INFINITE_RETRY_COUNT_SENTINEL 0

// Whether to step the state machine
STATUS signalingFsmStep(PSignalingClient, STATUS);

STATUS signalingFsmAccept(PSignalingClient, UINT64);
SIGNALING_CLIENT_STATE signalingFsmGetState(UINT64);

/**
 * Signaling state machine callbacks
 */
STATUS signalingFsmFromNew(UINT64, PUINT64);
STATUS signalingFsmNew(UINT64, UINT64);
STATUS signalingFsmFromGetToken(UINT64, PUINT64);
STATUS signalingFsmGetToken(UINT64, UINT64);
STATUS signalingFsmFromDescribe(UINT64, PUINT64);
STATUS signalingFsmDescribe(UINT64, UINT64);
STATUS signalingFsmFromCreate(UINT64, PUINT64);
STATUS signalingFsmCreate(UINT64, UINT64);
STATUS signalingFsmFromGetEndpoint(UINT64, PUINT64);
STATUS signalingFsmGetEndpoint(UINT64, UINT64);
STATUS signalingFsmFromGetIceConfig(UINT64, PUINT64);
STATUS signalingFsmGetIceConfig(UINT64, UINT64);
STATUS signalingFsmFromReady(UINT64, PUINT64);
STATUS signalingFsmReady(UINT64, UINT64);
STATUS signalingFsmFromConnect(UINT64, PUINT64);
STATUS signalingFsmConnect(UINT64, UINT64);
STATUS signalingFsmFromConnected(UINT64, PUINT64);
STATUS signalingFsmConnected(UINT64, UINT64);
STATUS signalingFsmFromDisconnected(UINT64, PUINT64);
STATUS signalingFsmDisconnected(UINT64, UINT64);
STATUS signalingFsmFromDelete(UINT64, PUINT64);
STATUS signalingFsmDelete(UINT64, UINT64);
STATUS signalingFsmFromDeleted(UINT64, PUINT64);
STATUS signalingFsmDeleted(UINT64, UINT64);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_SIGNALING_STATE_MACHINE__ */
