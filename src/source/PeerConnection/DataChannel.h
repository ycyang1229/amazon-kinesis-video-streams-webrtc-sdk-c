/*******************************************
DataChannel internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_DATACHANNEL__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_DATACHANNEL__

#if (ENABLE_DATA_CHANNEL)
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    RtcDataChannel dataChannel;

    PRtcPeerConnection pRtcPeerConnection;
    RtcDataChannelInit rtcDataChannelInit;//!< the initial setting for datat channel.
    UINT32 channelId;///!< the data channel id or the stream id of sctp session.
    UINT64 onMessageCustomData;
    RtcOnMessage onMessage;//!< the callback of the notification of receiving message over data channel for the external peer connection interface.

    UINT64 onOpenCustomData;
    RtcOnOpen onOpen;
} KvsDataChannel, *PKvsDataChannel;

#ifdef __cplusplus
}
#endif
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_DATACHANNEL__ */
