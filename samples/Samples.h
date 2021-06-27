/*******************************************
Shared include file for the samples
*******************************************/
#ifndef __KINESIS_VIDEO_SAMPLE_INCLUDE__
#define __KINESIS_VIDEO_SAMPLE_INCLUDE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <com/amazonaws/kinesis/video/webrtcclient/Include.h>
#include <gst/gst.h>
#include <gst/app/gstappsink.h>

#define STATUS_SAMPLE_BASE   0x70000000
#define STATUS_SAMPLE_FAILED STATUS_SAMPLE_BASE + 0x00000001

#define STATUS_GST_BASE              STATUS_SAMPLE_BASE + 0x01000000
#define STATUS_GST_FAILED            STATUS_GST_BASE + 0x00000001
#define STATUS_GST_DUMMY_SINK        STATUS_GST_BASE + 0x00000002
#define STATUS_GST_VIDEO_SINK        STATUS_GST_BASE + 0x00000003
#define STATUS_GST_AUDIO_SINK        STATUS_GST_BASE + 0x00000004
#define STATUS_GST_LINK_ELEMENT      STATUS_GST_BASE + 0x00000005
#define STATUS_GST_VIDEO_ELEMENT     STATUS_GST_BASE + 0x00000006
#define STATUS_GST_AUDIO_ELEMENT     STATUS_GST_BASE + 0x00000007
#define STATUS_GST_DUMMY_ELEMENT     STATUS_GST_BASE + 0x00000008
#define STATUS_GST_EMPTY_ELEMENT     STATUS_GST_BASE + 0x00000009
#define STATUS_GST_UNSUPPORTED_VIDEO STATUS_GST_BASE + 0x0000000A
#define STATUS_GST_UNSUPPORTED_AUDIO STATUS_GST_BASE + 0x0000000B

#define NUMBER_OF_H264_FRAME_FILES               1500
#define NUMBER_OF_OPUS_FRAME_FILES               618
#define DEFAULT_FPS_VALUE                        25
#define DEFAULT_MAX_CONCURRENT_STREAMING_SESSION 10

#define SAMPLE_MASTER_CLIENT_ID "ProducerMaster"
#define SAMPLE_VIEWER_CLIENT_ID "ConsumerViewer"
#define SAMPLE_CHANNEL_NAME     (PCHAR) "ScaryTestChannel"

#define SAMPLE_AUDIO_FRAME_DURATION (20 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)
#define SAMPLE_STATS_DURATION       (60 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define SAMPLE_VIDEO_FRAME_DURATION (HUNDREDS_OF_NANOS_IN_A_SECOND / DEFAULT_FPS_VALUE)

#define SAMPLE_PRE_GENERATE_CERT        TRUE
#define SAMPLE_PRE_GENERATE_CERT_PERIOD (1000 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)

#define SAMPLE_SESSION_CLEANUP_WAIT_PERIOD (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define SAMPLE_PENDING_MESSAGE_CLEANUP_DURATION (20 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define CA_CERT_PEM_FILE_EXTENSION ".pem"

#define FILE_LOGGING_BUFFER_SIZE (100 * 1024)
#define MAX_NUMBER_OF_LOG_FILES  5

#define SAMPLE_HASH_TABLE_BUCKET_COUNT  50
#define SAMPLE_HASH_TABLE_BUCKET_LENGTH 2

#define SAMPLE_RTSP_USERNAME_LEN MAX_CHANNEL_NAME_LEN
#define SAMPLE_RTSP_PASSWORD_LEN MAX_CHANNEL_NAME_LEN

#define IOT_CORE_CREDENTIAL_ENDPOINT ((PCHAR) "AWS_IOT_CORE_CREDENTIAL_ENDPOINT")
#define IOT_CORE_CERT                ((PCHAR) "AWS_IOT_CORE_CERT")
#define IOT_CORE_PRIVATE_KEY         ((PCHAR) "AWS_IOT_CORE_PRIVATE_KEY")
#define IOT_CORE_ROLE_ALIAS          ((PCHAR) "AWS_IOT_CORE_ROLE_ALIAS")
#define IOT_CORE_THING_NAME          ((PCHAR) "AWS_IOT_CORE_THING_NAME")

#define ECS_AUTH_TOKEN           ((PCHAR) "AWS_CONTAINER_AUTHORIZATION_TOKEN")
#define ECS_CREDENTIALS_FULL_URI ((PCHAR) "AWS_CONTAINER_CREDENTIALS_FULL_URI")

#define RTSP_CHANNEL  ((PCHAR) "AWS_RTSP_CHANNEL")
#define RTSP_URI      ((PCHAR) "AWS_RTSP_URI")
#define RTSP_USERNAME ((PCHAR) "AWS_RTSP_USERNAME")
#define RTSP_PASSWORD ((PCHAR) "AWS_RTSP_PASSWORD")

#define GST_ELEMENT_NAME_MAX_LEN 256

/* Uncomment the following line in order to enable IoT credentials checks in the provided samples */
//#define IOT_CORE_ENABLE_CREDENTIALS 1
#define ECS_ENABLE_CREDENTIALS 1

typedef VOID (*StreamingSessionHook)(PSampleConfiguration, PSampleStreamingSession);

typedef enum {
    SAMPLE_STREAMING_VIDEO_ONLY,
    SAMPLE_STREAMING_AUDIO_VIDEO,
} SampleStreamingMediaType;

typedef struct __SampleStreamingSession SampleStreamingSession;
typedef struct __SampleStreamingSession* PSampleStreamingSession;

typedef struct {
    UINT64 prevNumberOfPacketsSent;
    UINT64 prevNumberOfPacketsReceived;
    UINT64 prevNumberOfBytesSent;
    UINT64 prevNumberOfBytesReceived;
    UINT64 prevPacketsDiscardedOnSend;
    UINT64 prevTs;
} RtcMetricsHistory, *PRtcMetricsHistory;

#define GST_ENCODING_NAME_MAX_LEN 256
typedef struct {
    RTC_CODEC codec;
    CHAR encodingName[GST_ENCODING_NAME_MAX_LEN];
    UINT32 payloadType;
    UINT32 clockRate;
} CodecStreamConf, *PCodecStreamConf;

typedef struct {
    GMainLoop* mainLoop;  //!< the main runner for gstreamer.
    GstElement* pipeline; //!< the pipeline for the rtsp url.
    CodecStreamConf videoStream;
    CodecStreamConf audioStream;
} CodecConfiguration, *PCodecConfiguration;

typedef struct {
    CHAR uri[MAX_URI_CHAR_LEN];              //!< the rtsp url.
    CHAR channel[MAX_CHANNEL_NAME_LEN];      //!< the signaling channgel for the rtsp url.
    CHAR username[SAMPLE_RTSP_USERNAME_LEN]; //!< the username to login the rtsp url.
    CHAR password[SAMPLE_RTSP_PASSWORD_LEN]; //!< the password to login the rtsp url.
} RtspCameraConfiguration, *PRtspCameraConfiguration;

typedef struct {
    volatile ATOMIC_BOOL appTerminateFlag;
    volatile ATOMIC_BOOL interrupted;
    volatile ATOMIC_BOOL mediaThreadStarted; //!< the flag to identify the status of the media thread.
    volatile ATOMIC_BOOL recreateSignalingClient;
    volatile ATOMIC_BOOL connected;

    BOOL useTestSrc;
    ChannelInfo channelInfo;
    PCHAR pCaCertPath;
    PAwsCredentialProvider pCredentialProvider;
    SIGNALING_CLIENT_HANDLE signalingClientHandle;
    PBYTE pAudioFrameBuffer;
    UINT32 audioBufferSize;
    PBYTE pVideoFrameBuffer;
    UINT32 videoBufferSize;
    TID mediaSenderTid;
    TIMER_QUEUE_HANDLE timerQueueHandle;
    UINT32 iceCandidatePairStatsTimerId;
    SampleStreamingMediaType mediaType;
    startRoutine audioSource;
    startRoutine videoSource;
    startRoutine receiveAudioVideoSource;
    RtcOnDataChannel onDataChannel;

    TID signalingProcessor;
    PStackQueue pPendingSignalingMessageForRemoteClient;
    PHashTable pRtcPeerConnectionForRemoteClient;

    MUTEX sampleConfigurationObjLock;
    CVAR cvar;
    BOOL trickleIce;
    BOOL useTurn;
    BOOL enableFileLogging;
    UINT64 customData;
    PSampleStreamingSession sampleStreamingSessionList[DEFAULT_MAX_CONCURRENT_STREAMING_SESSION];
    UINT32 streamingSessionCount;
    MUTEX streamingSessionListReadLock; //!< the lock of streaming session.
    UINT32 iceUriCount;
    SignalingClientCallbacks signalingClientCallbacks;
    SignalingClientInfo clientInfo;
    RtcStats rtcIceCandidatePairMetrics;

    MUTEX signalingSendMessageLock;
    UINT32 pregenerateCertTimerId;
    PStackQueue pregeneratedCertificates; // Max MAX_RTCCONFIGURATION_CERTIFICATES certificates

    StreamingSessionHook createStreamingSessionPreHook;
    StreamingSessionHook createStreamingSessionPostHook;
    StreamingSessionHook freeStreamingSessionPreHook;
    StreamingSessionHook freeStreamingSessionPostHook;
    volatile ATOMIC_BOOL terminateCodecFlag;
    volatile ATOMIC_BOOL codecConfigLatched;
    MUTEX codecConfLock;
    CodecConfiguration codecConfiguration;           //!< the configuration of gstreamer.
    RtspCameraConfiguration rtspCameraConfiguration; //!< the configuration of rtsp camera.
} SampleConfiguration, *PSampleConfiguration;

typedef struct {
    UINT64 hashValue;
    UINT64 createTime;
    PStackQueue messageQueue;
} PendingMessageQueue, *PPendingMessageQueue;

typedef VOID (*StreamSessionShutdownCallback)(UINT64, PSampleStreamingSession);

struct __SampleStreamingSession {
    volatile ATOMIC_BOOL terminateFlag;
    volatile ATOMIC_BOOL candidateGatheringDone;
    volatile ATOMIC_BOOL peerIdReceived;
    volatile SIZE_T frameIndex;
    PRtcPeerConnection pPeerConnection;
    PRtcRtpTransceiver pVideoRtcRtpTransceiver;
    PRtcRtpTransceiver pAudioRtcRtpTransceiver;
    RtcSessionDescriptionInit answerSessionDescriptionInit;
    PSampleConfiguration pSampleConfiguration;
    UINT64 audioTimestamp;
    UINT64 videoTimestamp;
    CHAR peerId[MAX_SIGNALING_CLIENT_ID_LEN + 1];
    TID receiveAudioVideoSenderTid;
    UINT64 offerReceiveTime;
    UINT64 startUpLatency;
    BOOL firstKeyFrame; //!< the first key frame of this session is sent or not.
    BOOL firstFrame;
    RtcMetricsHistory rtcMetricsHistory;
    BOOL remoteCanTrickleIce;

    // this is called when the SampleStreamingSession is being freed
    StreamSessionShutdownCallback shutdownCallback;
    UINT64 shutdownCallbackCustomData;
};

VOID sigintHandler(INT32);
STATUS readFrameFromDisk(PBYTE, PUINT32, PCHAR);
PVOID sendVideoPackets(PVOID);
PVOID sendAudioPackets(PVOID);
PVOID sendGstreamerAudioVideo(PVOID);
PVOID sampleReceiveVideoFrame(PVOID args);
PVOID getPeriodicIceCandidatePairStats(PVOID);
STATUS getIceCandidatePairStatsCallback(UINT32, UINT64, UINT64);
STATUS pregenerateCertTimerCallback(UINT32, UINT64, UINT64);
STATUS createSampleConfiguration(PCHAR, SIGNALING_CHANNEL_ROLE_TYPE, BOOL, BOOL, PSampleConfiguration*);
STATUS freeSampleConfiguration(PSampleConfiguration*);
STATUS signalingClientStateChanged(UINT64, SIGNALING_CLIENT_STATE);
STATUS signalingMessageReceived(UINT64, PReceivedSignalingMessage);
STATUS handleAnswer(PSampleConfiguration, PSampleStreamingSession, PSignalingMessage);
STATUS handleOffer(PSampleConfiguration, PSampleStreamingSession, PSignalingMessage);
STATUS handleRemoteCandidate(PSampleStreamingSession, PSignalingMessage);
STATUS initializePeerConnection(PSampleConfiguration, PRtcPeerConnection*);
STATUS lookForSslCert(PSampleConfiguration*);
STATUS createSampleStreamingSession(PSampleConfiguration, PCHAR, BOOL, PSampleStreamingSession*);
STATUS freeSampleStreamingSession(PSampleStreamingSession*);
STATUS streamingSessionOnShutdown(PSampleStreamingSession, UINT64, StreamSessionShutdownCallback);
STATUS sendSignalingMessage(PSampleStreamingSession, PSignalingMessage);
STATUS respondWithAnswer(PSampleStreamingSession);
STATUS resetSampleConfigurationState(PSampleConfiguration);
VOID sampleFrameHandler(UINT64, PFrame);
VOID sampleBandwidthEstimationHandler(UINT64, DOUBLE);
VOID sampleSenderBandwidthEstimationHandler(UINT64, UINT32, UINT32, UINT32, UINT32, UINT64);
VOID onDataChannel(UINT64, PRtcDataChannel);
VOID onConnectionStateChange(UINT64, RTC_PEER_CONNECTION_STATE);
STATUS sessionCleanupWait(PSampleConfiguration);
STATUS logSignalingClientStats(PSignalingClientMetrics);
STATUS logSelectedIceCandidatesInformation(PSampleStreamingSession);
STATUS logStartUpLatency(PSampleConfiguration);
STATUS createMessageQueue(UINT64, PPendingMessageQueue*);
STATUS freeMessageQueue(PPendingMessageQueue);
STATUS submitPendingIceCandidate(PPendingMessageQueue, PSampleStreamingSession);
STATUS removeExpiredMessageQueues(PStackQueue);
STATUS getPendingMessageQueueForHash(PStackQueue, UINT64, BOOL, PPendingMessageQueue*);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_SAMPLE_INCLUDE__ */
