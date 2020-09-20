//
// Sctp
//

#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_SCTP_SCTP__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_SCTP_SCTP__

#if (ENABLE_DATA_CHANNEL)

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief https://tools.ietf.org/html/rfc4960#section-3
 * 
 *  The SCTP packet format is shown below:
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Common Header                                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Chunk #1                                                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | ...                                                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Chunk #n                                                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * 
 *  https://tools.ietf.org/html/rfc4960#section-3.3.1
 *  SCTP Common Header Field Descriptions
 *  SCTP Common Header Format
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Source Port Number            | Destination Port Number       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Verification Tag                                              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Checksum                                                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * 
*/


// 1200 - 12 (SCTP header Size)
#define SCTP_MTU                         1188
/** https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.2 */
#define SCTP_ASSOCIATION_DEFAULT_PORT    5000
/** https://tools.ietf.org/html/draft-ietf-mmusic-data-channel-sdpneg-28 */
#define SCTP_DCEP_HEADER_LENGTH          12
#define SCTP_DCEP_LABEL_LEN_OFFSET       8
#define SCTP_DCEP_LABEL_OFFSET           12
#define SCTP_MAX_ALLOWABLE_PACKET_LENGTH (SCTP_DCEP_HEADER_LENGTH + MAX_DATA_CHANNEL_NAME_LEN + MAX_DATA_CHANNEL_PROTOCOL_LEN + 2)

#define SCTP_SESSION_ACTIVE             0
#define SCTP_SESSION_SHUTDOWN_INITIATED 1
#define SCTP_SESSION_SHUTDOWN_COMPLETED 2

#define DEFAULT_SCTP_SHUTDOWN_TIMEOUT 2 * HUNDREDS_OF_NANOS_IN_A_SECOND

#define DEFAULT_USRSCTP_TEARDOWN_POLLING_INTERVAL (10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)
/**
 * @brief 
 *          https://yoshihisaonoue.wordpress.com/category/protocols/sctp/
 *          Payload Protocol Identifier (PPID): This must be 50 which is dedicated for WebRTC DCEP.
*/
enum { 
    SCTP_PPID_DCEP = 50,
    SCTP_PPID_STRING = 51,
    SCTP_PPID_BINARY = 53,
    SCTP_PPID_STRING_EMPTY = 56,
    SCTP_PPID_BINARY_EMPTY = 57 
};

enum {
    DCEP_DATA_CHANNEL_OPEN = 0x03,
};

typedef enum {
    DCEP_DATA_CHANNEL_RELIABLE_ORDERED = (BYTE) 0x00,
    DCEP_DATA_CHANNEL_RELIABLE_UNORDERED = (BYTE) 0x80,
    DCEP_DATA_CHANNEL_REXMIT = (BYTE) 0x01,
    DCEP_DATA_CHANNEL_TIMED = (BYTE) 0x02
} DATA_CHANNEL_TYPE;

// Callback that is fired when SCTP Association wishes to send packet
typedef VOID (*SctpSessionOutboundPacketFunc)(UINT64, PBYTE, UINT32);

// Callback that is fired when SCTP has a new DataChannel
// Argument is ChannelID and ChannelName + Len
typedef VOID (*SctpSessionDataChannelOpenFunc)(UINT64, UINT32, PBYTE, UINT32);

// Callback that is fired when SCTP has a DataChannel Message.
// Argument is ChannelID and Message + Len
typedef VOID (*SctpSessionDataChannelMessageFunc)(UINT64, UINT32, BOOL, PBYTE, UINT32);

typedef struct {
    UINT64 customData;
    SctpSessionOutboundPacketFunc outboundPacketFunc;//!< the callback of outbound sctp packets for webrtc client.
    SctpSessionDataChannelOpenFunc dataChannelOpenFunc;//!< the callback of inboud dcep packets for internal interface.
    SctpSessionDataChannelMessageFunc dataChannelMessageFunc;
} SctpSessionCallbacks, *PSctpSessionCallbacks;

typedef struct {
    /** https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.7 */
    volatile SIZE_T shutdownStatus;
    struct socket* socket;
    struct sctp_sendv_spa spa;
    BYTE packet[SCTP_MAX_ALLOWABLE_PACKET_LENGTH];
    UINT32 packetSize;
    SctpSessionCallbacks sctpSessionCallbacks;//!< the callbacl of sctp session.
} SctpSession, *PSctpSession;

STATUS initSctpSession();
VOID deinitSctpSession();
STATUS createSctpSession(PSctpSessionCallbacks, PSctpSession*);
STATUS freeSctpSession(PSctpSession*);
STATUS putSctpPacket(PSctpSession, PBYTE, UINT32);
STATUS sctpSessionWriteMessage(PSctpSession, UINT32, BOOL, PBYTE, UINT32);
STATUS sctpSessionWriteDcep(PSctpSession, UINT32, PCHAR, UINT32, PRtcDataChannelInit);

// Callbacks used by usrsctp
INT32 onSctpOutboundPacket(PVOID, PVOID, ULONG, UINT8, UINT8);
INT32 onSctpInboundPacket(struct socket*, union sctp_sockstore, PVOID, ULONG, struct sctp_rcvinfo, INT32, PVOID);

#ifdef __cplusplus
}
#endif
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_SCTP_SCTP__
