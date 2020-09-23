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
 * https://tools.ietf.org/html/rfc4960
 * https://tools.ietf.org/html/rfc6458
 * https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13    
 * https://tools.ietf.org/html/draft-ietf-behave-sctpnat-09
 * 
 * 
 * https://github.com/sctplab/usrsctp/blob/master/Manual.md
 * 
*/
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
/** Label Length: 2 bytes (unsigned integer) */
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
 *          https://tools.ietf.org/html/rfc4960#section-14.4
 *          https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-8
 * 
 *          +-------------------------------+----------+-----------+------------+
 *          | Value                         | SCTP     | Reference | Date       |
 *          |                               | PPID     |           |            |
 *          +-------------------------------+----------+-----------+------------+
 *          | WebRTC String                 | 51       | [RFCXXXX] | 2013-09-20 |
 *          | WebRTC Binary Partial         | 52       | [RFCXXXX] | 2013-09-20 |
 *          | (Deprecated)                  |          |           |            |
 *          | WebRTC Binary                 | 53       | [RFCXXXX] | 2013-09-20 |
 *          | WebRTC String Partial         | 54       | [RFCXXXX] | 2013-09-20 |
 *          | (Deprecated)                  |          |           |            |
 *          | WebRTC String Empty           | 56       | [RFCXXXX] | 2014-08-22 |
 *          | WebRTC Binary Empty           | 57       | [RFCXXXX] | 2014-08-22 |
 *          +-------------------------------+----------+-----------+------------+
*/
enum { 
    SCTP_PPID_DCEP = 50,
    SCTP_PPID_STRING = 51,
    SCTP_PPID_BINARY = 53,
    SCTP_PPID_STRING_EMPTY = 56,
    SCTP_PPID_BINARY_EMPTY = 57 
};
/**
 * @brief https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09#section-5.1
 * 
*/
enum {
    DCEP_DATA_CHANNEL_OPEN = 0x03,
};

typedef enum {
    DCEP_DATA_CHANNEL_RELIABLE_ORDERED = (BYTE) 0x00,//!< in-order bi-directional communication.
    DCEP_DATA_CHANNEL_RELIABLE_UNORDERED = (BYTE) 0x80,//!< unordered bi-directional communication.
    DCEP_DATA_CHANNEL_REXMIT = (BYTE) 0x01,//!< The Data Channel provides a partially-reliable in-order bi-directional communication. 
                                            //!< User messages will not be retransmitted more times than specified in the Reliability Parameter
    DCEP_DATA_CHANNEL_REXMIT_UNORDERED = (BYTE) 0x81,
    DCEP_DATA_CHANNEL_TIMED = (BYTE) 0x02,//!< The Data Channel provides a partial reliable in-order bi-directional communication. 
                                          //!<  User messages might not be transmitted or retransmitted after a specified life-time given in milliseconds in the Reliability Parameter. 
                                          //!< This life-time starts when providing the user message to the protocol stack.
    DCEP_DATA_CHANNEL_TIMED_UNORDERED = (BYTE) 0x82
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
    SctpSessionDataChannelOpenFunc dataChannelOpenFunc;//!< the callback of inboud dcep packets for internal sctp interface.
    SctpSessionDataChannelMessageFunc dataChannelMessageFunc;
} SctpSessionCallbacks, *PSctpSessionCallbacks;

typedef struct {
    /** https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.7 */
    volatile SIZE_T shutdownStatus;
    struct socket* socket;
    /** [RFC 6458](https://tools.ietf.org/html/rfc6458) */
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
