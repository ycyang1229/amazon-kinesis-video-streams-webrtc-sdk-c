/*******************************************
RTP Packet include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTP_RTPPACKET_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTP_RTPPACKET_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  The format of an SRTP packet is illustrated in the following figure.
 *  https://tools.ietf.org/html/rfc3711#section-3.1
 *  
 *          0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
 *       |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *       |                           timestamp                           | |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *       |           synchronization source (SSRC) identifier            | |
 *       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
 *       |            contributing source (CSRC) identifiers             | |
 *       |                               ....                            | |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *       |                   RTP extension (OPTIONAL)                    | |
 *     +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *     | |                          payload  ...                         | |
 *     | |                               +-------------------------------+ |
 *     | |                               | RTP padding   | RTP pad count | |
 *     +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
 *     | ~                     SRTP MKI (OPTIONAL)                       ~ |
 *     | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *     | :                 authentication tag (RECOMMENDED)              : |
 *     | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *     |                                                                   |
*/
#define MIN_HEADER_LENGTH 12
#define VERSION_SHIFT     6
#define VERSION_MASK      0x3
#define PADDING_SHIFT     5
#define PADDING_MASK      0x1
#define EXTENSION_SHIFT   4
#define EXTENSION_MASK    0x1
#define CSRC_COUNT_MASK   0xF
#define MARKER_SHIFT      7
#define MARKER_MASK       0x1
#define PAYLOAD_TYPE_MASK 0x7F
#define SEQ_NUMBER_OFFSET 2
#define TIMESTAMP_OFFSET  4
#define SSRC_OFFSET       8
#define CSRC_OFFSET       12
#define CSRC_LENGTH       4

#define RTP_HEADER_LEN(pRtpPacket)                                                                                                                   \
    (12 + \
    (pRtpPacket)->header.csrcCount * CSRC_LENGTH + \
    ((pRtpPacket)->header.extension ? 4 + (pRtpPacket)->header.extensionLength : 0))

#define RTP_GET_RAW_PACKET_SIZE(pRtpPacket) (RTP_HEADER_LEN(pRtpPacket) + ((pRtpPacket)->payloadLength))

#define GET_UINT16_SEQ_NUM(seqIndex) ((UINT16)((seqIndex) % (MAX_UINT16 + 1)))

typedef STATUS (*DepayRtpPayloadFunc)(PBYTE, UINT32, PBYTE, PUINT32, PBOOL);

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           timestamp                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           synchronization source (SSRC) identifier            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       contributing source (CSRC[0..15]) identifiers           |
 * |                             ....                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/**
 * #YC_TBD. this must be improved.
 * 
*/
struct __RtpPacketHeader {
    UINT8 version;
    BOOL padding;
    BOOL extension;
    BOOL marker;
    UINT8 csrcCount;
    UINT8 payloadType;
    UINT16 sequenceNumber;
    UINT32 timestamp;
    UINT32 ssrc;
    PUINT32 csrcArray;
    UINT16 extensionProfile;
    PBYTE extensionPayload;
    UINT32 extensionLength;
};
typedef struct __RtpPacketHeader RtpPacketHeader;
typedef RtpPacketHeader* PRtpPacketHeader;
/**
 * @brief we slice one payload into several subpayload according to mtu and the characteristic of video/audio encoding/decoding.
*/
struct __Payloads {
    PBYTE payloadBuffer;//!< the buffer pointer of payload.
    UINT32 payloadLength;//!< the length of the payload buffer.
    UINT32 maxPayloadLength;//!< the capacity of the payload buffer.
    PUINT32 payloadSubLength;//!< the array of the length for each subpayload
    UINT32 payloadSubLenSize;//!< the number of subpayload.
    UINT32 maxPayloadSubLenSize;//!< the capacity of payloadSubLength.
};
typedef struct __Payloads PayloadArray;
typedef PayloadArray* PPayloadArray;

typedef struct __RtpPacket RtpPacket;
struct __RtpPacket {
    RtpPacketHeader header;
    PBYTE payload;//!< the buffer pointer of payload.
    UINT32 payloadLength;
    PBYTE pRawPacket;//!< the bufffer pointer of raw packet.
    UINT32 rawPacketLength;
    // used for jitterBufferDelay calculation
    UINT64 receivedTime;
};
typedef RtpPacket* PRtpPacket;

STATUS createRtpPacket(UINT8, BOOL, BOOL, UINT8, BOOL, UINT8, UINT16, UINT32, UINT32, PUINT32, UINT16, UINT32, PBYTE, PBYTE, UINT32, PRtpPacket*);
STATUS setRtpPacket(UINT8, BOOL, BOOL, UINT8, BOOL, UINT8, UINT16, UINT32, UINT32, PUINT32, UINT16, UINT32, PBYTE, PBYTE, UINT32, PRtpPacket);
STATUS freeRtpPacket(PRtpPacket*);
STATUS createRtpPacketFromBytes(PBYTE, UINT32, PRtpPacket*);
STATUS constructRetransmitRtpPacketFromBytes(PBYTE, UINT32, UINT16, UINT8, UINT32, PRtpPacket*);
STATUS setRtpPacketFromBytes(PBYTE, UINT32, PRtpPacket);
STATUS createBytesFromRtpPacket(PRtpPacket, PBYTE, PUINT32);
STATUS setBytesFromRtpPacket(PRtpPacket, PBYTE, UINT32);
STATUS constructRtpPackets(PPayloadArray, UINT8, UINT16, UINT32, UINT32, PRtpPacket, UINT32);

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTP_RTPPACKET_H
