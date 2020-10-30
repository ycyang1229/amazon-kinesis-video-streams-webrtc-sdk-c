/*******************************************
RTCP Packet include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTCP_RTCPPACKET_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTCP_RTCPPACKET_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define RTCP_PACKET_LEN_OFFSET  2
#define RTCP_PACKET_TYPE_OFFSET 1

#define RTCP_PACKET_RRC_BITMASK 0x1F

#define RTCP_PACKET_HEADER_LEN 4
#define RTCP_NACK_LIST_LEN     8

#define RTCP_PACKET_VERSION_VAL 2

#define RTCP_PACKET_LEN_WORD_SIZE 4

#define RTCP_PACKET_REMB_MIN_SIZE          16
#define RTCP_PACKET_REMB_IDENTIFIER_OFFSET 8
#define RTCP_PACKET_REMB_MANTISSA_BITMASK  0x3FFFF

#define RTCP_PACKET_SENDER_REPORT_MINLEN      24
#define RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN 24
#define RTCP_PACKET_RECEIVER_REPORT_MINLEN    4 + RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN

// https://tools.ietf.org/html/rfc3550#section-4
// If the participant has not yet sent an RTCP packet (the variable
// initial is true), the constant Tmin is set to 2.5 seconds, else it
// is set to 5 seconds.
#define RTCP_FIRST_REPORT_DELAY (3 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define RTCP_PACKET_SENDER_REPORT_MINLEN      24
#define RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN 24
#define RTCP_PACKET_RECEIVER_REPORT_MINLEN    4 + RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN

// https://tools.ietf.org/html/rfc3550#section-4
// If the participant has not yet sent an RTCP packet (the variable
// initial is true), the constant Tmin is set to 2.5 seconds, else it
// is set to 5 seconds.
#define RTCP_FIRST_REPORT_DELAY (3 * HUNDREDS_OF_NANOS_IN_A_SECOND)

/**
 * 5.2.1. Full INTRA-frame Request (FIR) packet
 * https://tools.ietf.org/html/rfc2032#section-5.2.1
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |V=2|P| MBZ     | PT=RTCP_FIR   | length                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC                                                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * 5.2.2.  Negative ACKnowledgements (NACK) packet
 * https://tools.ietf.org/html/rfc2032#section-5.2.2
 *   0 1 2 3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |V=2|P| MBZ     | PT=RTCP_NACK  | length                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC                                                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | FSN                           | BLP                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * 12.1 RTCP Packet Types
 * abbrev.  name                 value
 * SR       sender report          200
 * RR       receiver report        201
 * SDES     source description     202
 * BYE      goodbye                203
 * APP      application-defined    204
 */

/**
 * REMB
 * The message is an RTCP message with payload type 206. RFC 3550 [RFC3550] defines the range, RFC 4585 defines the specific PT value 206 and the FMT
 * value 15.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |V=2|P| FMT=15  | PT=206        | length                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC of packet sender                                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC of media source                                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Unique identifier ’R’ ’E’ ’M’ ’B’                             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Num SSRC      | BR Exp         | BR Mantissa                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC feedback                                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | ...
 */
/**
 * Payload-Specific Feedback Messages
 *  0: unassigned
 *  1: Picture Loss Indication (PLI)
 *  2: Slice Loss Indication (SLI)
 *  3: Reference Picture Selection Indication (RPSI)
 *  4-14: unassigned
 *  15: Application layer FB (AFB) message
 *  16-30: unassigned
 *  31: reserved for future expansion of the sequence number space
 *
 */
typedef enum {
    RTCP_PACKET_TYPE_FIR = 192, //!< Full INTRA-frame Request (FIR) packet
                                //!< https://tools.ietf.org/html/rfc2032#section-5.2.1
    RTCP_PACKET_TYPE_SENDER_REPORT = 200,
    RTCP_PACKET_TYPE_RECEIVER_REPORT = 201, // https://tools.ietf.org/html/rfc3550#section-6.4.2
    RTCP_PACKET_TYPE_SOURCE_DESCRIPTION = 202,
    RTCP_PACKET_TYPE_GENERIC_RTP_FEEDBACK = 205,      // https://tools.ietf.org/html/rfc4585#section-6.1
    RTCP_PACKET_TYPE_PAYLOAD_SPECIFIC_FEEDBACK = 206, //!< https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03
} RTCP_PACKET_TYPE;

/**
 * https://tools.ietf.org/html/rfc4585#section-6.1
 * Common Packet Format for Feedback Messages
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |V=2|P| FMT     | PT            | length                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC of packet sender                                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | SSRC of media source                                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  : Feedback Control Information (FCI)                            :
 *  :                                                               :
 *
 * Name  | Value | Brief Description
 * ----------+-------+------------------------------------
 * RTPFB | 205   | Transport layer FB message
 * PSFB  | 206   | Payload-specific FB message
 *
 */
/**
 * Figure 4: Syntax for the Generic NACK message
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | PID                           | BLP                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef enum {
    RTCP_FEEDBACK_MESSAGE_TYPE_NACK = 1, //!< Transport layer FB messages
                                         //!< // https://tools.ietf.org/html/rfc4585#section-6.2.1
    RTCP_PSFB_PLI = 1,                   //!< https://tools.ietf.org/html/rfc4585#section-6.3.1
    RTCP_PSFB_SLI = 2,                   //!< https://tools.ietf.org/html/rfc4585#section-6.3.2
    RTCP_PSFB_RPSI = 3,                  //!< https://tools.ietf.org/html/rfc4585#section-6.3.3
    RTCP_FEEDBACK_MESSAGE_TYPE_APPLICATION_LAYER_FEEDBACK = 15,
} RTCP_FEEDBACK_MESSAGE_TYPE;

/**
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|    Count   |       PT      |             length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*@brief https://tools.ietf.org/html/rfc3550#section-6.4.1
 *
 */
typedef struct {
    UINT8 version;
    UINT8 receptionReportCount;
    RTCP_PACKET_TYPE packetType;

    UINT32 packetLength;
} RtcpPacketHeader, *PRtcpPacketHeader;

typedef struct {
    RtcpPacketHeader header;

    PBYTE payload;
    UINT32 payloadLength;
} RtcpPacket, *PRtcpPacket;

STATUS setRtcpPacketFromBytes(PBYTE, UINT32, PRtcpPacket);
/**
 *
 */
STATUS rtcpNackListGet(PBYTE, UINT32, PUINT32, PUINT32, PUINT16, PUINT32);
STATUS rembValueGet(PBYTE, UINT32, PDOUBLE, PUINT32, PUINT8);
STATUS isRembPacket(PBYTE, UINT32);

#define NTP_OFFSET    2208988800ULL
#define NTP_TIMESCALE 4294967296ULL

// converts 100ns precision time to ntp time
UINT64 convertTimestampToNTP(UINT64 time100ns);

#define DLSR_TIMESCALE 65536

// https://tools.ietf.org/html/rfc3550#section-4
// In some fields where a more compact representation is
//   appropriate, only the middle 32 bits are used; that is, the low 16
//   bits of the integer part and the high 16 bits of the fractional part.
#define MID_NTP(ntp_time) (UINT32)((currentTimeNTP >> 16U) & 0xffffffffULL)

#ifdef __cplusplus
}
#endif

#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTCP_RTCPPACKET_H
