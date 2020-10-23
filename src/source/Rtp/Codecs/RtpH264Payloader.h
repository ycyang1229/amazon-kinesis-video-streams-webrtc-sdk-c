/*******************************************
H264 RTP Payloader include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTPH264PAYLOADER_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTPH264PAYLOADER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define FU_A_HEADER_SIZE 2
#define FU_B_HEADER_SIZE 4
// https://tools.ietf.org/html/rfc6184#section-5.7.1
#define STAP_A_HEADER_SIZE   1
#define STAP_B_HEADER_SIZE   3
#define SINGLE_U_HEADER_SIZE 1
#define FU_A_INDICATOR       28
#define FU_B_INDICATOR       29
#define STAP_A_INDICATOR     24
#define STAP_B_INDICATOR     25
#define NAL_TYPE_MASK        31

/**
 * RTP payload format for single NAL unit packet
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |F|NRI| Type    |                                               |
 *  +-+-+-+-+-+-+-+-+                                               |
 *  |                                                               |
 *  | Bytes 2..n of a single NAL unit                               |
 *  |                                                               |
 *  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               :...OPTIONAL RTP padding        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * RTP payload format for aggregation packets
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |F|NRI| Type    |                                               |
 *  +-+-+-+-+-+-+-+-+                                               |
 *  |                                                               |
 *  | one or more aggregation units                                 |
 *  |                                                               |
 *  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               :...OPTIONAL RTP padding        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Table 4. Type field for STAPs and MTAPs
 * Type Packet  Timestamp offset    DON-related fields
 *              field length        (DON, DONB, DOND)
 *              (in bits)           present
 * --------------------------------------------------------
 * 24   STAP-A  0                   no
 * 25   STAP-B  0                   yes
 * 26   MTAP16  16                  yes
 * 27   MTAP24  24                  yes
 *
 *
 */

/*
 * https://tools.ietf.org/html/rfc6184#section-5.8
 * RTP payload format for FU-A
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | FU indicator  |   FU header   |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *  |                                                               |
 *  |                         FU payload                            |
 *  |                                                               |
 *  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               :...OPTIONAL RTP padding        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * RTP payload format for FU-B
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | FU indicator  | FU header     |             DON               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 *  |                                                               |
 *  |                          FU payload                           |
 *  |                                                               |
 *  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               :...OPTIONAL RTP padding        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *  The FU indicator octet has the following format:
 *  +---------------+
 *  |0|1|2|3|4|5|6|7|
 *  +-+-+-+-+-+-+-+-+
 *  |F|NRI|   Type  |
 *  +---------------+
 *
 * The FU header has the following format:
 *  +---------------+
 *  |0|1|2|3|4|5|6|7|
 *  +-+-+-+-+-+-+-+-+
 *  |S|E|R|   Type  |
 *  +---------------+
 *
 */

typedef struct {
#if 0
    BYTE forbidden_zero_bit:1;
    BYTE nal_ref_idc:2;
    BYTE nal_type:5;
#else
    BYTE nal_type : 5;
    BYTE nal_ref_idc : 2; //!< The value of NRI MUST be the maximum of all the NAL units carried in the aggregation packet.
    BYTE forbidden_zero_bit : 1;
#endif
} NALU_HDR, *PNALU_HDR;

STATUS createPayloadForH264(UINT32, PBYTE, UINT32, PBYTE, PUINT32, PUINT32, PUINT32);
STATUS getNextNaluLength(PBYTE, UINT32, PUINT32, PUINT32);
STATUS createPayloadFromNalu(UINT32, PBYTE, UINT32, PPayloadArray, PUINT32, PUINT32);
STATUS depayH264FromRtpPayload(PBYTE, UINT32, PBYTE, PUINT32, PBOOL);

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTPH264PAYLOADER_H
