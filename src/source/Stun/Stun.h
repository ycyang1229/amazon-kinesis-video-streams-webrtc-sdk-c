/*******************************************
StunPackager internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_STUN_PACKAGER__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_STUN_PACKAGER__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Stun header structure
 * - 2 UINT16 type len
 * - 2 UINT16 packet data len
 * - 4 UINT16 magic cookie
 * - 12 UINT16 transaction id
 * - data
 */
#define STUN_HEADER_LEN                (UINT16) 20
#define STUN_HEADER_TYPE_LEN           (UINT16) 2
#define STUN_HEADER_DATA_LEN           (UINT16) 2
#define STUN_HEADER_MAGIC_COOKIE       (UINT32) 0x2112A442
#define STUN_HEADER_MAGIC_COOKIE_LE    (UINT32) 0x42A41221
#define STUN_HEADER_MAGIC_COOKIE_LEN   SIZEOF(STUN_HEADER_MAGIC_COOKIE)
#define STUN_HEADER_TRANSACTION_ID_LEN (UINT16) 12

/**
 * Stun attribute header structure
 * - 2 UINT16 type len
 * - 2 UINT16 attribute data len
 * - attribute specific data
 */
#define STUN_ATTRIBUTE_HEADER_TYPE_LEN (UINT16) 2
#define STUN_ATTRIBUTE_HEADER_DATA_LEN (UINT16) 2
#define STUN_ATTRIBUTE_HEADER_LEN      (UINT16)(STUN_ATTRIBUTE_HEADER_TYPE_LEN + STUN_ATTRIBUTE_HEADER_DATA_LEN)

#define STUN_ATTRIBUTE_ADDRESS_FAMILY_LEN (UINT16) 2
#define STUN_ATTRIBUTE_ADDRESS_PORT_LEN   (UINT16) 2
#define STUN_ATTRIBUTE_ADDRESS_HEADER_LEN (UINT16)(STUN_ATTRIBUTE_ADDRESS_FAMILY_LEN + STUN_ATTRIBUTE_ADDRESS_PORT_LEN)

/**
 * Fingerprint attribute value length = 4 bytes = 32 bits
 */
#define STUN_ATTRIBUTE_FINGERPRINT_LEN (UINT16) 4

/**
 * Priority attribute value length = 4 bytes = 32 bits
 */
#define STUN_ATTRIBUTE_PRIORITY_LEN (UINT16) 4

/**
 * Lifetime attribute value length = 4 bytes = 32 bits representing number of seconds until expiration
 */
#define STUN_ATTRIBUTE_LIFETIME_LEN (UINT16) 4

#define STUN_ATTRIBUTE_CHANNEL_NUMBER_LEN (UINT16) 4

/**
 * The flag is 32 bit long but only 2 bits are used
 */
#define STUN_ATTRIBUTE_CHANGE_REQUEST_FLAG_LEN (UINT16) 4

/**
 * Ice-controll and Ice-controlling attribute value length = 8 bytes = 64 bits for a UINT64 tie breaker
 */
#define STUN_ATTRIBUTE_ICE_CONTROL_LEN (UINT16) 8

/**
 * Requested transport protocol attribute value length = 4 bytes = 32 bits
 */
#define STUN_ATTRIBUTE_REQUESTED_TRANSPORT_PROTOCOL_LEN (UINT16) 4

/**
 * Candidate attribute has no size
 */
#define STUN_ATTRIBUTE_FLAG_LEN (UINT16) 0

/**
 * STUN packet transaction id = 96 bits
 */
#define STUN_TRANSACTION_ID_LEN (UINT16) 12

/**
 * STUN HMAC attribute value length
 */
#define STUN_HMAC_VALUE_LEN KVS_SHA1_DIGEST_LENGTH

/**
 * Max number of attributes allowed
 */
#define STUN_ATTRIBUTE_MAX_COUNT 20

/**
 * Default allocation size for a STUN packet
 */
#define STUN_PACKET_ALLOCATION_SIZE 2048

#define STUN_SEND_INDICATION_OVERHEAD_SIZE                36
#define STUN_SEND_INDICATION_APPLICATION_DATA_OFFSET      36
#define STUN_SEND_INDICATION_APPLICATION_DATA_LEN_OFFSET  34
#define STUN_SEND_INDICATION_XOR_PEER_ADDRESS_OFFSET      28
#define STUN_SEND_INDICATION_XOR_PEER_ADDRESS_PORT_OFFSET 26

/**
 * Need to XOR the calculate fingerprint value with this per
 * https://tools.ietf.org/html/rfc5389#section-15.5
 */
#define STUN_FINGERPRINT_ATTRIBUTE_XOR_VALUE (UINT32) 0x5354554e

#define STUN_ERROR_CODE_PACKET_ERROR_CLASS_OFFSET  2
#define STUN_ERROR_CODE_PACKET_ERROR_CODE_OFFSET   3
#define STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET 4
#define STUN_PACKET_TRANSACTION_ID_OFFSET          8

/**
 * https://tools.ietf.org/html/rfc3489#section-11.2.4
 */
#define STUN_ATTRIBUTE_CHANGE_REQUEST_FLAG_CHANGE_IP   4
#define STUN_ATTRIBUTE_CHANGE_REQUEST_FLAG_CHANGE_PORT 2

/**
 * Taking a PBYTE pointing to stun error packet's error code attribute's error class location and another PBYTE
 * pointing to the error code location, return stun error code as UINT16
 */
#define GET_STUN_ERROR_CODE(pClass, pCode) ((UINT16)((*(PUINT8)(pClass)) * 100 + *(PUINT8)(pCode)))

/**
 * Packages the attribute header into a specified buffer
 */
#define PACKAGE_STUN_ATTR_HEADER(pBuf, type, dataLen)                                                                                                \
    putInt16((PINT16)(pBuf), (UINT16)(type));                                                                                                        \
    putInt16((PINT16)((pBuf) + STUN_ATTRIBUTE_HEADER_TYPE_LEN), (UINT16)(dataLen));

/**
 * @brief   STUN packet types
 *          https://tools.ietf.org/html/rfc5389#appendix-A
*/
typedef enum {
    // #define IS_REQUEST(msg_type) (((msg_type) & 0x0110) == 0x0000)
    STUN_PACKET_TYPE_BINDING_REQUEST = (UINT16) 0x0001,
    STUN_PACKET_TYPE_SHARED_SECRET_REQUEST = (UINT16) 0x0002,
    // https://tools.ietf.org/html/rfc5766#section-13
    STUN_PACKET_TYPE_ALLOCATE = (UINT16) 0x0003,//!< only request/response semantics defined
    STUN_PACKET_TYPE_REFRESH = (UINT16) 0x0004,//!< only request/response semantics defined
    STUN_PACKET_TYPE_SEND = (UINT16) 0x0006,//!< only indication semantics defined
    STUN_PACKET_TYPE_DATA = (UINT16) 0x0007,//!< only indication semantics defined
    STUN_PACKET_TYPE_CREATE_PERMISSION = (UINT16) 0x0008,//!< only request/response semantics defined
    STUN_PACKET_TYPE_CHANNEL_BIND_REQUEST = (UINT16) 0x0009,//!< only request/response semantics defined

    //#define IS_INDICATION(msg_type) (((msg_type) & 0x0110) == 0x0010)
    STUN_PACKET_TYPE_BINDING_INDICATION = (UINT16) 0x0011,
    STUN_PACKET_TYPE_SEND_INDICATION = (UINT16) 0x0016,
    STUN_PACKET_TYPE_DATA_INDICATION = (UINT16) 0x0017,

    //#define IS_SUCCESS_RESP(msg_type) (((msg_type) & 0x0110) == 0x0100)
    STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS = (UINT16) 0x0101,
    STUN_PACKET_TYPE_SHARED_SECRET_RESPONSE = (UINT16) 0x0102,
    STUN_PACKET_TYPE_ALLOCATE_SUCCESS_RESPONSE = (UINT16) 0x0103, //!< turn connection.
    STUN_PACKET_TYPE_REFRESH_SUCCESS_RESPONSE = (UINT16) 0x0104, //!< turn connection.
    STUN_PACKET_TYPE_CREATE_PERMISSION_SUCCESS_RESPONSE = (UINT16) 0x0108, //!< turn connection.
    STUN_PACKET_TYPE_CHANNEL_BIND_SUCCESS_RESPONSE = (UINT16) 0x0109, //!< turn connection.

    //#define IS_ERR_RESP(msg_type) (((msg_type) & 0x0110) == 0x0110)
    STUN_PACKET_TYPE_BINDING_RESPONSE_ERROR = (UINT16) 0x0111,
    STUN_PACKET_TYPE_SHARED_SECRET_ERROR_RESPONSE = (UINT16) 0x0112,
    STUN_PACKET_TYPE_ALLOCATE_ERROR_RESPONSE = (UINT16) 0x0113,
    STUN_PACKET_TYPE_REFRESH_ERROR_RESPONSE = (UINT16) 0x0114,
    STUN_PACKET_TYPE_CREATE_PERMISSION_ERROR_RESPONSE = (UINT16) 0x0118,
    STUN_PACKET_TYPE_CHANNEL_BIND_ERROR_RESPONSE = (UINT16) 0x0119,
} STUN_PACKET_TYPE;

/*
 * Taking a PBYTE pointing to a buffer containing stun packet, return whether the stun packet is error packet or not
 */
#define STUN_PACKET_IS_TYPE_ERROR(pPacketBuffer)                                                                                                     \
    ((getInt16(*(PINT16) pPacketBuffer) == STUN_PACKET_TYPE_BINDING_RESPONSE_ERROR) ||                                                               \
     (getInt16(*(PINT16) pPacketBuffer) == STUN_PACKET_TYPE_SHARED_SECRET_ERROR_RESPONSE) ||                                                         \
     (getInt16(*(PINT16) pPacketBuffer) == STUN_PACKET_TYPE_ALLOCATE_ERROR_RESPONSE) ||                                                              \
     (getInt16(*(PINT16) pPacketBuffer) == STUN_PACKET_TYPE_REFRESH_ERROR_RESPONSE) ||                                                               \
     (getInt16(*(PINT16) pPacketBuffer) == STUN_PACKET_TYPE_CREATE_PERMISSION_ERROR_RESPONSE) ||                                                     \
     (getInt16(*(PINT16) pPacketBuffer) == STUN_PACKET_TYPE_CHANNEL_BIND_ERROR_RESPONSE))

/**
 * @brief   STUN error codes
 *          https://tools.ietf.org/html/rfc5389#section-15.6
 *          https://tools.ietf.org/html/rfc5766#section-6.4
*/
typedef enum {
    STUN_ERROR_TRY_ALTERNATE = (UINT16) 300,
    STUN_ERROR_BAD_REQUEST = (UINT16) 400,
    STUN_ERROR_UNAUTHORIZED = (UINT16) 401,
    STUN_ERROR_FORBIDDEN = (UINT16) 403,
    STUN_ERROR_UNKNOWN_ATTRIBUTE = (UINT16) 420,
    STUN_ERROR_ALLOCATION_MISMATCH = (UINT16) 437,
    STUN_ERROR_STALE_NONCE = (UINT16) 438,
    STUN_ERROR_WRONG_CREDENTIALS = (UINT16) 441,
    STUN_ERROR_UNSUPPORTED_TRANSPORT_ADDRESS = (UINT16) 442,
    STUN_ERROR_ALLOCATION_QUOTA_REACHED = (UINT16) 486,
    STUN_ERROR_SERVER_ERROR = (UINT16) 500,
    STUN_ERROR_INSUFFICIENT_CAPACITY = (UINT16) 508,
} STUN_ERROR_CODE;

/**
 * @brief   STUN attribute types
 *          https://tools.ietf.org/html/rfc5389#section-18.2
*/
typedef enum {
    // Comprehension-required range (0x0000-0x7FFF)
    STUN_ATTRIBUTE_TYPE_RESERVED = (UINT16) 0x0000,
    STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS = (UINT16) 0x0001,
    STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS = (UINT16) 0x0002,
    STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST = (UINT16) 0x0003,
    STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS = (UINT16) 0x0004,
    STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS = (UINT16) 0x0005,
    STUN_ATTRIBUTE_TYPE_USERNAME = (UINT16) 0x0006,
    STUN_ATTRIBUTE_TYPE_PASSWORD = (UINT16) 0x0007,
    STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY = (UINT16) 0x0008,
    STUN_ATTRIBUTE_TYPE_ERROR_CODE = (UINT16) 0x0009,
    STUN_ATTRIBUTE_TYPE_UNKNOWN_ATTRIBUTES = (UINT16) 0x000A,
    STUN_ATTRIBUTE_TYPE_REFLECTED_FROM = (UINT16) 0x000B,
    // // https://tools.ietf.org/html/rfc5766#section-14
    STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER = (UINT16) 0x000C,
    STUN_ATTRIBUTE_TYPE_LIFETIME = (UINT16) 0x000D,
    STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS = (UINT16) 0x0012,
    STUN_ATTRIBUTE_TYPE_DATA = (UINT16) 0x0013,
    STUN_ATTRIBUTE_TYPE_REALM = (UINT16) 0x0014,
    STUN_ATTRIBUTE_TYPE_NONCE = (UINT16) 0x0015,
    STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS = (UINT16) 0x0016,
    STUN_ATTRIBUTE_TYPE_EVEN_PORT = (UINT16) 0x0018,
    STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT = (UINT16) 0x0019,
    STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT = (UINT16) 0x001A,
    STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS = (UINT16) 0x0020,
    STUN_ATTRIBUTE_TYPE_RESERVATION_TOKEN = (UINT16) 0x0022,
    STUN_ATTRIBUTE_TYPE_PRIORITY = (UINT16) 0x0024,
    STUN_ATTRIBUTE_TYPE_USE_CANDIDATE = (UINT16) 0x0025,
    // Comprehension-optional range (0x8000-0xFFFF)
    STUN_ATTRIBUTE_TYPE_SOFTWARE = (UINT16) 0x8022,
    STUN_ATTRIBUTE_TYPE_ALTERNATE_SERVER = (UINT16) 0x8023,
    STUN_ATTRIBUTE_TYPE_FINGERPRINT = (UINT16) 0x8028,
    STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED = (UINT16) 0x8029,
    STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING = (UINT16) 0x802A,

} STUN_ATTRIBUTE_TYPE;

/**
 * Stun packet header definition
 *
 * IMPORTANT: This structure has exactly the same layout as the on-the-wire header for STUN packet
 * according to the following RFCs:
 *
 * https://tools.ietf.org/html/rfc5389#section-15
 * https://tools.ietf.org/html/rfc3489#section-11.2
 *
 */
typedef struct {
    UINT16 stunMessageType;
    UINT16 messageLength;
    UINT32 magicCookie;
    BYTE transactionId[STUN_TRANSACTION_ID_LEN];
} StunHeader, *PStunHeader;

typedef struct {
    // Type of the STUN attribute
    UINT16 type;

    // Length of the value
    UINT16 length;
} StunAttributeHeader, *PStunAttributeHeader;

typedef struct {
    StunAttributeHeader attribute;
    KvsIpAddress address;
} StunAttributeAddress, *PStunAttributeAddress;

typedef struct {
    // Encapsulating the attribute header
    StunAttributeHeader attribute;

    // Padded with 0 - 3 bytes to be 32-bit aligned
    UINT16 paddedLength;

    // NOTE: User name which might or might not be NULL terminated will follow the attribute header
    // NOTE: This will contain the padded bits as well
    PCHAR userName;
} StunAttributeUsername, *PStunAttributeUsername;

typedef struct {
    StunAttributeHeader attribute;
    UINT32 crc32Fingerprint;
} StunAttributeFingerprint, *PStunAttributeFingerprint;

typedef struct {
    StunAttributeHeader attribute;
    UINT32 priority;
} StunAttributePriority, *PStunAttributePriority;

typedef struct {
    StunAttributeHeader attribute;
} StunAttributeFlag, *PStunAttributeFlag;

typedef struct {
    StunAttributeHeader attribute;
    BYTE messageIntegrity[STUN_HMAC_VALUE_LEN];
} StunAttributeMessageIntegrity, *PStunAttributeMessageIntegrity;

typedef struct {
    StunAttributeHeader attribute;
    UINT32 lifetime;
} StunAttributeLifetime, *PStunAttributeLifetime;

typedef struct {
    StunAttributeHeader attribute;
    BYTE protocol[4];
} StunAttributeRequestedTransport, *PStunAttributeRequestedTransport;

typedef struct {
    // Encapsulating the attribute header
    StunAttributeHeader attribute;

    // Padded with 0 - 3 bytes to be 32-bit aligned
    UINT16 paddedLength;

    // NOTE: User name which might or might not be NULL terminated will follow the attribute header
    // NOTE: This will contain the padded bits as well
    PCHAR realm;
} StunAttributeRealm, *PStunAttributeRealm;

typedef struct {
    StunAttributeHeader attribute;

    // Padded with 0 - 3 bytes to be 32-bit aligned
    UINT16 paddedLength;

    PBYTE nonce;
} StunAttributeNonce, *PStunAttributeNonce;

typedef struct {
    StunAttributeHeader attribute;

    UINT16 errorCode;

    // Padded with 0 - 3 bytes to be 32-bit aligned
    UINT16 paddedLength;

    PCHAR errorPhrase;
} StunAttributeErrorCode, *PStunAttributeErrorCode;

typedef struct {
    StunAttributeHeader attribute;

    UINT64 tieBreaker;
} StunAttributeIceControl, *PStunAttributeIceControl;

typedef struct {
    StunAttributeHeader attribute;

    // Padded with 0 - 3 bytes to be multiple of 4
    UINT16 paddedLength;

    PBYTE data;
} StunAttributeData, *PStunAttributeData;

typedef struct {
    StunAttributeHeader attribute;

    UINT16 channelNumber;

    UINT16 reserve;
} StunAttributeChannelNumber, *PStunAttributeChannelNumber;

typedef struct {
    StunAttributeHeader attribute;

    /* only two bit of changeFlag is used. 0x00000002 means change ip. 0x00000004 means change port */
    UINT32 changeFlag;
} StunAttributeChangeRequest, *PStunAttributeChangeRequest;

/**
 * Internal representation of the STUN packet.
 *
 * NOTE: The allocations will follow the main structure.
 */
typedef struct {
    // Stun header
    StunHeader header;//!< the stun header.

    // Number of attributes in the list
    UINT32 attributesCount;

    // The entire structure allocation size
    UINT32 allocationSize;//!< the size of allocated buffer. #YC_TBD, need to review the size.

    // Stun attributes
    PStunAttributeHeader* attributeList;//!< the buffer of stun attributes.
} StunPacket, *PStunPacket;

STATUS stunSerializePacket(PStunPacket, PBYTE, UINT32, BOOL, BOOL, PBYTE, PUINT32);
STATUS stunDeserializePacket(PBYTE, UINT32, PBYTE, UINT32, PStunPacket*);
STATUS stunFreePacket(PStunPacket*);
STATUS stunCreatePacket(STUN_PACKET_TYPE, PBYTE, PStunPacket*);
STATUS stunAppendAttrAddress(PStunPacket, STUN_ATTRIBUTE_TYPE, PKvsIpAddress);
STATUS stunAppendAttrUsername(PStunPacket, PCHAR);
STATUS stunAppendAttrFlag(PStunPacket, STUN_ATTRIBUTE_TYPE);
STATUS stunAppendAttrPriority(PStunPacket, UINT32);
STATUS stunAppendAttrLifetime(PStunPacket, UINT32);
STATUS stunAppendAttrRequestedTransport(PStunPacket, UINT8);
STATUS stunAppendAttrRealm(PStunPacket, PCHAR);
STATUS stunAppendAttrNonce(PStunPacket, PBYTE, UINT16);
STATUS stunUpdateAttrNonce(PStunPacket, PBYTE, UINT16);
STATUS stunAppendAttrErrorCode(PStunPacket, PCHAR, UINT16);
STATUS stunAppendAttrIceControl(PStunPacket, STUN_ATTRIBUTE_TYPE, UINT64);
STATUS stunAppendAttrData(PStunPacket, PBYTE, UINT16);
STATUS stunAppendAttrChannelNumber(PStunPacket, UINT16);
STATUS stunAppendAttrChangeRequest(PStunPacket, UINT32);

STATUS stunGetAttribute(PStunPacket, STUN_ATTRIBUTE_TYPE, PStunAttributeHeader*);

/**
 * xor an ip address in place
 */
STATUS stunXorIpAddress(PKvsIpAddress, PBYTE);
//
// Internal functions
//
STATUS stunPackageIpAddr(PStunHeader, STUN_ATTRIBUTE_TYPE, PKvsIpAddress, PBYTE, PUINT32);
UINT16 stunGetPackagedAttributeSize(PStunAttributeHeader);
STATUS stunGetFirstAvailableAttribute(PStunPacket, PStunAttributeHeader*);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_STUN_PACKAGER__ */
