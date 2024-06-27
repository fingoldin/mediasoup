#include <cstdint>
#include <cstdlib>
#include <unordered_map>

enum SRTPProfile {
    SRTP_AES128_CM_HMAC_SHA1_80 = 0
};

typedef __int128 uint128_t;

typedef struct transport_tuple {
    uint32_t address[4];
    uint16_t port;
    bool isIPv6;
} transport_tuple_t;
typedef struct transport_state {
    uint64_t nbytes_recv;
    uint64_t nbytes_trans;
    uint16_t id;
    uint128_t salt; // network byte order, 112 bits
    uint128_t key; // network byte order
    uint16_t auth_key[10];
    SRTPProfile profile;
    uint64_t npackets; // 48 bits
} transport_state_t;

typedef struct stream_tuple {
    uint16_t transportId;
    uint32_t ssrc;
} stream_tuple_t;
typedef struct producer_to_consumer {
    send_stream_state_t* consumer;
    producer_to_consumer_t* next;
} producer_to_consumer_t;
typedef struct recv_stream_state {
    bool valid_bad_seq;
    bool init;
    uint16_t max_seq;
    uint32_t roc;
    uint16_t bad_seq;
    //uint16_t base_seq;
    uint8_t payloadType; // 7 bits
    uint8_t mimeType; // 2 bits
    uint8_t ntemporalLayers; // 2 bits
    uint8_t nspatialLayers; // 2 bits
    uint32_t* curr_bitrate; // in units of 16 Bytes/sec, 20 bits
    uint32_t* prev_bitrate; // in units of 16 Bytes/sec, 20 bits
    uint8_t clockRate; // in kHz
    uint32_t jitter;
    int32_t transit;
    bool paused;
    bool keyframePending;
    uint32_t mappedSsrc;
    uint8_t mappedPayloadType; // 7 bits
    producer_to_consumer_t* consumers;
} recv_stream_state_t;
typedef struct send_stream_state {
    bool valid_bad_seq;
    bool init;
    uint16_t max_seq;
    uint32_t roc;
    uint16_t bad_seq;
    //uint16_t base_seq;
    uint32_t curr_bitrate; // in units of 16 Bytes/sec, 20 bits
    uint32_t prev_bitrate; // in units of 16 Bytes/sec, 20 bits
    bool syncRequired;
    bool keyFrameSupported;
    uint32_t ssrc;
    uint32_t supportedPayloadTypes; // 96 - 127
    transport_state_t* transport;
    uint8_t type; // 2 bits, 00 = simpleconsumer, 01 = svcconsumer, 10 = simulcastconsumer
} send_stream_state_t;


class HardwareEmulator {
public:
    HardwareEmulator();

protected:
    static const uint16_t MAX_DROPOUT = 3000;
    static const uint16_t MAX_MISORDER = 100;
    static const uint64_t MAX_SRTP_PACKETS = 1u << 48;

    void ProcessPacket(uint8_t* data, size_t len, const struct sockaddr* remoteSockAddr);
    void PacketToCpu(uint8_t* data, size_t len, const struct sockaddr* remoteSockAddr);

    transport_tuple_t GetTransportTuple(const struct sockaddr* remoteSockAddr);
    std::unordered_map<transport_tuple_t, transport_state_t> transportTable;

    stream_tuple_t GetStreamTuple(const transport_state_t transportState, uint32_t ssrc);
    std::unordered_map<stream_tuple_t, stream_state_t> streamTable;
};