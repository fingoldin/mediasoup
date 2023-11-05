#include <cstdint>

typedef uint16_t transport_hash_t;
const int TRANSPORT_HASH_MAP_SIZE = 65536; // bytes

class HardwarePacketProcessor {
public:
    HardwarePacketProcessor();

protected:
    void ProcessPacket(const uint8_t* data, size_t len);

    uint8_t transportReady[TRANSPORT_HASH_MAP_SIZE/8];
  
    transport_hash_t selectedTuples[TRANSPORT_HASH_MAP_SIZE];
    transport_hash_t additionalTuples[TRANSPORT_HASH_MAP_SIZE][8];

    uint8_t midExtensionIds[TRANSPORT_HASH_MAP_SIZE];
    uint8_t ridExtensionIds[TRANSPORT_HASH_MAP_SIZE];
    uint8_t repairedRidExtensionIds[TRANSPORT_HASH_MAP_SIZE];
	uint8_t absSendTimeExtensionIds[TRANSPORT_HASH_MAP_SIZE];
	uint8_t transportWideCc01ExtensionIds[TRANSPORT_HASH_MAP_SIZE];

    BlockingQueue unprocessedQueue;
};