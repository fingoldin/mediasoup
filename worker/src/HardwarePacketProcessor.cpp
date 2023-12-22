#include "HardwarePacketProcessor.hpp"

HardwarePacketProcessor::HardwarePacketProcessor()
{
    
}

void HardwarePacketProcessor::ProcessPacket(const uint8_t* data, size_t len)
{
    uint64_t transportHash;

    if(!this->transportReady[transportHash]) {
        // drop 
    }

    if(this->selectedTuples[transportHash] != transportHash) {
        bool found = false;
        for(int i = 0; i < HardwarePacketProcessor::MaxTuples; i++) {
            if(this->additionalTuples[transportHash] == transportHash) {
                found = true;
                break;
            }
        }
        if (!found)
        {
            // drop
        }
    }

    // Decrypt packet

    // Check if packet is valid RTP packet, else drop

    this->selectedTuples[transportHash] = transportHash;

    
}

uint64_t HardwarePacketProcessor::GetWebrtcTransportHashIPv4(const uint64_t address, const uint64_t port)
{
    uint64_t hash = port << 48;
    hash |= address << 16;
    hash |= 0x0000; // AF_INET.

    return hash;
}

uint64_t HardwarePacketProcessor::GetWebrtcTransportHashIPv6(const uint32_t* a, const uint64_t port)
{
    const uint32_t address1 = a[0] ^ a[1] ^ a[2] ^ a[3];
    const uint32_t address2 = a[0];

    uint64_t hash = port << 48;
    hash |= static_cast<uint64_t>(address1) << 16;
    hash |= address2 >> 16 & 0xFFFC;
    hash |= 0x0002; // AF_INET6.

    return hash;
}