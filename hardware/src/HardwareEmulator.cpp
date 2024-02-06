#include "HardwareEmulator.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory>
#include <cstring>

#define max(a,b) ((a) > (b) ? (a) : (b))

HardwareEmulator::HardwareEmulator()
{
    
}

void HardwareEmulator::OnWebRtcTransportCreated(uint32_t id)
{
    
}

void HardwareEmulator::PacketToCpu(uint8_t* data, size_t len, const struct sockaddr* remoteSockAddr)
{

}

void HardwareEmulator::ProcessPacket(uint8_t* data, size_t len, const struct sockaddr* remoteSockAddr)
{
    uint32_t currentTimeMs = 0; // TODO

    // Check if this is an RTP Packet by checking if its size is gte the minimal
    // header size, and if the version (first two bits) is 2.
    size_t header_len = 12;
    const bool isRtp = len >= header_len && data[0] > 127 && data[0] < 192;
    if(!isRtp) {
        return this->PacketToCpu(data, len, remoteSockAddr); // Non RTP packet
    }

    // Further validate header
    uint8_t cc = data[0] & 0xF;
    header_len = 12 + 4*cc;
    if(len < header_len) {
        return; // Drop;
    }
    bool x = data[0] & (1u << 4);
    if(x) {
        uint16_t xlen = ntohs(*(reinterpret_cast<const uint16_t*>(&data[4*(3 + cc) + 2])));
        header_len = 12 + 4*(cc + 1 + xlen);
        if(len < header_len) {
            return; // Drop
        }
    }

    const transport_tuple_t transportTuple = this->GetTransportTuple(remoteSockAddr);
    auto transportIt = this->transportTable.find(transportTuple);
    // WebRtcTransport ::OnRtpDataReceived 
    //      this->dtlsTransport->GetState() == RTC::DtlsTransport::DtlsState::CONNECTED 
    //      this->srtpRecvSession != nullptr 
    // WebRtcTransport::OnRtpDataReceived 
    //      this->iceServer->IsValidTuple(tuple) 
    // IceServer::HasTuple 
    if(transportIt == this->transportTable.end()) {
        return; // Drop 
    }
    transport_state_t transportState = transportIt->second;
    
    transportState.nbytes_recv += len;

    // Key limits
    if(transportState.npackets == HardwareEmulator::MAX_SRTP_PACKETS - 1) {
        return; // Drop
    }    

    const uint32_t nssrc = *(reinterpret_cast<const uint32_t*>(&data[8]));
    uint32_t ssrc = ntohl(nssrc);
    const stream_tuple_t streamTuple = this->GetStreamTuple(transportState, ssrc);
    auto streamIt = this->streamTable.find(streamTuple);
    if(streamIt == this->streamTable.end()) {
        return this->PacketToCpu(data, len, remoteSockAddr); // Run RtpListener::GetProducer and Producer::GetRtpStream for rtp stream initialization, then pass the packet back here
    }
    recv_stream_state_t streamState = streamIt->second;

    uint8_t payloadType = data[1] & 0b01111111;
    if (payloadType != streamState.payloadType) {
        return this->PacketToCpu(data, len, remoteSockAddr); // RTX streams?
    }

    const uint16_t seq = ntohs(*(reinterpret_cast<const uint16_t*>(&data[2])));

    // SrtpSession::DecryptSrtp
    // TODO: RTCP, replay database, multiple encryption algorithms (SRTP_AEAD), detect SSRC collisions between receiving and sending streams
    {
        uint16_t udelta = seq - streamState.max_seq;
        
        if(!streamState.init) {
            //streamState.base_seq = seq;
            streamState.max_seq = seq;
            streamState.valid_bad_seq = false;
            streamState.roc = 0;
            streamState.init = true;
        } else if(udelta < HardwareEmulator::MAX_DROPOUT) {
            if(seq < streamState.max_seq) {
                streamState.roc++;
            }
            streamState.max_seq = seq;
        } else if (udelta <= 65536 - HardwareEmulator::MAX_MISORDER) {
            if(streamState.valid_bad_seq && seq == streamState.bad_seq) {
                //streamState.base_seq = seq;
                streamState.max_seq = seq;
                streamState.valid_bad_seq = false;
                streamState.roc = 0;
            } else {
                streamState.bad_seq = seq + 1;
                streamState.valid_bad_seq = true;
            }
        }

        uint64_t packet_idx = (streamState.roc << 16) + seq;

        uint128_t* payload = reinterpret_cast<uint128_t*>(&data[header_len]);
        size_t npayload_blocks = (len - header_len)/16;
        size_t last_block_nbytes = (len - header_len) % 16;

        if(transportState.profile == SRTP_AES128_CM_HMAC_SHA1_80) {
            // Authentication
            const size_t tag_len = 10;

            uint8_t computed_tag[tag_len];
            uint8_t tag[tag_len];
            memcpy(&tag[0], &data[len - tag_len], tag_len); // extract auth tag
            memcpy(&data[len - tag_len], reinterpret_cast<uint8_t*>(&streamState.roc), 4); // Append the roc
            
            // TODO
            HardwareEmulator::HMAC_SHA1(&computed_tag[0], &data[0], len - tag_len + 4); // 10 bytes for auth tag, 4 bytes for roc
            for(size_t i = 0; i < tag_len; i++) 
                if(tag[i] != computed_tag[i])
                    return; // Drop

            uint128_t iv = (transportState.salt << 16) ^ (static_cast<uint128_t>(nssrc) << 64) ^ (static_cast<uint128_t>(packet_idx) << 16);

            for(size_t i = 0; i < npayload_blocks; i++)
                // TODO
                payload[i] = payload[i] ^ HardwareEmulator::AES(transportState.key, iv + i);
            
            if (last_block_nbytes) {
                uint8_t* last_keystream_block = reinterpret_cast<uint8_t*>(HardwareEmulator::AES(transportState.key, iv + npayload_blocks));
                uint8_t* last_block = reinterpret_cast<uint8_t*>(&payload[npayload_blocks]);
                for(size_t j = 0; j < last_block_nbytes; j++)
                    last_block[j] = last_block[j] ^ last_keystream_block[j];
            }
        } else {
            return this->PacketToCpu(data, len, remoteSockAddr); // Should never be here.
        }
    }

    // TODO: TransportCongestionControlServer::IncomingPacket

    // TODO: Producer::PreProcessRtpPacket(RTC::RtpPacket* packet)

    // TODO: RTC::Codecs::Tools::ProcessRtpPacket(packet, streamState.mimeType);
    bool isKeyframe = false;
    uint8_t spatialLayer = 0;
    uint8_t temporalLayer = 0;


    const uint32_t timestamp = ntohl(*(reinterpret_cast<uint32_t*>(&data[4])));
    uint32_t arrival = currentTimeMs*streamState.clockRate;
    int32_t transit = arrival - timestamp;
    uint32_t d = abs(transit - streamState.transit);
    if(streamState.transit == 0)
        streamState.transit = transit;
    else {
        streamState.transit = transit;
        streamState.jitter += d - ((streamState.jitter + 8) >> 4);
    }

    streamState.curr_bitrate[spatialLayer*streamState.ntemporalLayers + temporalLayer] += (8 + len) >> 4;

    if(isKeyframe && streamState.keyframePending)
        streamState.keyframePending = false;

    // Not inactive anymore.
    //if (streamState.inactive)
    //    streamState.inactive = false;

    transportState.npackets++;

    if (streamState.paused) {
        return; // Done
    }

    // TODO: Producer::MangleRtpPacket(RTC::RtpPacket* packet)
    ssrc = streamState.mappedSsrc;
    payloadType = streamState.mappedPayloadType;

    // TODO: Producer::PostProcessRtpPacket(RTC::RtpPacket* packet);

    producer_to_consumer_t* consumer = streamState.consumers;

    // Router::OnTransportProducerRtpPacketReceived
    // SimpleConsumer
    while(consumer) {
        send_stream_state_t& consumeStreamState = *(consumer->consumer);

        //consumer->SendRtpPacket(packet, sharedPacket);
        if (payloadType > 127 || payloadType < 96 || !(consumeStreamState.supportedPayloadTypes & (1u << (payloadType - 96))))
		{
			continue; // Drop
		}

        bool marker;
        // TODO: if(!packet->ProcessPayload(this->encodingContext.get(), marker)))
        {
            continue; // Drop
        }

        if (consumeStreamState.syncRequired && consumeStreamState.keyFrameSupported && isKeyframe)
        {
            continue; // Drop
        }

        if (consumeStreamState.syncRequired)
		{
			// TODO: this->rtpSeqManager.Sync(packet->GetSequenceNumber() - 1);

			consumeStreamState.syncRequired = false;
		}

        // TODO: bool SeqManager<T, N>::Input(const T input, T& output);

        ssrc = consumeStreamState.ssrc;
        // TODO: set seq

        uint16_t udelta = seq - consumeStreamState.max_seq;
        
        if(!consumeStreamState.init) {
            //streamState.base_seq = seq;
            consumeStreamState.max_seq = seq;
            consumeStreamState.valid_bad_seq = false;
            consumeStreamState.roc = 0;
            consumeStreamState.init = true;
        } else if(udelta < HardwareEmulator::MAX_DROPOUT) {
            if(seq < consumeStreamState.max_seq) {
                consumeStreamState.roc++;
            }
            consumeStreamState.max_seq = seq;
        } else if (udelta <= 65536 - HardwareEmulator::MAX_MISORDER) {
            if(consumeStreamState.valid_bad_seq && seq == consumeStreamState.bad_seq) {
                //streamState.base_seq = seq;
                consumeStreamState.max_seq = seq;
                consumeStreamState.valid_bad_seq = false;
                consumeStreamState.roc = 0;
            } else {
                consumeStreamState.bad_seq = seq + 1;
                consumeStreamState.valid_bad_seq = true;
            }
        }

        consumeStreamState.curr_bitrate += (8 + len) >> 4;

        // TODO: packet->UpdateAbsSendTime(DepLibUV::GetTimeMs());

        // Libwebrtc TCC Client

        // TODO: Encrypt packet

        // TODO: Send packet

        consumeStreamState.transport->npackets++;

        consumer = consumer->next;
    }
}

stream_tuple_t HardwareEmulator::GetStreamTuple(const transport_state_t transportState, const uint32_t ssrc)
{
    stream_tuple_t tuple;
    tuple.transportId = transportState.id;
    tuple.ssrc = ssrc;
    return tuple;
}

transport_tuple_t HardwareEmulator::GetTransportTuple(const struct sockaddr* remoteSockAddr)
{
    transport_tuple_t tuple;

    switch (remoteSockAddr->sa_family)
    {
        case AF_INET:
        {
            auto* remoteSockAddrIn = reinterpret_cast<const struct sockaddr_in*>(remoteSockAddr);

            tuple.address[0] = ntohl(remoteSockAddrIn->sin_addr.s_addr);
            tuple.port = ntohs(remoteSockAddrIn->sin_port);
            tuple.isIPv6 = false;

            break;
        }
        case AF_INET6:
        {
            auto* remoteSockAddrIn6 = reinterpret_cast<const struct sockaddr_in6*>(remoteSockAddr);
            auto* a = reinterpret_cast<const uint32_t*>(std::addressof(remoteSockAddrIn6->sin6_addr));

            for(int i = 0; i < 4; i++)
                tuple.address[3 - i] = ntohl(a[i]);
            tuple.port = ntohs(remoteSockAddrIn6->sin6_port);
            tuple.isIPv6 = true;

            break;
        }
    }

    return tuple;
}