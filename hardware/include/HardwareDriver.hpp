#include <string>

class HardwareDriver
{
    public:
        static void OnWebRtcTransportCreated(const std::string& id)
        {
            HardwareEmulator::OnWebRtcTransportCreated(UUIDHash(id));
        }

        static void OnWebRtcTransportClosed(const std::string& id)
        {
            HardwareEmulator::OnWebRtcTransportClosed(UUIDHash(id));
        }

    private:
        HardwareDriver();
};