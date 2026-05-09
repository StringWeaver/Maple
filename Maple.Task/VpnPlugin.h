#pragma once
#include <mutex>
#include "leaf.h"
#include "CustomBuffer.h"
#include "winrt/Windows.Networking.Sockets.h"
#include "winrt/Windows.Networking.Vpn.h"

namespace winrt::Maple_Task::implementation
{
    static const hstring CONFIG_PATH_SETTING_KEY = L"CONFIG_PATH";
    static const hstring NETIF_SETTING_KEY = L"NETIF";
    static constexpr std::wstring_view ConfigFolderAccessListKey = L"configFolder";
    struct VpnPlugin : implements<VpnPlugin, Windows::Networking::Vpn::IVpnPlugIn>
    {
        VpnPlugin() = default;

        void Connect(Windows::Networking::Vpn::VpnChannel const& channel);
        void Disconnect(Windows::Networking::Vpn::VpnChannel const& channel);
        void GetKeepAlivePayload(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer& keepAlivePacket);
        void Encapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBufferList const& packets, Windows::Networking::Vpn::VpnPacketBufferList const& encapulatedPackets);
        void Decapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer const& encapBuffer, Windows::Networking::Vpn::VpnPacketBufferList const& decapsulatedPackets, Windows::Networking::Vpn::VpnPacketBufferList const& controlPacketsToSend);

        void ConnectCore(Windows::Networking::Vpn::VpnChannel const& channel);
        void StopLeaf();

        Leaf* m_leaf{};
        NetStackHandle* m_netStackHandle{};
        Windows::Networking::Vpn::VpnChannel m_channel{ nullptr };
        std::mutex m_channelLock{};
    };
    extern winrt::com_ptr<VpnPlugin> VpnPluginInstance;
}
