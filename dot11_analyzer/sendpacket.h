#ifndef SENDPACKET_H
#define SENDPACKET_H

#include <tins/tins.h>
#include <iostream>
#include <unistd.h>

class SendPacket
{
public:
    SendPacket();

    void sendDeauth(std::string BSSID, std::string STA_ADDR, std::string interface_name, int count);
};

#endif // SENDPACKET_H
