#include <iostream>
#include <unistd.h>
#include <map>
#include <thread>

#include <tins/tins.h>

using namespace std;
using namespace Tins;

void send_Beacon();
void send_probeResp(string srcaddr, string desaddr, string ssid);

void recv_Packet();

int isResponse(const Dot11ProbeRequest &proveReq);

inline int DS_status(const Dot11 &dot11) { return dot11.from_ds() * 2 + dot11.to_ds(); }

map<string, string> listSSID {
    {"00:01:36:11:11:22", "길길짱잘생김"},
    {"00:01:36:11:44:11", "테스트0"},
    {"00:01:36:11:33:11", "테스트1"},
    {"00:01:36:55:66:77", "테스트2"},
    {"00:01:36:11:22:33", "테스트3"},
    {"00:01:36:77:88:99", "테스트4"},
    {"00:01:36:77:88:AA", "테스트5"},
};

#define INTERFACE "wlan4"

#define	ISRESP_BROADCAST 1
#define ISRESP_UNICAST  2

int main(int argc, char *argv[])
{
    /* Thread for send beacon */
    thread beaconThread(&send_Beacon);
    /* Thread for recv packet & send probeResp */
    thread recvThread(&recv_Packet);

    beaconThread.join();
    recvThread.join();
}

void send_Beacon() {
    PacketSender sender(INTERFACE);

    while(true) {
        for (map<string, string>::iterator it = listSSID.begin(); it!=listSSID.end(); ++it) {

            RadioTap radiotap;

            radiotap.dbm_signal(-100);

            Dot11Beacon beacon;

            beacon.addr1(Dot11::BROADCAST);
            beacon.addr2(it->first);
            beacon.addr3(beacon.addr2());

            beacon.ssid(it->second);
            beacon.supported_rates({ 1.0f, 5.5f, 11.0f, 6, 9, 12, 18 });
            beacon.ds_parameter_set(8);

            beacon.erp_information(0);
            beacon.extended_supported_rates({ 24, 36, 48, 54 });

            beacon.rsn_information(RSNInformation::wpa2_psk());

            radiotap.inner_pdu(beacon);

            sender.send(radiotap);
            usleep(10000);
        }
    }
}

void recv_Packet() {
    Sniffer sniffer(INTERFACE, Sniffer::PROMISC);

    while (true) {
        PDU *packet = sniffer.next_packet();
        const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

        /*
         *  DS Status - Address field contents
         *
         *  To Ds  | From DS | Addr 1 | Addr 2 | Addr 3 | Addr 4
         *    0    |  0      |  DA    | SA     | BSSID  | n/a
         *    0    |  1      |  DA    | BSSID  | SA     | n/a
         *    1    |  0      |  BSSID | SA     | DA     | n/a
         *    1    |  1      |  RA    | TA     | DA     | SA
         */

        switch (DS_status(dot11)) {

        }

        /* Send probe response when received probe request */
        if (dot11.type() == Dot11::MANAGEMENT) {
            if (dot11.subtype() == Dot11::PROBE_REQ) {
                const Dot11ProbeRequest &proveReq = packet->rfind_pdu<Dot11ProbeRequest>();
                switch (isResponse(proveReq)) {
                    case ISRESP_BROADCAST:
                    {
                        for (map<string, string>::iterator it = listSSID.begin(); it!=listSSID.end(); ++it) {
                            send_probeResp(it->first, proveReq.addr2().to_string(), it->second);
                            usleep(10000);
                        }
                        break;
                    }

                    case ISRESP_UNICAST:
                    {
                        map<string, string>::iterator it = listSSID.find( proveReq.addr1().to_string() );
                        send_probeResp(it->first, proveReq.addr2().to_string(), it->second);
                        break;
                    }

                    default:
                        return;

                }
            }
        }   // end if


    }
}

int isResponse(const Dot11ProbeRequest &proveReq) {
    if (proveReq.addr1() == Dot11::BROADCAST) {
        return ISRESP_BROADCAST;
    }

    else if ( listSSID.find(proveReq.addr1().to_string()) != listSSID.end() ) {
        return ISRESP_UNICAST;
    }

    else
        return 0;
}

void send_probeResp(string srcaddr, string desaddr, string ssid) {
    PacketSender sender(INTERFACE);

    RadioTap radiotap;
    Dot11ProbeResponse ProbeResp;

    ProbeResp.addr1(desaddr);

    ProbeResp.ds_parameter_set(8);
    ProbeResp.supported_rates({ 1.0f, 5.5f, 11.0f, 6, 9, 12, 18 });
    ProbeResp.erp_information(0);
    ProbeResp.extended_supported_rates({ 24, 36, 48, 54 });

    ProbeResp.rsn_information(RSNInformation::wpa2_psk());

    ProbeResp.addr2(srcaddr);
    ProbeResp.addr3(ProbeResp.addr2());
    ProbeResp.ssid(ssid);

    radiotap.inner_pdu(ProbeResp);

    sender.send(radiotap);
}
