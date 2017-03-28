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
    {"00:01:37:11:11:22", "1.테스트"},
    {"00:01:38:11:44:11", "2.ㅁㅇㅁㅇ"},
    {"00:01:39:11:33:11", "3.테스트테스트"},
    {"00:01:46:55:66:77", "Test2"},
    {"00:01:26:11:22:33", "Test3"},
    {"00:01:16:77:88:99", "Test4"},
    {"00:01:06:77:88:AA", "Test5"},
};

#define INTERFACE "wlx00a82b000c8e"

#define	ISRESP_BROADCAST 1
#define ISRESP_UNICAST  2

std::string interface = "";

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(0);
    }

    interface = argv[1];

    /* Thread for send beacon */
    thread beaconThread(&send_Beacon);
    /* Thread for recv packet & send probeResp */
    thread recvThread(&recv_Packet);

    beaconThread.join();
    recvThread.join();
}

void send_Beacon() {
    SnifferConfiguration config;
    config.set_rfmon(true);
    Sniffer sniffer(interface, config);

    PacketSender sender(interface);

    /* TIM struct */
    Dot11ManagementFrame::tim_type tim;

    tim.dtim_count = 1;
    tim.dtim_period = 3;
    tim.bitmap_control = 0;
    tim.partial_virtual_bitmap.insert(tim.partial_virtual_bitmap.begin(), 0);

    int i= 0;

    printf("in\n");

    while(true) {
        for (map<string, string>::iterator it = listSSID.begin(); it!=listSSID.end(); ++it) {

            RadioTap radiotap;

            Dot11Beacon beacon;

            beacon.addr1(Dot11::BROADCAST);
            beacon.addr2(it->first);
            beacon.addr3(beacon.addr2());

            /* Fixed parameters */
            beacon.interval(100);

            /* Capabilities info struct */
            beacon.capabilities().ess(1);
            beacon.capabilities().ibss(0);

            beacon.capabilities().cf_poll(0);
            beacon.capabilities().cf_poll_req(0);
            beacon.capabilities().qos(0);

            beacon.capabilities().privacy(1);
            beacon.capabilities().short_preamble(0);
            beacon.capabilities().pbcc(0);
            beacon.capabilities().channel_agility(0);
            beacon.capabilities().spectrum_mgmt(0);
            beacon.capabilities().sst(1);

            beacon.capabilities().apsd(0);
            beacon.capabilities().radio_measurement(0);
            beacon.capabilities().dsss_ofdm(0);
            beacon.capabilities().delayed_block_ack(0);
            beacon.capabilities().immediate_block_ack(0);

            /* Tagged parameters */
            beacon.ssid(it->second);
            beacon.supported_rates({ 1.0f, 2.0f, 5.5f, 11.0f, 6, 9, 12, 18 });
            beacon.ds_parameter_set(10);
            beacon.tim(tim);
            beacon.erp_information(0);

            Dot11Beacon::vendor_specific_type vendor;
            vendor.oui = "00:50:f2";
            vendor.data.insert(vendor.data.end(),
            {0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
             0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00});

            beacon.vendor_specific(vendor);

            beacon.extended_supported_rates({ 24, 36, 48, 54 });

            beacon.rsn_information(RSNInformation::wpa2_psk());

            radiotap.inner_pdu(beacon);

            sender.send(radiotap);
            usleep(100);

            printf("\r%d", ++i);
        }
        usleep(10000);

    }
}

void recv_Packet() {
    Sniffer sniffer(interface, Sniffer::PROMISC);

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
    PacketSender sender(interface);

    RadioTap radiotap;
    Dot11ProbeResponse ProbeResp;

    ProbeResp.addr1(desaddr);

    ProbeResp.ds_parameter_set(8);
    ProbeResp.supported_rates({ 1.0f, 2.0f, 5.5f, 11.0f, 6, 9, 12, 18 });
    ProbeResp.erp_information(0);
    ProbeResp.extended_supported_rates({ 24, 36, 48, 54 });

    ProbeResp.rsn_information(RSNInformation::wpa2_psk());

    ProbeResp.addr2(srcaddr);
    ProbeResp.addr3(ProbeResp.addr2());
    ProbeResp.ssid(ssid);

    radiotap.inner_pdu(ProbeResp);

    sender.send(radiotap);
}
