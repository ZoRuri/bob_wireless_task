#include "capture.h"

Capture::Capture(QObject *parent) : QObject(parent)
{
    status = false;
}

void Capture::getHandle(string handle)
{
    interface = handle;
}

void Capture::run()
{ 
    /* Config for setting monitor mode */
    SnifferConfiguration config;
    config.set_rfmon(true);
    Sniffer sniffer(interface, config);

    while (status) {
        PDU *packet = sniffer.next_packet();

        /* Capture Information structure */
        struct captureInfo capInfo;

        try {
            const RadioTap &radiotap = packet->rfind_pdu<RadioTap>();

            //if (radiotap.present() & RadioTap::TSTF)
               // clog << "timestamp: " << radiotap.tsft() << endl;

            if (radiotap.present() & RadioTap::DBM_SIGNAL)
                capInfo.signal = (int)radiotap.dbm_signal();
                //clog << std::dec << "signal=" << (int)radiotap.dbm_signal() << hex << " " << (int)radiotap.dbm_signal() << endl;

        } catch (Tins::pdu_not_found) {
            clog << "not radiotap packet" << endl;
            continue;
        }


        try {
            const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

            switch(dot11.type()) {
                case Dot11::MANAGEMENT:
                    capInfo.type = FC_TYPE_MANAGEMENT;
                    dot11_mgt_frame(packet, &capInfo);
                    break;

                case Dot11::CONTROL:
                    capInfo.type = FC_TYPE_CONTROL;
                    dot11_ctl_frame(packet, &capInfo);
                    break;

                case Dot11::DATA:
                    capInfo.type = FC_TYPE_DATA;
                    dot11_data_frame(packet, &capInfo);
                    break;

                default:
                    clog << "?" << endl;
            }

        } catch (Tins::pdu_not_found) {
            clog << "not dot11 packet" << endl;
            continue;
        }

    }
}

void Capture::dot11_mgt_frame(PDU *packet, captureInfo *capInfo)
{
    const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

    switch (dot11.subtype()) {
        case Dot11::PROBE_REQ:
            break;

        case Dot11::PROBE_RESP:
            break;

        case Dot11::BEACON:
            capInfo->type = FC_MGT_BEACON;
            dot11_information_element(packet, capInfo);
            break;

        case 14:        // Action no Ack
            return;

        default:
            return;
    }

    dot11_get_addr(packet, Dot11::MANAGEMENT, capInfo);

    save_CaptureInfo(capInfo);
}

void Capture::dot11_ctl_frame(PDU *packet, captureInfo *capInfo)
{
    const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

    switch (dot11.subtype()) {
        case Dot11::CTS:
            return;

        case 5: // VHT NDP Announcement - subtype 5
            return;
    }

    //const Dot11Control &ctl = packet->rfind_pdu<Dot11Control>();
}

void Capture::dot11_data_frame(PDU *packet, captureInfo *capInfo)
{
    //const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

    dot11_get_addr(packet, Dot11::DATA, capInfo);

    //const Dot11Data &data = packet->rfind_pdu<Dot11Data>();

    save_CaptureInfo(capInfo);
}

void Capture::dot11_information_element(PDU *packet, captureInfo *capInfo)
{
    const Dot11ManagementFrame &mgt = packet->rfind_pdu<Dot11ManagementFrame>();

    /* Loop tagged elements */
    for ( const auto& opt : mgt.options() ) {
        /* Check element ID */
        switch( opt.option() ) {
            case Dot11::SSID:
                capInfo->SSID = mgt.ssid();
                //clog << "ssid: " << mgt.ssid() << endl;
                break;

            case Dot11::DS_SET:
                capInfo->channel = (int)mgt.ds_parameter_set();
                //clog << "channel " << (int)mgt.ds_parameter_set() << endl;
                break;

            case Dot11::RSN:
            {
                RSNInformation rsn = mgt.rsn_information();

                /* Group Cypher Suite */
                if (rsn.group_suite() == RSNInformation::CCMP)
                    clog << "WPA2-AES" << endl;
                else if (rsn.group_suite() == RSNInformation::TKIP)
                    clog << "WPA-TKIP" << endl;
                else if (rsn.group_suite() == RSNInformation::WEP_40)
                    clog << "WEP_40" << endl;
                else if (rsn.group_suite() == RSNInformation::WEP_104)
                    clog << "WEP_104" << endl;

                /* AKM Cypher - Auth Key Management */
                for ( const auto& akm : rsn.akm_cyphers() ) {
                    if (akm == RSNInformation::PSK)
                        capInfo->auth.append("PSK");
                        //clog << "PSK" << endl;
                    else if (akm == RSNInformation::PMKSA)
                        capInfo->auth.append("802.1X/EAP");
                        //clog << "802.1X" << endl;
                }

                break;
            }

            default:
                break;
        }

    } // End loop tagged elements

}

void Capture::dot11_get_addr(PDU *packet, int type, captureInfo *capInfo)
{
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

    if (type == Dot11::MANAGEMENT) {
        const Dot11ManagementFrame &mgt = packet->rfind_pdu<Dot11ManagementFrame>();

        /* DS status */
        switch ( DS_status(dot11) ) {
            case DS_STATUS_NODS:
                //clog << mgt.addr1() << endl;
                //clog << mgt.addr2() << endl;
                capInfo->BSSID = mgt.addr3().to_string();
                break;

            case DS_STATUS_FROMDS:
                capInfo->STA = mgt.addr1().to_string();
                capInfo->BSSID = mgt.addr2().to_string();
                //clog << "AP: " << mgt.addr3() << endl;
                break;

            case DS_STATUS_TODS:
                capInfo->BSSID = mgt.addr1().to_string();
                capInfo->STA = mgt.addr2().to_string();
                //clog << "AP: " << mgt.addr3() << endl;
                break;

            case DS_STATUS_DSTODS:
                break;
        }
    } else if (type == Dot11::DATA) {
        const Dot11Data &data = packet->rfind_pdu<Dot11Data>();

        /* DS status */
        switch ( DS_status(dot11) ) {
            case DS_STATUS_NODS:
                //clog << data.addr1() << endl;
                //clog << data.addr2() << endl;
                capInfo->BSSID = data.addr3().to_string();
                break;

            case DS_STATUS_FROMDS:
                capInfo->STA = data.addr1().to_string();
                capInfo->BSSID = data.addr2().to_string();
                //clog << "AP: " << data.addr3() << endl;
                break;

            case DS_STATUS_TODS:
                capInfo->BSSID = data.addr1().to_string();
                capInfo->STA = data.addr2().to_string();
                //clog << "AP: " << data.addr3() << endl;
                break;

            case DS_STATUS_DSTODS:
                break;
        }

    }

}

void Capture::save_CaptureInfo(captureInfo *capInfo) {

    /* Find BSSID in AP Hashmap */
    const auto& APsearch = AP_hashmap.find(capInfo->BSSID);

    if ( APsearch != AP_hashmap.end() ) {    /* Already here */

        AP_hashmap[capInfo->BSSID].signal = capInfo->signal;
        AP_hashmap[capInfo->BSSID].SSID = capInfo->SSID;
        AP_hashmap[capInfo->BSSID].channel = capInfo->channel;
        AP_hashmap[capInfo->BSSID].auth = capInfo->auth;

        if (capInfo->type == FC_MGT_BEACON)
            AP_hashmap[capInfo->BSSID].beaconCount = AP_hashmap[capInfo->BSSID].beaconCount + 1;

        else if (capInfo->type == FC_TYPE_DATA) {
            if (!capInfo->STA.empty()) {    /* If station data */
                STAinfo STA;

                const auto& STAsearch = STA_hashmap.find(capInfo->BSSID);

                STA_hashmap.insert(pair<string, STAinfo>(capInfo->BSSID, STA));
            }

            AP_hashmap[capInfo->BSSID].dataCount = AP_hashmap[capInfo->BSSID].dataCount + 1;
        }

    } else {    /* First */
        APinfo AP;

        AP.signal = capInfo->signal;
        AP.SSID = capInfo->SSID;
        AP.channel = capInfo->channel;
        AP.auth = capInfo->auth;

        /* Check type */
        if (capInfo->type == FC_MGT_BEACON)
            AP.beaconCount = 1;
        else if (capInfo->type == FC_TYPE_DATA)
            return;

        AP_hashmap.insert(pair<string, APinfo>(capInfo->BSSID, AP));
    }

}
