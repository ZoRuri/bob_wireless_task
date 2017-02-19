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

            if (radiotap.present() & RadioTap::TSTF)
                capInfo.timestamp = radiotap.tsft();

            if (radiotap.present() & RadioTap::DBM_SIGNAL)
                capInfo.signal = (int)radiotap.dbm_signal();

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
    const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

    if (dot11.subtype() & Dot11::DATA_NULL)
        ;

    dot11_get_addr(packet, Dot11::DATA, capInfo);

    /* if QoS Data (EAPOL is on QoS Data packet) */
    if (dot11.subtype() & Dot11::QOS_DATA_DATA) {
        eapol_handshake(packet, capInfo);
    }

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
                break;

            case Dot11::DS_SET:
                capInfo->channel = (int)mgt.ds_parameter_set();
                break;

            case Dot11::RSN:
            {
                RSNInformation rsn = mgt.rsn_information();

                /* Group Cypher Suite */
                /*
                if (rsn.group_suite() == RSNInformation::CCMP)
                    clog << "WPA2-AES" << endl;
                else if (rsn.group_suite() == RSNInformation::TKIP)
                    clog << "WPA-TKIP" << endl;
                else if (rsn.group_suite() == RSNInformation::WEP_40)
                    clog << "WEP_40" << endl;
                else if (rsn.group_suite() == RSNInformation::WEP_104)
                    clog << "WEP_104" << endl;
                */
                int count = 0;

                for ( const auto& pairwise : rsn.pairwise_cyphers() ) {

                    if (pairwise == RSNInformation::CCMP)
                        count |= PAIRWISE_FLAGS_CCMP;

                    else if (pairwise == RSNInformation::TKIP)
                        count |= PAIRWISE_FLAGS_TKIP;

                    else if (pairwise == RSNInformation::WEP_40)
                        count |= PAIRWISE_FLAGS_WEP40;

                    else if (pairwise == RSNInformation::WEP_104)
                        count |= PAIRWISE_FLAGS_WEP104;
                }

                capInfo->encryption = encrption_LUT.find(count)->second;
                capInfo->cipher = cipher_LUT.find(count)->second;

                /* AKM Cypher - Auth Key Management */
                for ( const auto& akm : rsn.akm_cyphers() ) {

                    if (akm == RSNInformation::PSK)
                        capInfo->auth.append("PSK");

                    else if (akm == RSNInformation::PMKSA)
                        capInfo->auth.append("802.1X/EAP");
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
                capInfo->STAmac = mgt.addr1().to_string();
                capInfo->BSSID = mgt.addr2().to_string();
                //clog << "AP: " << mgt.addr3() << endl;
                break;

            case DS_STATUS_TODS:
                capInfo->BSSID = mgt.addr1().to_string();
                capInfo->STAmac = mgt.addr2().to_string();
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
                capInfo->STAmac = data.addr1().to_string();
                capInfo->BSSID = data.addr2().to_string();
                //clog << "AP: " << data.addr3() << endl;
                break;

            case DS_STATUS_TODS:
                capInfo->BSSID = data.addr1().to_string();
                capInfo->STAmac = data.addr2().to_string();
                //clog << "AP: " << data.addr3() << endl;
                break;

            case DS_STATUS_DSTODS:
                break;
        }

    }

}

void Capture::eapol_handshake(PDU *packet, captureInfo *capInfo)
{
    const RSNEAPOL *eapol = packet->find_pdu<RSNEAPOL>();

    if (eapol == nullptr)
        return;

    capInfo->type = FC_DATA_EAPOL;

    /* Get EAPOL's flags */
    u_int keyType = (u_int)eapol->key_t();
    u_int keyAck  = (u_int)eapol->key_ack() * 2;
    u_int keyMic  = (u_int)eapol->key_mic() * 4;
    u_int install = (u_int)eapol->install() * 8;

    u_int keyInfo = keyType | keyAck | keyMic | install;

    EAPOLinfo EAPOL;

    switch(keyInfo & EAPOL_MASK) {
        /* EAPOL Handshake 1 of 4 */
        case EAPOL_KEY_1:
            capInfo->anonce = HexToString(eapol->nonce(), RSNEAPOL::nonce_size);
            capInfo->eapolFlag = EAPOL_FLAG_ANONCE;
            break;

        case EAPOL_KEY_2_4:
            if (eapol->wpa_length()) {
                /* EAPOL Handshake 2 of 4 */
                capInfo->snonce = HexToString(eapol->nonce(), RSNEAPOL::nonce_size);
                capInfo->eapolFlag = EAPOL_FLAG_SNONCE;
            } else {
                /* EAPOL Handshake 4 of 4 */
                capInfo->mic = HexToString(eapol->mic(), RSNEAPOL::mic_size);
                capInfo->eapolFlag = EAPOL_FLAG_MIC;
            }
            break;

        /* EAPOL Handshake 3 of 4 */
        case EAPOL_KEY_3:
            capInfo->anonce = HexToString(eapol->nonce(), RSNEAPOL::nonce_size);
            capInfo->eapolFlag = EAPOL_FLAG_ANONCE;
            break;

        default:
            clog << "wrong eapol" << endl;
            break;
    }
}

void Capture::save_CaptureInfo(captureInfo *capInfo)
{
    /* Broadcast || Multicast*/
    if (capInfo->BSSID.find("ff:ff:ff:ff:ff:ff") != string::npos
            || capInfo->STAmac.find("01:00:5e") == 0
            || capInfo->STAmac.find("33:33") == 0)
        return;

    /* Check Type */
    switch(capInfo->type & FC_TYPE_MASK) {
        case FC_TYPE_MANAGEMENT:
        {
            if (capInfo->type == FC_MGT_BEACON) {
                /* Find BSSID in AP Hashmap */
                const auto& APsearch = AP_hashmap.find(capInfo->BSSID);

                if ( APsearch != AP_hashmap.end() ) {    /* Finded */
                    AP_hashmap[capInfo->BSSID].beaconCount = AP_hashmap[capInfo->BSSID].beaconCount + 1;
                    AP_hashmap[capInfo->BSSID].signal = capInfo->signal;
                    AP_hashmap[capInfo->BSSID].SSID = capInfo->SSID;
                    AP_hashmap[capInfo->BSSID].channel = capInfo->channel;
                    AP_hashmap[capInfo->BSSID].auth = capInfo->auth;
                    AP_hashmap[capInfo->BSSID].encryption = capInfo->encryption;
                    AP_hashmap[capInfo->BSSID].cipher = capInfo->cipher;

                } else {    /* First */
                    APinfo AP;

                    AP.signal = capInfo->signal;
                    AP.SSID = capInfo->SSID;
                    AP.channel = capInfo->channel;
                    AP.auth = capInfo->auth;
                    AP.cipher = capInfo->cipher;
                    AP.encryption = capInfo->encryption;
                    AP.beaconCount = 1;

                    AP_hashmap.insert(pair<string, APinfo>(capInfo->BSSID, AP));
                }
            }

            break;
        }

        case FC_TYPE_DATA:
        {
            /* Find BSSID in AP Hashmap */
            const auto& APsearch = AP_hashmap.find(capInfo->BSSID);

            if ( APsearch == AP_hashmap.end() )
                return;

            /* Broadcast || Multicast*/
            if (capInfo->STAmac.find("ff:ff:ff:ff:ff:ff") != string::npos
                    || capInfo->STAmac.find("01:00:5e") == 0
                    || capInfo->STAmac.find("33:33") == 0)
                return;

            AP_hashmap[capInfo->BSSID].dataCount = AP_hashmap[capInfo->BSSID].dataCount + 1;

            if (!capInfo->STAmac.empty()) {    /* If station data */
                STAinfo STA;
                int checkFinded = 0;

                auto STAsearch = STA_hashmap.find(capInfo->BSSID);

                if (STAsearch == STA_hashmap.end()) {   /* First child station */
                    STA.STAmac = capInfo->STAmac;
                    STA.signal = capInfo->signal;
                    STA.dataCount = 1;

                    AP_hashmap[capInfo->BSSID].STAcount = AP_hashmap[capInfo->BSSID].STAcount + 1;
                    STA_hashmap.insert(pair<string, STAinfo>(capInfo->BSSID, STA));

                } else {    /* Others */
                    /* Loop finded station */
                    for(; STAsearch != STA_hashmap.end(); ++STAsearch) {
                        if (STAsearch->second.STAmac == capInfo->STAmac) {
                            STAsearch->second.dataCount = STAsearch->second.dataCount + 1;
                            STAsearch->second.signal = capInfo->signal;
                            checkFinded = 1;
                            break;
                        }
                    } // End station search loop

                    if (!checkFinded) {
                        STA.signal = capInfo->signal;
                        STA.STAmac = capInfo->STAmac;
                        STA.dataCount = 1;

                        AP_hashmap[capInfo->BSSID].STAcount = AP_hashmap[capInfo->BSSID].STAcount + 1;
                        STA_hashmap.insert(pair<string, STAinfo>(capInfo->BSSID, STA));
                    }
                }

            } // End station data

            /* if EAPOL packet */
            if (capInfo->type == FC_DATA_EAPOL) {
                /* For update time */
                time_t now = time(NULL);

                struct tm tstruct;
                char buf[20];

                tstruct = *localtime(&now);

                strftime(buf, sizeof(buf), "%Y-%m-%d %I:%M:%S", &tstruct);
                string updateTime(buf);

                auto EAPOLsearch = EAPOL_hashmap.find(capInfo->BSSID);

                EAPOLinfo EAPOL;

                if (EAPOLsearch == EAPOL_hashmap.end()) {   /* First EAPOL info in AP */

                    insertEAPOL(&EAPOL, capInfo);

                    EAPOL.STAmac = capInfo->STAmac;
                    EAPOL.status |= capInfo->eapolFlag;
                    EAPOL.updateTime = updateTime;

                    EAPOL.timestamp = capInfo->timestamp;   /* radiotap mac time */

                    EAPOL_hashmap.insert(pair<string, EAPOLinfo>(capInfo->BSSID, EAPOL));

                    clog << EAPOL.mic << " " << EAPOL.anonce << " " << EAPOL.snonce << endl;

                } else {    /* Others */
                    for (; EAPOLsearch != EAPOL_hashmap.end(); ++EAPOLsearch) {
                        if (EAPOLsearch->second.STAmac == capInfo->STAmac) {
                            /* if collect all EAPOL Handshake */
                            if ( EAPOLsearch->second.status == EAPOL_STATUS_COMPLETE )
                                return;

                            /* if new EAPOL handshake */
                            if ( 250000 < (capInfo->timestamp - EAPOLsearch->second.timestamp) ) {
                                EAPOLsearch->second.snonce = "";
                                EAPOLsearch->second.anonce = "";
                                EAPOLsearch->second.mic = "";
                                EAPOLsearch->second.status = 0;
                            }

                            insertEAPOL(&EAPOLsearch->second, capInfo);

                            EAPOLsearch->second.updateTime = updateTime;
                            EAPOLsearch->second.timestamp = capInfo->timestamp;
                            EAPOLsearch->second.status = EAPOLsearch->second.status | capInfo->eapolFlag;

                            return;
                        }
                    } // End loop

                    insertEAPOL(&EAPOL, capInfo);

                    EAPOL.status = capInfo->eapolFlag;
                    EAPOL.STAmac = capInfo->STAmac;
                    EAPOL.updateTime = updateTime;

                    EAPOL.timestamp = capInfo->timestamp;   /* radiotap mac time */

                    EAPOL_hashmap.insert(pair<string, EAPOLinfo>(capInfo->BSSID, EAPOL));
                }

            }

            break;
        }

        default:
            return;

    }

}
