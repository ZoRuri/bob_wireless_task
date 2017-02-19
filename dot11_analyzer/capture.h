#ifndef CAPTURE_H
#define CAPTURE_H

#include <QDebug>
#include <QObject>

#include <tins/tins.h>

#include <iostream>
#include <thread>
#include <unistd.h>
#include <time.h>

#include <unordered_map>

using namespace Tins;
using namespace std;

/* Define for DS Status */
#define DS_STATUS_NODS   0
#define DS_STATUS_TODS   1
#define DS_STATUS_FROMDS 2
#define DS_STATUS_DSTODS 3

/* Define for frame control type */
#define FC_TYPE_MANAGEMENT  0x00
#define FC_TYPE_CONTROL     0x10
#define FC_TYPE_DATA        0x20

#define FC_TYPE_MASK        0xf0

#define FC_MGT_PROBEREQ     0x04
#define FC_MGT_PROBERESP    0x05
#define FC_MGT_BEACON       0x08

#define FC_DATA_EAPOL       0x2F

/* Define for pairwise key type */
#define PAIRWISE_FLAGS_CCMP 1
#define PAIRWISE_FLAGS_TKIP 2
#define PAIRWISE_FLAGS_WEP40 4
#define PAIRWISE_FLAGS_WEP104 8

#define PAIRWISE_FLAGS_MASK 15

/* Define for EAPOL 4 way handshake */
#define EAPOL_MASK      15
#define EAPOL_KEY_1     0b0011
#define EAPOL_KEY_2_4   0b0101
#define EAPOL_KEY_3     0b1111

/* Define for EAPOL info status */
#define EAPOL_STATUS_NULL       0
//#define EAPOL_STATUS_IMCOMPLETE 2
#define EAPOL_STATUS_COMPLETE   7

#define EAPOL_FLAG_MIC    1
#define EAPOL_FLAG_SNONCE 2
#define EAPOL_FLAG_ANONCE 4

struct captureInfo {
    string BSSID;
    int8_t signal;
    int type;
    string SSID;
    string STAmac = "";
    int channel;
    string encryption = "OPEN";
    string cipher;
    string auth;
    /* EAPOL */
    uint64_t timestamp;
    uint eapolFlag = 0;
    int    keyVer;
    string snonce;
    string anonce;
    string mic;
};

struct APinfo {
    int8_t signal;
    int STAcount = 0;
    int EAPOLcount = 0;
    int channel = 0;
    string SSID;
    int dataCount = 0;
    int beaconCount = 0;
    string encryption;
    string cipher;
    string auth;
};

struct STAinfo {
    string STAmac;
    int8_t signal;
    int    dataCount = 0;

    uint   eapol_status = 0;
    int    eapol_keyVer;
    string eapol_snonce;
    string eapol_anonce;
    string eapol_mic;
    string eapol_updateTime;
    uint64_t eapol_timestamp;
};

class Capture : public QObject
{
    Q_OBJECT

public:
    explicit Capture(QObject *parent = 0);
    void getHandle(string handle);

    bool status;

    /* Key: BSSID, Value: Struct */
    unordered_map <string, APinfo> AP_hashmap;
    unordered_multimap <string, STAinfo> STA_hashmap;

private:
    void dot11_mgt_frame(PDU *packet, captureInfo *capInfo);
    void dot11_ctl_frame(PDU *packet, captureInfo *capInfo);
    void dot11_data_frame(PDU *packet, captureInfo *capInfo);

    void dot11_information_element(PDU *packet, captureInfo *capInfo);
    void dot11_get_addr(PDU *packet, int type, captureInfo *capInfo);

    inline int DS_status(const Dot11 &dot11) { return dot11.from_ds() * 2 + dot11.to_ds(); }

    inline string HexToString(const uint8_t *hexArray, int size) {
        string output;
        char temp[2];

        for (int i = 0; i < size; ++i) {
            sprintf(temp, "%02x", hexArray[i]);
            output.append(temp);
        }

        return output;
    }

    inline void insertEAPOL(STAinfo *eapolInfo, captureInfo *capInfo)
    {
        clog << "flag: " << capInfo->eapolFlag << endl;

        if ( capInfo->eapolFlag & EAPOL_FLAG_ANONCE )
            eapolInfo->eapol_anonce = capInfo->anonce;

        if ( capInfo->eapolFlag & EAPOL_FLAG_SNONCE )
            eapolInfo->eapol_snonce = capInfo->snonce;

        if ( capInfo->eapolFlag & EAPOL_FLAG_MIC )
            eapolInfo->eapol_mic = capInfo->mic;
    }

    void eapol_handshake(PDU *packet, captureInfo *capInfo);

    void save_CaptureInfo(captureInfo *capInfo);

    string interface;

    /* Lookup table for pairwise */
    unordered_map <int, string> encrption_LUT = {
       {PAIRWISE_FLAGS_CCMP, "WPA2"}, {PAIRWISE_FLAGS_TKIP, "WPA"},
       {PAIRWISE_FLAGS_WEP40, "WEP"}, {PAIRWISE_FLAGS_WEP104, "WEP"},
       {PAIRWISE_FLAGS_CCMP | PAIRWISE_FLAGS_TKIP, "WPA/WPA2"},
    };

    unordered_map <int, string> cipher_LUT = {
       {PAIRWISE_FLAGS_CCMP, "CCMP"}, {PAIRWISE_FLAGS_TKIP, "TKIP"},
       {PAIRWISE_FLAGS_WEP40, "WEP-40"}, {PAIRWISE_FLAGS_WEP104, "WEP-104"},
       {PAIRWISE_FLAGS_CCMP | PAIRWISE_FLAGS_TKIP, "MIXED"},
    };

public slots:
    void run();
};

#endif // CAPTURE_H
