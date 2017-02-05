#ifndef CAPTURE_H
#define CAPTURE_H

#include <QDebug>
#include <QObject>

#include <iostream>
#include <tins/tins.h>
#include <thread>
#include <unistd.h>

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

#define FC_MGT_PROBEREQ     0x04
#define FC_MGT_PROBERESP    0x05
#define FC_MGT_BEACON       0x08

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
};

struct APinfo {
    int8_t signal;
    int STAcount = 0;
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
    int dataCount = 0;
};

#define PAIRWISE_FLAGS_CCMP 1
#define PAIRWISE_FLAGS_TKIP 2
#define PAIRWISE_FLAGS_WEP40 4
#define PAIRWISE_FLAGS_WEP104 8

#define PAIRWISE_FLAGS_MASK 15

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
