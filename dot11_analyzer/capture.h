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
#define FC_TYPE_CONTROL 0x10
#define FC_TYPE_DATA    0x20

#define FC_MGT_BEACON 0x08

struct captureInfo {
    string BSSID;
    int8_t signal;
    int type;
    string SSID;
    string STA = "";
    int channel;
    string encrption;
    string auth;
};

struct APinfo {
    int8_t signal;
    int STAcount = 0;
    int channel = 0;
    string SSID;
    int dataCount = 0;
    int beaconCount = 0;
    string encrption;
    string auth;
};

struct STAinfo {
    string STAmac;
    int dataCount = 0;
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

    void save_CaptureInfo(captureInfo *capInfo);

    string interface;

public slots:
    void run();
};

#endif // CAPTURE_H
