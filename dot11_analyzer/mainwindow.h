#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qdebug.h>
#include <QThread>
#include <QTimer>
#include <QTreeWidgetItem>
#include <QLabel>
#include <QPoint>
#include <QSignalMapper>

#include "interfacedialog.h"
#include "senddialog.h"
#include "eapoldialog.h"

#include "capture.h"
#include "sendpacket.h"

#define COLUMN_ESSID        0
#define COLUMN_STACOUNT     1
#define COLUMN_SIGNAL       2
#define COLUMN_BEACON       3
#define COLUMN_DATA         4
#define COLUMN_CHANNEL      5
#define COLUMN_ENCRYPTION   6
#define COLUMN_CIPHER       7
#define COLUMN_AUTH         8
#define COLUMN_EAPOL        9
#define COLUMN_BSSID       10

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    void STA_Information(string BSSID, QTreeWidgetItem* parentItem);

private slots:
    void on_actionInterface_triggered();

    void on_actionStart_triggered();

    void on_actionStop_triggered();

    void channel_loop();

    void on_actionClear_triggered();

    void contextMenu(const QPoint & pos);

    void AP_Information();

    void send_deauth(QString deauthInfo);

    void eapol_information(QString eapolData);

    void eapol_deauth();

private:
    Ui::MainWindow *ui;

    InterfaceDialog interfaceDialog;
    SendDialog      sendDialog;
    EAPOLDialog     eapolDialog;

    Capture capture;
    QThread captureThread;

    SendPacket sendPacket;

    QTimer timer;

    QThread APThread;

    QLabel *iLabel;
    QLabel *statusLabel;
    QLabel *channelLabel;

    int channel = 1;
    char command[30];

    inline string getStatus(int status) {
        if (status == EAPOL_STATUS_NULL)
            return "NULL";
        else if (status == EAPOL_STATUS_COMPLETE)
            return "Complete";
        else
            return "Incomplete";

    }
};

#endif // MAINWINDOW_H
