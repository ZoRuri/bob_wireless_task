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
#include "capture.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_actionInterface_triggered();

    void on_actionStart_triggered();

    void on_actionStop_triggered();

    void channel_loop();

    void AP_Information();

    void STA_Information(string BSSID, QTreeWidgetItem* parentItem);

    void on_actionClear_triggered();

    void contextMenu(const QPoint & pos);

    void send_deauth(QString deauthInfo);

private:
    Ui::MainWindow *ui;

    InterfaceDialog interfaceDialog;
    SendDialog sendDialog;

    Capture capture;
    QThread captureThread;

    QTimer timer;

    QThread APThread;

    QLabel *iLabel;
    QLabel *statusLabel;
    QLabel *channelLabel;

    int channel = 1;
    char command[30];
};

#endif // MAINWINDOW_H
