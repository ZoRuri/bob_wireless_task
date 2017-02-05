#ifndef SENDDIALOG_H
#define SENDDIALOG_H

#include <QDialog>
#include <QDebug>
#include <tins/tins.h>
#include <unistd.h>

using namespace Tins;

namespace Ui {
class SendDialog;
}

class SendDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SendDialog(QWidget *parent = 0);
    ~SendDialog();

    void setData(QString AP, QString STA, int channel, QString interface);

private slots:

    void on_pbSend_clicked();

    void on_pbQuit_clicked();

private:
    Ui::SendDialog *ui;

    pcap_if_t *alldevsp;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    char command[30];
};

#endif // SENDDIALOG_H
