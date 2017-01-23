#include "interfacedialog.h"
#include "ui_interfacedialog.h"

InterfaceDialog::InterfaceDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InterfaceDialog)
{
    ui->setupUi(this);
    findInterface();
}

InterfaceDialog::~InterfaceDialog()
{
    delete ui;
}

void InterfaceDialog::findInterface() {
    pcap_if_t *alldevsp;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_findalldevs(&alldevsp, errbuf);

    for(dev = alldevsp; dev ; dev = dev->next)
    {
        ui->listWidget->addItem(dev->name);
    }

    pcap_freealldevs(alldevsp);
}

void InterfaceDialog::selectInterface() {
    QListWidgetItem *currentItem;
    currentItem = ui->listWidget->currentItem();

    if (currentItem != 0x0) {
        handle = currentItem->text().toStdString();

        qDebug() << handle.c_str();
        this->close();
    } else {
        QMessageBox::critical(this, "Error", "Please select interface", "Close");
    }

}

void InterfaceDialog::on_pbSelect_clicked()
{
    selectInterface();
}

void InterfaceDialog::on_pbClose_clicked()
{
    this->close();
}
