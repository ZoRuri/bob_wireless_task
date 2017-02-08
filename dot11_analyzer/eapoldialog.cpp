#include "eapoldialog.h"
#include "ui_eapoldialog.h"

EAPOLDialog::EAPOLDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EAPOLDialog)
{
    ui->setupUi(this);

    this->setWindowTitle("EAPOL information");
}

EAPOLDialog::~EAPOLDialog()
{
    delete ui;
}

void EAPOLDialog::setLabel(QString BSSID, QString ESSID, int EAPOLcount)
{
    ui->label_bssid->setText(QString("BSSID : %1").arg(BSSID));
    ui->label_essid->setText(QString("ESSID : %1").arg(ESSID));
    ui->label_eapolCount->setText(QString("Handshake Count : %1").arg(EAPOLcount));
}

void EAPOLDialog::setItem(string STAmac, string anonce, string snonce, string mic, string updateTime)
{
    QTreeWidgetItem *itemInfo = new QTreeWidgetItem(ui->treeWidget);

    itemInfo->setText(0, QString::fromStdString(STAmac).toUpper());
    itemInfo->setText(1, QString::fromStdString(anonce));
    itemInfo->setText(2, QString::fromStdString(snonce));
    itemInfo->setText(3, QString::fromStdString(mic));
    itemInfo->setText(4, QString::fromStdString(updateTime));


//    auto itemList = capture.EAPOL_hashmap.find(BSSID);

//    for (;itemList != capture.EAPOL_hashmap.end(); ++itemList)
//    {
//        itemInfo->setText(0, QString::fromStdString(itemList->second.STAmac));
//        itemInfo->setText(1, QString::fromStdString(itemList->second.anonce));
//        itemInfo->setText(2, QString::fromStdString(itemList->second.snonce));
//        itemInfo->setText(3, QString::fromStdString(itemList->second.mic));
//    }

}

void EAPOLDialog::itemClear()
{
    while (int i = ui->treeWidget->topLevelItemCount())
        delete ui->treeWidget->topLevelItem(i - 1);
}
