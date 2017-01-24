#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    /* TreeWidget column size */
    ui->treeWidget->header()->resizeSection(0, 230);    /* ESSID */
    ui->treeWidget->header()->resizeSection(1, 50);     /* STA Count */
    ui->treeWidget->header()->resizeSection(2, 60);     /* Signal */
    ui->treeWidget->header()->resizeSection(3, 80);     /* Beacon */
    ui->treeWidget->header()->resizeSection(4, 80);     /* Data */
    ui->treeWidget->header()->resizeSection(5, 50);     /* Channel */

    ui->treeWidget->header()->resizeSection(7, 70);     /* Cipher */

    ui->treeWidget->header()->resizeSection(9, 120);    /* BSSID */

    connect(&captureThread, SIGNAL(started()), &capture, SLOT(run()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(channel_loop()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(AP_Information()) );

    iLabel = new QLabel(this);
    statusLabel = new QLabel(this);
    channelLabel = new QLabel(this);

    iLabel->setText(tr("No Interface"));
    statusLabel->setText(tr("Stopped"));
    channelLabel->setText(tr("Channel"));

    ui->statusBar->addWidget(iLabel, 10);
    ui->statusBar->addWidget(statusLabel, 10);
    ui->statusBar->addWidget(channelLabel, 10);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionInterface_triggered()
{
    interfaceDialog.findInterface();

    interfaceDialog.setModal(true);
    interfaceDialog.exec();

    iLabel->setText(QString::fromStdString(interfaceDialog.handle));
}

void MainWindow::on_actionStart_triggered()
{
    /* Check handle */
    if ( interfaceDialog.handle.empty() ) {
        QMessageBox::critical(this, "Error", tr("Please select interface"), "Close");

    } else if (capture.status) {
        QMessageBox::critical(this, "Error", "It's already started", "Close");

    } else {
        capture.getHandle(interfaceDialog.handle);
        capture.status = true;
        capture.moveToThread(&captureThread);
        captureThread.start();

        statusLabel->setText("Running");
        ui->actionStart->setDisabled(true);
        ui->actionStop->setEnabled(true);

        timer.start(1000);
    }

}

void MainWindow::on_actionStop_triggered()
{
    if (capture.status) {
        timer.stop();

        capture.status = false;
        captureThread.quit();
        captureThread.wait();

        statusLabel->setText("Stopped");

        ui->actionStop->setDisabled(true);
        ui->actionStart->setEnabled(true);

    } else {
        QMessageBox::critical(this, "Error", "It's already stopped", "Close");
    }
}

void MainWindow::on_actionClear_triggered()
{
    capture.AP_hashmap.clear();
    capture.STA_hashmap.clear();

    while (int i = ui->treeWidget->topLevelItemCount())
        delete ui->treeWidget->topLevelItem(i - 1);
}

void MainWindow::channel_loop()
{
    snprintf (command, sizeof(command), "iwconfig %s channel %d", interfaceDialog.handle.c_str(), channel);
    system(command);

    channelLabel->setText(QString("Channel: %1").arg(channel));

    channel += 6;

    if (channel > 14)
        channel = channel % 6 + 1;
}

void MainWindow::AP_Information()
{
    for (const auto& it : capture.AP_hashmap) {
        QList<QTreeWidgetItem *> item = ui->treeWidget->findItems(QString::fromStdString(it.first), Qt::MatchFixedString, 9);

        /* New tree widget item */
        if (item.count() == 0) {
            QTreeWidgetItem* itemInfo = new QTreeWidgetItem(ui->treeWidget);

            itemInfo->setText(0, QString::fromStdString(it.second.SSID));
            itemInfo->setText(1, QString::number(capture.STA_hashmap.count(it.first)));
            itemInfo->setText(2, QString::number(it.second.signal));
            itemInfo->setText(3, QString::number(it.second.beaconCount));
            itemInfo->setText(4, QString::number(it.second.dataCount));
            itemInfo->setText(5, QString::number(it.second.channel));
            itemInfo->setText(6, QString::fromStdString(it.second.encryption));
            itemInfo->setText(7, QString::fromStdString(it.second.cipher));
            itemInfo->setText(8, QString::fromStdString(it.second.auth));
            itemInfo->setText(9, QString::fromStdString(it.first).toUpper());


        } else {    /* Tree widget item is exist */
            QTreeWidgetItem* itemInfo = item[0];

            itemInfo->setText(0, QString::fromStdString(it.second.SSID));
            itemInfo->setText(1, QString::number(capture.STA_hashmap.count(it.first)));
            itemInfo->setText(2, QString::number(it.second.signal));
            itemInfo->setText(3, QString::number(it.second.beaconCount));
            itemInfo->setText(4, QString::number(it.second.dataCount));
            itemInfo->setText(5, QString::number(it.second.channel));
            itemInfo->setText(6, QString::fromStdString(it.second.encryption));
            itemInfo->setText(7, QString::fromStdString(it.second.cipher));
            itemInfo->setText(8, QString::fromStdString(it.second.auth));

            STA_Information(it.first, itemInfo);

        }

    }   // End loop hashmap
}

void MainWindow::STA_Information(string BSSID, QTreeWidgetItem* parentItem)
{
    auto range = capture.STA_hashmap.equal_range(BSSID);

    for (auto it = range.first; it != range.second ; ++it) {
        QList<QTreeWidgetItem *> STAitem = ui->treeWidget->findItems(QString::fromStdString(it->second.STAmac),
                                                                     Qt::MatchRecursive | Qt::MatchFixedString, 9);

        if (STAitem.count() == 0) { // New station
            QTreeWidgetItem* itemInfo = new QTreeWidgetItem(parentItem);

            itemInfo->setText(0, QString("STA %1").arg(parentItem->childCount()));
            itemInfo->setText(1, "-");
            itemInfo->setText(2, QString::number(it->second.signal));
            itemInfo->setText(3, "-");
            itemInfo->setText(4, QString::number(it->second.dataCount));
            itemInfo->setText(5, (parentItem->text(5)));

            itemInfo->setText(9, QString::fromStdString(it->second.STAmac).toUpper());


        } else {
            QTreeWidgetItem* itemInfo = STAitem[0];

            itemInfo->setText(2, QString::number(it->second.signal));

            itemInfo->setText(4, QString::number(it->second.dataCount));

            itemInfo->setText(9, QString::fromStdString(it->second.STAmac).toUpper());


        }

    } // End Loop

}

