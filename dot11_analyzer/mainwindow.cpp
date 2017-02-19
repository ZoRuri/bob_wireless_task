#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    /* TreeWidget column size */
    ui->treeWidget->header()->resizeSection(COLUMN_ESSID, 230);    /* ESSID */
    ui->treeWidget->header()->resizeSection(COLUMN_STACOUNT, 50);  /* STA Count */
    ui->treeWidget->header()->resizeSection(COLUMN_SIGNAL, 60);    /* Signal */
    ui->treeWidget->header()->resizeSection(COLUMN_BEACON, 80);    /* Beacon */
    ui->treeWidget->header()->resizeSection(COLUMN_DATA, 80);      /* Data */
    ui->treeWidget->header()->resizeSection(COLUMN_CHANNEL, 50);   /* Channel */

    ui->treeWidget->header()->resizeSection(COLUMN_CIPHER, 70);    /* Cipher */

    ui->treeWidget->header()->resizeSection(COLUMN_BSSID, 120);    /* BSSID */

    connect(&captureThread, SIGNAL(started()), &capture, SLOT(run()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(channel_loop()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(AP_Information()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(eapol_deauth()));

    iLabel = new QLabel(this);
    statusLabel = new QLabel(this);
    channelLabel = new QLabel(this);

    iLabel->setText(tr("No Interface"));
    statusLabel->setText(tr("Stopped"));
    channelLabel->setText(tr("Channel"));

    ui->statusBar->addWidget(iLabel, 10);
    ui->statusBar->addWidget(statusLabel, 10);
    ui->statusBar->addWidget(channelLabel, 10);

    ui->treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);

    connect(ui->treeWidget, &QTreeWidget::customContextMenuRequested, this, &MainWindow::contextMenu);

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

        timer.start(2000);
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
    channel += 6;

    if (channel > 14)
        channel = channel % 6 + 1;

    snprintf (command, sizeof(command), "iwconfig %s channel %d", interfaceDialog.handle.c_str(), channel);
    system(command);

    channelLabel->setText(QString("Channel: %1").arg(channel));

}

void MainWindow::AP_Information()
{
    for (const auto& it : capture.AP_hashmap) {
        QList<QTreeWidgetItem *> item = ui->treeWidget->findItems(QString::fromStdString(it.first), Qt::MatchFixedString, 10);

        /* New tree widget item */
        if (item.count() == 0) {
            QTreeWidgetItem* itemInfo = new QTreeWidgetItem(ui->treeWidget);

            itemInfo->setText(COLUMN_ESSID, QString::fromStdString(it.second.SSID));
            itemInfo->setText(COLUMN_STACOUNT, QString::number(capture.STA_hashmap.count(it.first)));
            itemInfo->setText(COLUMN_SIGNAL, QString::number(it.second.signal));
            itemInfo->setText(COLUMN_BEACON, QString::number(it.second.beaconCount));
            itemInfo->setText(COLUMN_DATA, QString::number(it.second.dataCount));
            itemInfo->setText(COLUMN_CHANNEL, QString::number(it.second.channel));
            itemInfo->setText(COLUMN_ENCRYPTION, QString::fromStdString(it.second.encryption));
            itemInfo->setText(COLUMN_CIPHER, QString::fromStdString(it.second.cipher));
            itemInfo->setText(COLUMN_AUTH, QString::fromStdString(it.second.auth));
            itemInfo->setText(COLUMN_EAPOL, QString::number(it.second.EAPOLcount));
            itemInfo->setText(COLUMN_BSSID, QString::fromStdString(it.first).toUpper());


        } else {    /* Tree widget item is exist */
            QTreeWidgetItem* itemInfo = item[0];

            itemInfo->setText(COLUMN_ESSID, QString::fromStdString(it.second.SSID));
            itemInfo->setText(COLUMN_STACOUNT, QString::number(capture.STA_hashmap.count(it.first)));
            itemInfo->setText(COLUMN_SIGNAL, QString::number(it.second.signal));
            itemInfo->setText(COLUMN_BEACON, QString::number(it.second.beaconCount));
            itemInfo->setText(COLUMN_DATA, QString::number(it.second.dataCount));
            itemInfo->setText(COLUMN_CHANNEL, QString::number(it.second.channel));
            itemInfo->setText(COLUMN_ENCRYPTION, QString::fromStdString(it.second.encryption));
            itemInfo->setText(COLUMN_CIPHER, QString::fromStdString(it.second.cipher));
            itemInfo->setText(COLUMN_AUTH, QString::fromStdString(it.second.auth));
            itemInfo->setText(COLUMN_EAPOL, QString::number(it.second.EAPOLcount));

            STA_Information(it.first, itemInfo);

        }

    }   // End loop hashmap
}

void MainWindow::STA_Information(string BSSID, QTreeWidgetItem* parentItem)
{
    auto range = capture.STA_hashmap.equal_range(BSSID);

    for (auto it = range.first; it != range.second ; ++it) {
        QList<QTreeWidgetItem *> STAitem = ui->treeWidget->findItems(QString::fromStdString(it->second.STAmac),
                                                                     Qt::MatchRecursive | Qt::MatchFixedString, 10);

        if (STAitem.count() == 0) { // New station
            QTreeWidgetItem *itemInfo = new QTreeWidgetItem(parentItem);

            itemInfo->setText(COLUMN_ESSID, QString("STA %1").arg(parentItem->childCount()));
            itemInfo->setText(COLUMN_STACOUNT, "-");
            itemInfo->setText(COLUMN_SIGNAL, QString::number(it->second.signal));
            itemInfo->setText(COLUMN_BEACON, "-");
            itemInfo->setText(COLUMN_DATA, QString::number(it->second.dataCount));
            itemInfo->setText(COLUMN_CHANNEL, (parentItem->text(5)));

            itemInfo->setText(COLUMN_EAPOL, QString::fromStdString(getStatus(it->second.eapol_status)));
            itemInfo->setText(COLUMN_BSSID, QString::fromStdString(it->second.STAmac).toUpper());


        } else {
            QTreeWidgetItem* itemInfo = STAitem[0];

            itemInfo->setText(COLUMN_SIGNAL, QString::number(it->second.signal));

            itemInfo->setText(COLUMN_DATA, QString::number(it->second.dataCount));

            itemInfo->setText(COLUMN_EAPOL, QString::fromStdString(getStatus(it->second.eapol_status)));
            itemInfo->setText(COLUMN_BSSID, QString::fromStdString(it->second.STAmac).toUpper());

        }

    } // End Loop

}

void MainWindow::contextMenu( const QPoint & pos )
{
    QTreeWidget *tree = ui->treeWidget;

    QTreeWidgetItem *item = tree->itemAt(pos);

    qDebug() << pos << item->text(0) << item->parent();

    QAction *sendDeauth = new QAction(tr("Send deauth packet"), this);
    QAction *eapolInfo = new QAction(tr("EAPOL information"), this);

    QSignalMapper *signalMapper = new QSignalMapper(this);
    QSignalMapper *signalMapper2 = new QSignalMapper(this);

    /* Parent item (AP) */
    if (item->parent() == nullptr) {
        /* Send deauth Dialog connect */
        connect(sendDeauth, SIGNAL(triggered()), signalMapper, SLOT(map()));

        QString deauthData = "%1 %2 %3";
        deauthData = deauthData.arg(item->text(COLUMN_BSSID), "FF:FF:FF:FF:FF:FF", item->text(5));

        signalMapper->setMapping(sendDeauth, deauthData);

        connect(signalMapper, SIGNAL(mapped(QString)), this, SLOT(send_deauth(QString)));

        /* EAPOL information Dialog connect */
        connect(eapolInfo, SIGNAL(triggered()), signalMapper2, SLOT(map()));

        QString eapolData = "%1 %2";
        eapolData = eapolData.arg(item->text(COLUMN_BSSID), item->text(COLUMN_ESSID));

        signalMapper2->setMapping(eapolInfo, eapolData);

        connect(signalMapper2, SIGNAL(mapped(QString)), this, SLOT(eapol_information(QString)));

    } else {
        /* Child item (STA) */
        /* Send deauth Dialog connect */
        connect(sendDeauth, SIGNAL(triggered()), signalMapper, SLOT(map()));

        QString deauthData = "%1 %2 %3";
        deauthData = deauthData.arg(item->parent()->text(COLUMN_BSSID), item->text(COLUMN_BSSID), item->text(COLUMN_CHANNEL));

        signalMapper->setMapping(sendDeauth, deauthData);

        connect(signalMapper, SIGNAL(mapped(QString)), this, SLOT(send_deauth(QString)));

        /* EAPOL information Dialog connect */
        connect(eapolInfo, SIGNAL(triggered()), signalMapper2, SLOT(map()));

        QString eapolData = "%1 %2";
        eapolData = eapolData.arg(item->parent()->text(COLUMN_BSSID), item->parent()->text(COLUMN_ESSID));

        signalMapper2->setMapping(eapolInfo, eapolData);

        connect(signalMapper2, SIGNAL(mapped(QString)), this, SLOT(eapol_information(QString)));
    }

    QMenu menu(this);
    menu.addAction(sendDeauth);
    menu.addAction(eapolInfo);

    QPoint point(pos);
    menu.exec(tree->mapToGlobal(pos));
}

void MainWindow::send_deauth(QString deauthData)
{
    QStringList data = deauthData.split(" ");

    sendDialog.setData(data.value(0), data.value(1), data.value(2).toInt(), iLabel->text());

    sendDialog.setModal(true);
    sendDialog.exec();
}

void MainWindow::eapol_information(QString eapolData)
{
    QStringList data = eapolData.split(" ");

    int eapolCount = capture.AP_hashmap[data.value(0).toLower().toStdString()].EAPOLcount;

    eapolDialog.setLabel(data.value(0), data.value(1), eapolCount);

    auto range = capture.STA_hashmap.equal_range(data.value(0).toLower().toStdString());

    for(auto itemList = range.first ;itemList != range.second; ++itemList)
    {
        if (itemList->second.eapol_status != EAPOL_STATUS_NULL) {
            eapolDialog.setItem(itemList->second.STAmac, itemList->second.eapol_anonce,
                                itemList->second.eapol_snonce, itemList->second.eapol_mic,
                                itemList->second.eapol_updateTime);
        }
    }

    eapolDialog.setModal(true);
    eapolDialog.exec();

    eapolDialog.itemClear();

}

void MainWindow::eapol_deauth()
{
    QString ch = QString::number(channel);

    QList<QTreeWidgetItem *> itemList = ui->treeWidget->findItems(ch, Qt::MatchExactly, COLUMN_CHANNEL);


    foreach( QTreeWidgetItem *item, itemList ) {
        auto range = capture.STA_hashmap.equal_range(item->text(COLUMN_BSSID).toLower().toStdString());

        for(auto eapolList = range.first; eapolList != range.second; ++eapolList)
        {
            if (eapolList->second.eapol_status != EAPOL_STATUS_COMPLETE) {
                sendPacket.sendDeauth(item->text(COLUMN_BSSID).toStdString(),
                                      eapolList->second.STAmac, "wlan4", 10);
            }
            //qDebug() << QString::fromStdString(eapolList->second.STAmac);
        }

        qDebug() << item->text(COLUMN_BSSID) << QString::number(capture.AP_hashmap[item->text(COLUMN_BSSID).toLower().toStdString()].EAPOLcount);


        //qDebug() << ch << item->text(COLUMN_BSSID) << item->text(COLUMN_CHANNEL);
    }
}
