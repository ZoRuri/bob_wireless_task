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
        QList<QTreeWidgetItem *> item = ui->treeWidget->findItems(QString::fromStdString(it.first), Qt::MatchFixedString, 10);

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

            itemInfo->setText(10, QString::fromStdString(it.first).toUpper());


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
                                                                     Qt::MatchRecursive | Qt::MatchFixedString, 10);

        if (STAitem.count() == 0) { // New station
            QTreeWidgetItem* itemInfo = new QTreeWidgetItem(parentItem);

            itemInfo->setText(0, QString("STA %1").arg(parentItem->childCount()));
            itemInfo->setText(1, "-");
            itemInfo->setText(2, QString::number(it->second.signal));
            itemInfo->setText(3, "-");
            itemInfo->setText(4, QString::number(it->second.dataCount));
            itemInfo->setText(5, (parentItem->text(5)));

            itemInfo->setText(10, QString::fromStdString(it->second.STAmac).toUpper());


        } else {
            QTreeWidgetItem* itemInfo = STAitem[0];

            itemInfo->setText(2, QString::number(it->second.signal));

            itemInfo->setText(4, QString::number(it->second.dataCount));

            itemInfo->setText(10, QString::fromStdString(it->second.STAmac).toUpper());

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

    //connect(eapolInfo, SIGNAL(triggered()), this, SLOT(eapol_information()));

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

    int eapolCount = capture.EAPOL_hashmap.count(data.value(0).toLower().toStdString());

    eapolDialog.setLabel(data.value(0), data.value(1), eapolCount);

    auto range = capture.EAPOL_hashmap.equal_range(data.value(0).toLower().toStdString());

    for(auto itemList = range.first ;itemList != range.second; ++itemList)
    {
        eapolDialog.setItem(itemList->second.STAmac, itemList->second.anonce,
                            itemList->second.snonce, itemList->second.mic);
    }

//    for (const auto& it : capture.EAPOL_hashmap)
//    {
//        auto it2 = capture.EAPOL_hashmap.equal_range(it.first);

//        clog << "====ap====" << endl;
//        clog <<  it.first << endl;

//        for (auto it3 = it2.first; it3 != it2.second ; ++it3)
//        {
//            clog << "---------" << endl;
//            clog << it3->second.STAmac << endl;
//            clog << it3->second.snonce << endl;
//            clog << it3->second.anonce << endl;
//            clog << it3->second.mic << endl;
//            clog << it3->second.status << endl;
//            clog << it3->second.timestamp << endl;

//        }
//    }

    eapolDialog.setModal(true);
    eapolDialog.exec();

    eapolDialog.itemClear();

}


