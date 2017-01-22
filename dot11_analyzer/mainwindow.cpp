#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(&captureThread, SIGNAL(started()), &capture, SLOT(run()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(channel_loop()));
    connect(&timer, SIGNAL(timeout()), this, SLOT(test()) );

    //connect(&APThread, SIGNAL(timeout()), this, SLOT(test()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionInterface_triggered()
{
    interfaceDialog.setModal(true);
    interfaceDialog.exec();

    qDebug() << interfaceDialog.handle.c_str();
}

void MainWindow::on_actionStart_triggered()
{
    /* Check handle */
    if ( interfaceDialog.handle.empty() ) {
        QMessageBox::critical(this, "Error", "Please select interface", "Close");

    } else if (capture.status) {
        QMessageBox::critical(this, "Error", "It's already started", "Close");

    } else {
        capture.getHandle(interfaceDialog.handle);
        capture.status = true;
        capture.moveToThread(&captureThread);
        captureThread.start();

        moveToThread(&APThread);
        APThread.start();

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
    } else {
        QMessageBox::critical(this, "Error", "It's already stopped", "Close");
    }
}

void MainWindow::channel_loop()
{
    snprintf (command, sizeof(command), "iwconfig %s channel %d", interfaceDialog.handle.c_str(), channel);
    system(command);

    channel += 6;

    if (channel > 14)
        channel = channel % 6 + 1;
}

void MainWindow::test()
{
    for (const auto& it : capture.AP_hashmap) {
        QList<QTreeWidgetItem *> item = ui->treeWidget->findItems(QString::fromStdString(it.first), Qt::MatchExactly, 0);

        /* New tree widget item */
        if (item.count() == 0) {
            QTreeWidgetItem* itemInfo = new QTreeWidgetItem(ui->treeWidget);

            itemInfo->setText(0, QString::fromStdString(it.first));

            itemInfo->setText(2, QString::number(it.second.signal));
            itemInfo->setText(3, QString::number(it.second.beaconCount));
            itemInfo->setText(4, QString::number(it.second.dataCount));
            itemInfo->setText(5, QString::number(it.second.channel));

            itemInfo->setText(8, QString::fromStdString(it.second.auth));
            itemInfo->setText(9, QString::fromStdString(it.second.SSID));


        } else {    /* Tree widget item is exist */
            QTreeWidgetItem* itemInfo = item[0];

            itemInfo->setText(2, QString::number(it.second.signal));
            itemInfo->setText(3, QString::number(it.second.beaconCount));
            itemInfo->setText(4, QString::number(it.second.dataCount));
            itemInfo->setText(5, QString::number(it.second.channel));

            itemInfo->setText(8, QString::fromStdString(it.second.auth));
            itemInfo->setText(9, QString::fromStdString(it.second.SSID));
        }

    }   // End loop hashmap
}
