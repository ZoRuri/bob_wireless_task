#ifndef INTERFACEDIALOG_H
#define INTERFACEDIALOG_H

#include <QDialog>
#include <qdebug.h>
#include <QMessageBox>
#include <pcap/pcap.h>

#include <iostream>

namespace Ui {
class InterfaceDialog;
}

class InterfaceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit InterfaceDialog(QWidget *parent = 0);
    ~InterfaceDialog();

    std::string handle;
    void findInterface();

private:
    void selectInterface();

private slots:
    void on_pbSelect_clicked();
    void on_pbClose_clicked();

private:
    Ui::InterfaceDialog *ui;
};

#endif // INTERFACEDIALOG_H
