#ifndef EAPOLDIALOG_H
#define EAPOLDIALOG_H

#include <QDialog>

#include <iostream>

#include <unordered_map>

#include "capture.h"

using namespace std;

namespace Ui {
class EAPOLDialog;
}

class EAPOLDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EAPOLDialog(QWidget *parent = 0);
    ~EAPOLDialog();

    void setLabel(QString BSSID, QString ESSID, int EAPOLcount);

    void setItem(string STAmac, string anonce, string snonce, string mic);

    void itemClear();

private:
    Ui::EAPOLDialog *ui;

    Capture capture;

};

#endif // EAPOLDIALOG_H
