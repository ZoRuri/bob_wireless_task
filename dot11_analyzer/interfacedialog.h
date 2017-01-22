#ifndef INTERFACEDIALOG_H
#define INTERFACEDIALOG_H

#include <QDialog>

namespace Ui {
class InterfaceDialog;
}

class InterfaceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit InterfaceDialog(QWidget *parent = 0);
    ~InterfaceDialog();

private:
    Ui::InterfaceDialog *ui;
};

#endif // INTERFACEDIALOG_H
