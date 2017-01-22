#include "interfacedialog.h"
#include "ui_interfacedialog.h"

InterfaceDialog::InterfaceDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InterfaceDialog)
{
    ui->setupUi(this);
}

InterfaceDialog::~InterfaceDialog()
{
    delete ui;
}
