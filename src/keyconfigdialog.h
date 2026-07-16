#ifndef KEYCONFIGDIALOG_H
#define KEYCONFIGDIALOG_H

#include <QDialog>

namespace Ui {
class KeyConfigDialog;
}

class KeyConfigDialog : public QDialog
{
    Q_OBJECT

public:
    explicit KeyConfigDialog(QWidget *parent = nullptr);
    ~KeyConfigDialog();

    QString getSm4KeyPath() const;
    QString getSm2PrivateKeyPath() const;
    QString getSm2PublicKeyPath() const;

    void setSm4KeyPath(const QString& path);
    void setSm2PrivateKeyPath(const QString& path);
    void setSm2PublicKeyPath(const QString& path);

private slots:
    void on_browseSm4Button_clicked();
    void on_browsePrivateKeyButton_clicked();
    void on_browsePublicKeyButton_clicked();
    void on_saveButton_clicked();
    void on_cancelButton_clicked();

private:
    Ui::KeyConfigDialog *ui;
};

#endif // KEYCONFIGDIALOG_H
