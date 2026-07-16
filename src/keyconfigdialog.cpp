#include "keyconfigdialog.h"
#include "ui_keyconfigdialog.h"
#include "configmanager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>

KeyConfigDialog::KeyConfigDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::KeyConfigDialog)
{
    ui->setupUi(this);

    // 设置模态对话框
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::WindowTitleHint |
                   Qt::WindowCloseButtonHint );
    // 加载现有配置
    ConfigManager& config = ConfigManager::instance();
    ui->sm4KeyEdit->setText(config.getSm4KeyPath());
    ui->privateKeyEdit->setText(config.getPrivateKeyPath());
    ui->publicKeyEdit->setText(config.getPublicKeyPath());
}

KeyConfigDialog::~KeyConfigDialog()
{
    delete ui;
}

QString KeyConfigDialog::getSm4KeyPath() const
{
    return ui->sm4KeyEdit->text();
}

QString KeyConfigDialog::getSm2PrivateKeyPath() const
{
    return ui->privateKeyEdit->text();
}

QString KeyConfigDialog::getSm2PublicKeyPath() const
{
    return ui->publicKeyEdit->text();
}

void KeyConfigDialog::setSm4KeyPath(const QString& path)
{
    ui->sm4KeyEdit->setText(path);
}

void KeyConfigDialog::setSm2PrivateKeyPath(const QString& path)
{
    ui->privateKeyEdit->setText(path);
}

void KeyConfigDialog::setSm2PublicKeyPath(const QString& path)
{
    ui->publicKeyEdit->setText(path);
}

void KeyConfigDialog::on_browseSm4Button_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    "选择SM4密钥文件",
                                                    QApplication::applicationDirPath(),
                                                    "密钥文件 (*.bin);;所有文件 (*.*)");

    if (!fileName.isEmpty()) {
        ui->sm4KeyEdit->setText(fileName);
    }
}

void KeyConfigDialog::on_browsePrivateKeyButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    "选择SM2私钥文件",
                                                    QApplication::applicationDirPath(),
                                                    "PEM文件 (*.pem);;所有文件 (*.*)");

    if (!fileName.isEmpty()) {
        ui->privateKeyEdit->setText(fileName);
    }
}

void KeyConfigDialog::on_browsePublicKeyButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    "选择SM2公钥文件",
                                                    QApplication::applicationDirPath(),
                                                    "PEM文件 (*.pem);;所有文件 (*.*)");

    if (!fileName.isEmpty()) {
        ui->publicKeyEdit->setText(fileName);
    }
}

void KeyConfigDialog::on_saveButton_clicked()
{
    // 验证文件是否存在（可选）
    QString sm4Path = ui->sm4KeyEdit->text();
    QString privatePath = ui->privateKeyEdit->text();
    QString publicPath = ui->publicKeyEdit->text();

    if (!sm4Path.isEmpty() && !QFileInfo::exists(sm4Path)) {
        QMessageBox::warning(this, "警告", "SM4密钥文件不存在！");
        return;
    }

    if (!privatePath.isEmpty() && !QFileInfo::exists(privatePath)) {
        QMessageBox::warning(this, "警告", "SM2私钥文件不存在！");
        return;
    }

    if (!publicPath.isEmpty() && !QFileInfo::exists(publicPath)) {
        QMessageBox::warning(this, "警告", "SM2公钥文件不存在！");
        return;
    }

    // 保存配置
    ConfigManager& config = ConfigManager::instance();
    config.setSm4KeyPath(sm4Path);
    config.setPrivateKeyPath(privatePath);
    config.setPublicKeyPath(publicPath);

    QMessageBox::information(this, "成功", "密钥配置已保存！");
    accept();
}

void KeyConfigDialog::on_cancelButton_clicked()
{
    reject();
}
