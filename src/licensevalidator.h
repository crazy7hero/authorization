#ifndef LICENSEVALIDATOR_H
#define LICENSEVALIDATOR_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>
#include <QRegularExpression>  

class LicenseValidator : public QObject
{
    Q_OBJECT

public:
    // 授权信息结构体（与 LicenseGenerator::LicenseInfo 保持一致）
    struct LicenseInfo {
        QString version;
        QDateTime issueDate;
        QDateTime expireDate;
        QString macAddress;
        QJsonObject extraData;
    };

    // 验证结果结构体
    struct ValidatedInfo {
        // 授权信息（验证通过后填充）
        QString version;
        QDateTime issueDate;
        QDateTime expireDate;
        QString macAddress;
        QJsonObject extraData;

        // 验证状态
        bool isValid = false;
        QString errorMessage;
        QString statusText;
    };

    explicit LicenseValidator(QObject *parent = nullptr);

    // 验证授权文件
    ValidatedInfo validateLicenseFile(const QString &licensePath, const QString &macAddress);

    QString getLastError() const { return lastError; }

private:
    // 授权文件解析结果
    struct LicenseFileData {
        QByteArray encryptedData;
        QByteArray signature;
        QByteArray publicKey;
        QByteArray combinedSm4Mac;
        QByteArray macAddress;
        QJsonObject licenseInfo;  // 明文显示信息（可选）
    };

    // 解析授权文件
    bool parseLicenseFile(const QByteArray &data, LicenseFileData &licenseData);

    // 解析授权数据
    LicenseInfo parseLicenseData(const QByteArray &data);

    QString lastError;
};

#endif // LICENSEVALIDATOR_H
