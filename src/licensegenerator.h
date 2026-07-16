#ifndef LICENSEGENERATOR_H
#define LICENSEGENERATOR_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>

class LicenseGenerator : public QObject
{
    Q_OBJECT

public:
    // 授权信息结构体（生成端和验证端共用）
    struct LicenseInfo {
        QString version;
        QDateTime issueDate;
        QDateTime expireDate;
        QString macAddress;
        QJsonObject extraData;
    };

    explicit LicenseGenerator(QObject *parent = nullptr);

    // 生成授权文件（原始方式）
    bool generateLicenseFile(const LicenseInfo &info,
                             const QString &privateKeyPath,
                             const QString &password,
                             const QByteArray &sm4Key,
                             const QString &outputPath);

    // 生成授权文件（SM3 哈希+SM2 签名+SM4 加密方式）
    bool generateLicenseWithHashAndSign(const LicenseInfo &info,
                                        const QString &privateKeyPath,
                                        const QString &password,
                                        const QByteArray &sm4Key,
                                        const QString &outputPath);

    // 生成密钥对
    bool generateKeys(const QString &password, const QString &keyDir);

    QString getLastError() const { return lastError; }

private:
    // 构建授权数据（JSON 格式）
    QByteArray buildLicenseData(const LicenseInfo &info);

    // 构建授权文件 V1（原始方式）
    QByteArray buildLicenseFile(const QByteArray &licenseData,
                                const QByteArray &signature,
                                const QByteArray &sm4Key,
                                const QByteArray &publicKey,
                                const QString &macAddress);

    // 构建授权文件 V2（哈希 + 签名 + 加密方式）
    QByteArray buildLicenseFileV2(const LicenseInfo &info,
                                  const QByteArray &signature,
                                  const QByteArray &publicKey,
                                  const QByteArray &encryptedData,
                                  const QByteArray &sm4Key);

    QString lastError;
};

#endif // LICENSEGENERATOR_H
