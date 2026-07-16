#include "licensegenerator.h"
#include "gmsslcrypto.h"
#include "configmanager.h"
#include "logmanager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QDir>
#include <stdexcept>

LicenseGenerator::LicenseGenerator(QObject *parent)
    : QObject(parent)
{
}

bool LicenseGenerator::generateLicenseFile(const LicenseInfo &info,
                                           const QString &privateKeyPath,
                                           const QString &password,
                                           const QByteArray &sm4Key,
                                           const QString &outputPath)
{
    try {
        LOG_INFO("LICENSE", QString("开始生成授权文件：%1").arg(outputPath));
        LOG_INFO("LICENSE", QString("MAC 地址：%1").arg(info.macAddress));

        // 1. 构建授权数据
        QByteArray licenseData = buildLicenseData(info);
        LOG_DEBUG("LICENSE", QString("授权数据构建完成，大小：%1字节").arg(licenseData.size()));

        // 2. 加载私钥
        GmSSLCrypto &crypto = GmSSLCrypto::instance();
        if (!crypto.loadSm2PrivateKeyPem(privateKeyPath, password)) {
            lastError = "私钥加载失败";
            LOG_ERROR("LICENSE", lastError);
            return false;
        }
        LOG_INFO("LICENSE", "SM2 私钥加载成功");

        // 3. SM2 签名
        QByteArray signature;
        if (!crypto.sm2Sign(licenseData, signature)) {
            lastError = "授权数据签名失败";
            LOG_ERROR("LICENSE", lastError);
            return false;
        }
        LOG_INFO("LICENSE", "SM2 签名成功");

        // 4. 获取公钥
        QByteArray publicKey = crypto.getSm2PublicKey();
        if (publicKey.isEmpty()) {
            lastError = "公钥导出失败";
            LOG_ERROR("LICENSE", lastError);
            return false;
        }

        // 5. 构建最终授权文件
        QByteArray licenseFile = buildLicenseFile(licenseData, signature, sm4Key, publicKey, info.macAddress);
        LOG_DEBUG("LICENSE", QString("授权文件构建完成，大小：%1字节").arg(licenseFile.size()));

        // 6. 保存授权文件
        QFile file(outputPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            lastError = "无法打开输出文件";
            LOG_ERROR("LICENSE", QString("%1: %2").arg(lastError).arg(outputPath));
            return false;
        }

        qint64 written = file.write(licenseFile);
        file.close();

        if (written != licenseFile.size()) {
            lastError = "文件写入失败";
            LOG_ERROR("LICENSE", lastError);
            return false;
        }

        LOG_INFO("LICENSE", QString("授权文件生成成功：%1").arg(outputPath));
        LOG_INFO("LICENSE", QString("SM4 密钥大小：%1字节").arg(sm4Key.size()));
        LOG_INFO("LICENSE", QString("签名大小：%1字节").arg(signature.size()));
        LOG_INFO("LICENSE", QString("公钥大小：%1字节").arg(publicKey.size()));

        return true;

    } catch (const std::exception &e) {
        lastError = QString("异常：%1").arg(e.what());
        LOG_CRITICAL("LICENSE", lastError);
        return false;
    }
}

bool LicenseGenerator::generateLicenseWithHashAndSign(const LicenseInfo &info,
                                                      const QString &privateKeyPath,
                                                      const QString &password,
                                                      const QByteArray &sm4Key,
                                                      const QString &outputPath)
{
    try {
        LOG_INFO("LICENSE_GEN", "开始生成授权文件（SM3 哈希+SM2 签名+SM4 加密）");

        GmSSLCrypto &crypto = GmSSLCrypto::instance();

        // 1. 构建授权数据
        QByteArray licenseData = buildLicenseData(info);
        LOG_DEBUG("LICENSE_GEN", QString("授权数据构建完成，大小：%1字节").arg(licenseData.size()));

        // 2. 计算 SM3 哈希
        QByteArray sm3Hash = crypto.sm3Hash(licenseData);
        if (sm3Hash.isEmpty() || sm3Hash.size() != 32) {
            lastError = "SM3 哈希计算失败";
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }
        LOG_DEBUG("LICENSE_GEN", "SM3 哈希计算成功");

        // 3. 加载私钥
        if (!crypto.loadSm2PrivateKeyPem(privateKeyPath, password)) {
            lastError = "私钥加载失败";
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }
        LOG_DEBUG("LICENSE_GEN", "SM2 私钥加载成功");

        // 4. 对哈希值进行 SM2 签名
        QByteArray signature;
        if (!crypto.sm2Sign(sm3Hash, signature)) {
            lastError = "SM2 签名失败";
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }
        LOG_DEBUG("LICENSE_GEN", QString("SM2 签名成功，签名大小：%1字节").arg(signature.size()));

        // 5. 获取公钥
        QByteArray publicKey = crypto.getSm2PublicKey();
        if (publicKey.isEmpty()) {
            lastError = "公钥导出失败";
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }
        LOG_DEBUG("LICENSE_GEN", QString("公钥导出成功，大小：%1字节").arg(publicKey.size()));

        // 6. 用 SM4 密钥加密授权数据
        QByteArray encryptedData;
        if (!crypto.sm4Encrypt(sm4Key, licenseData, encryptedData)) {
            lastError = "SM4 加密失败";
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }
        LOG_DEBUG("LICENSE_GEN", QString("SM4 加密成功，加密后大小：%1字节").arg(encryptedData.size()));

        // 7. 构建授权文件 V2
        QByteArray licenseFile = buildLicenseFileV2(info, signature, publicKey, encryptedData, sm4Key);

        // 8. 保存文件
        QFile file(outputPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            lastError = QString("无法打开文件：%1").arg(outputPath);
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }

        qint64 written = file.write(licenseFile);
        file.close();

        if (written != licenseFile.size()) {
            lastError = "文件写入不完整";
            LOG_ERROR("LICENSE_GEN", lastError);
            return false;
        }

        LOG_INFO("LICENSE_GEN", QString("授权文件生成成功：%1").arg(outputPath));
        return true;

    } catch (const std::exception &e) {
        lastError = QString("异常：%1").arg(e.what());
        LOG_CRITICAL("LICENSE_GEN", lastError);
        return false;
    }
}

QByteArray LicenseGenerator::buildLicenseData(const LicenseInfo &info)
{
    QJsonObject json;

    json["version"] = info.version;
    json["issue_date"] = info.issueDate.toString(Qt::ISODate);
    json["expire_date"] = info.expireDate.toString(Qt::ISODate);
    json["mac_address"] = info.macAddress.toUpper();

    // 额外数据
    if (!info.extraData.isEmpty()) {
        json["extra_data"] = info.extraData;
    }

    // 序列化
    QJsonDocument doc(json);
    return doc.toJson(QJsonDocument::Compact);
}

QByteArray LicenseGenerator::buildLicenseFile(const QByteArray &licenseData,
                                              const QByteArray &signature,
                                              const QByteArray &sm4Key,
                                              const QByteArray &publicKey,
                                              const QString &macAddress)
{
    GmSSLCrypto &crypto = GmSSLCrypto::instance();

    // 1. 用 SM4 密钥加密授权数据
    QByteArray encryptedLicenseData;
    if (!crypto.sm4Encrypt(sm4Key, licenseData, encryptedLicenseData)) {
        throw std::runtime_error("授权数据加密失败");
    }

    // 2. 将 SM4 密钥与 MAC 地址合并
    QByteArray combinedSm4Mac = crypto.combineSm4WithMac(sm4Key, macAddress);
    if (combinedSm4Mac.isEmpty()) {
        throw std::runtime_error("SM4 密钥与 MAC 地址合并失败");
    }

    // 3. 构建 JSON 格式的授权文件
    QJsonObject licenseFile;

    // 文件头标识
    licenseFile["format"] = "SM2_LICENSE_V1";
    licenseFile["version"] = "1.0";
    licenseFile["create_time"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    licenseFile["algorithm"] = "SM2-SM3-SM4";

    // 存储各部分数据（Base64 编码）
    licenseFile["public_key"] = QString(publicKey.toBase64());
    licenseFile["signature"] = QString(signature.toBase64());
    licenseFile["encrypted_data"] = QString(encryptedLicenseData.toBase64());
    licenseFile["combined_sm4_mac"] = QString(combinedSm4Mac.toBase64());

    // 明文 MAC 地址列表（Base64 编码）
    QByteArray utf8MacAddress = macAddress.toUtf8();
    QString base64MacAddress = utf8MacAddress.toBase64();
    licenseFile["mac_addresses"] = base64MacAddress;

    // 序列化为 JSON
    QJsonDocument fileDoc(licenseFile);
    return fileDoc.toJson(QJsonDocument::Indented);
}

QByteArray LicenseGenerator::buildLicenseFileV2(const LicenseInfo &info,
                                                const QByteArray &signature,
                                                const QByteArray &publicKey,
                                                const QByteArray &encryptedData,
                                                const QByteArray &sm4Key)
{
    QJsonObject licenseFile;

    // 文件头信息
    licenseFile["format"] = "SM2_LICENSE_V2";
    licenseFile["create_time"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 安全数据（Base64 编码）
    licenseFile["public_key"] = QString(publicKey.toBase64());
    licenseFile["signature"] = QString(signature.toBase64());
    licenseFile["encrypted_data"] = QString(encryptedData.toBase64());

    // SM4 密钥与 MAC 地址合并的数据（用于绑定硬件）
    GmSSLCrypto &crypto = GmSSLCrypto::instance();
    QByteArray combinedSm4Mac = crypto.combineSm4WithMac(sm4Key, info.macAddress);
    if (!combinedSm4Mac.isEmpty()) {
        licenseFile["combined_sm4_mac"] = QString(combinedSm4Mac.toBase64());
    }

    // 明文 MAC 地址列表（Base64 编码）
    QByteArray utf8MacAddress = info.macAddress.toUtf8();
    QString base64MacAddress = utf8MacAddress.toBase64();
    licenseFile["macaddresses"] = base64MacAddress;

    // 序列化为 JSON
    QJsonDocument fileDoc(licenseFile);
    return fileDoc.toJson(QJsonDocument::Indented);
}

bool LicenseGenerator::generateKeys(const QString &password, const QString &keyDir)
{
    try {
        LOG_INFO("KEYGEN", QString("开始生成密钥到目录：%1").arg(keyDir));

        GmSSLCrypto &crypto = GmSSLCrypto::instance();

        // 生成 SM2 密钥对
        if (!crypto.generatem_sm2KeyPair()) {
            lastError = "SM2 密钥对生成失败";
            LOG_ERROR("KEYGEN", lastError);
            return false;
        }

        // 生成 SM4 密钥
        QByteArray sm4Key = crypto.generateSm4Key();
        if (sm4Key.isEmpty()) {
            lastError = "SM4 密钥生成失败";
            LOG_ERROR("KEYGEN", lastError);
            return false;
        }

        // 确保目录存在
        QDir dir(keyDir);
        if (!dir.exists()) {
            if (!dir.mkpath(".")) {
                lastError = "无法创建密钥目录";
                LOG_ERROR("KEYGEN", lastError);
                return false;
            }
            LOG_DEBUG("KEYGEN", QString("创建密钥目录：%1").arg(keyDir));
        }

        // 保存私钥（PEM 格式）
        QString privateKeyPath = dir.filePath("sm2_private.pem");
        if (!crypto.saveSm2PrivateKeyPem(privateKeyPath, password)) {
            lastError = "私钥保存失败";
            LOG_ERROR("KEYGEN", lastError);
            return false;
        }

        // 保存公钥（PEM 格式）
        QString publicKeyPath = dir.filePath("sm2_public.pem");
        if (!crypto.saveSm2PublicKeyPem(publicKeyPath)) {
            lastError = "公钥保存失败";
            LOG_ERROR("KEYGEN", lastError);
            return false;
        }

        // 保存 SM4 密钥（二进制格式）
        QString sm4KeyPath = dir.filePath("sm4_key.bin");
        if (!crypto.saveSm4Key(sm4KeyPath, sm4Key)) {
            lastError = "SM4 密钥保存失败";
            LOG_ERROR("KEYGEN", lastError);
            return false;
        }

        LOG_INFO("KEYGEN", "密钥生成完成");
        LOG_INFO("KEYGEN", QString("私钥文件 (PEM): %1").arg(privateKeyPath));
        LOG_INFO("KEYGEN", QString("公钥文件 (PEM): %1").arg(publicKeyPath));
        LOG_INFO("KEYGEN", QString("SM4 密钥文件 (bin): %1").arg(sm4KeyPath));

        return true;

    } catch (const std::exception &e) {
        lastError = QString("异常：%1").arg(e.what());
        LOG_CRITICAL("KEYGEN", lastError);
        return false;
    }
}
