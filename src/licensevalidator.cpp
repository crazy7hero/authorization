#include "licensevalidator.h"
#include "gmsslcrypto.h"
#include "logmanager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <stdexcept>

LicenseValidator::LicenseValidator(QObject *parent)
    : QObject(parent)
{
}

LicenseValidator::ValidatedInfo LicenseValidator::validateLicenseFile(const QString &licensePath,
                                                                      const QString &macAddress)
{
    ValidatedInfo result;

    try {
        GmSSLCrypto &crypto = GmSSLCrypto::instance();
        LOG_INFO("VALIDATOR", QString("开始验证授权文件：%1").arg(licensePath));


        // 1. 读取授权文件
        QFile file(licensePath);
        if (!file.open(QIODevice::ReadOnly)) {
            result.errorMessage = "无法打开授权文件";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

        QByteArray fileData = file.readAll();
        file.close();

        if (fileData.isEmpty()) {
            result.errorMessage = "授权文件为空";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

        LOG_DEBUG("VALIDATOR", QString("授权文件大小：%1字节").arg(fileData.size()));

        // 2. 解析授权文件
        LicenseFileData licenseFileData;
        if (!parseLicenseFile(fileData, licenseFileData)) {
            result.errorMessage = "授权文件格式错误";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

#ifdef USE_MAC_ADDRESS
        // MAC 地址模式：验证 MAC 地址
        QString mac = licenseFileData.macAddress;
        QString normalizedLicenseMac = crypto.normalizeMacAddress(mac);
        QString normalizedInputMac = crypto.normalizeMacAddress(macAddress);

        LOG_INFO("VALIDATOR", QString("  用户输入的MAC地址：%1").arg(macAddress));
        LOG_INFO("VALIDATOR", QString("  解析授权文件中的MAC地址：%1").arg(mac));

        if (normalizedLicenseMac != normalizedInputMac) {
            result.errorMessage = "请检查MAC地址是否正确";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }
#else
        // 机器唯一 ID 模式：验证 64 位十六进制
        QString licenseId = licenseFileData.macAddress;
        QString normalizedLicenseId = licenseId.remove(QRegularExpression("[^0-9A-Fa-f]")).toUpper();
        QString normalizedInputId = QString(macAddress).remove(QRegularExpression("[^0-9A-Fa-f]")).toUpper();

        LOG_INFO("VALIDATOR", QString("  用户输入的机器ID：%1").arg(macAddress));
        LOG_INFO("VALIDATOR", QString("  解析授权文件中的机器ID：%1").arg(licenseId));

        // 检查长度是否为 64 位
        if (normalizedLicenseId.length() != 64 || normalizedInputId.length() != 64) {
            result.errorMessage = "机器唯一ID格式错误，应为64位十六进制 (SHA-256)";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

        // 检查是否匹配
        if (normalizedLicenseId != normalizedInputId) {
            result.errorMessage = "请检查机器唯一ID是否正确";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

#endif
        LOG_DEBUG("VALIDATOR", QString("解析成功：公钥=%1字节，签名=%2字节，加密数据=%3字节，合并数据=%4字节")
            .arg(licenseFileData.publicKey.size())
            .arg(licenseFileData.signature.size())
            .arg(licenseFileData.encryptedData.size())
            .arg(licenseFileData.combinedSm4Mac.size()));

        // 3. 从合并数据中提取 SM4 密钥

        QByteArray sm4Key = crypto.extractSm4FromCombined(licenseFileData.combinedSm4Mac, macAddress);
        if (sm4Key.isEmpty()) {
            result.errorMessage = "SM4 密钥提取失败，请检查 MAC 地址";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

        LOG_INFO("VALIDATOR", "SM4 密钥提取成功");

        // 4. 用 SM4 密钥解密授权数据
        QByteArray decryptedLicenseData;
        if (!crypto.sm4Decrypt(sm4Key, licenseFileData.encryptedData, decryptedLicenseData)) {
            result.errorMessage = "授权数据解密失败";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }

        LOG_DEBUG("VALIDATOR", QString("授权数据解密成功，大小：%1字节").arg(decryptedLicenseData.size()));

        // 5. 解析授权数据
        LicenseInfo licenseInfo = parseLicenseData(decryptedLicenseData);

        // 6. 验证 MAC 地址
#ifdef USE_MAC_ADDRESS
        // MAC 地址模式
        QString normalizedLicenseMac2 = crypto.normalizeMacAddress(licenseInfo.macAddress);
        if (normalizedLicenseMac2 != normalizedInputMac) {
            result.errorMessage = QString("MAC 地址不匹配（解密数据）\n授权 MAC: %1\n输入 MAC: %2")
                                      .arg(licenseInfo.macAddress)
                                      .arg(macAddress);
            //LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }
        //LOG_INFO("VALIDATOR", "MAC 地址验证通过（解密数据）");
#else
        // 机器唯一 ID 模式
        QString normalizedLicenseId2 = licenseInfo.macAddress.remove(QRegularExpression("[^0-9A-Fa-f]")).toUpper();
        if (normalizedLicenseId2 != normalizedInputId) {
            result.errorMessage = QString("机器唯一ID不匹配（解密数据）\n授权 ID: %1\n输入 ID: %2")
                                      .arg(licenseInfo.macAddress)
                                      .arg(macAddress);
            //LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }
        //LOG_INFO("VALIDATOR", "机器唯一ID验证通过（解密数据）");
#endif

        // 7. 计算 SM3 哈希（与生成时保持一致）
        QByteArray sm3Hash = crypto.sm3Hash(decryptedLicenseData);
        if (sm3Hash.isEmpty() || sm3Hash.size() != 32) {
            result.errorMessage = "SM3 哈希计算失败";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }
        LOG_DEBUG("VALIDATOR", "SM3 哈希计算成功");

        // 8. 使用哈希值进行 SM2 验签
        if (!crypto.sm2Verify(licenseFileData.publicKey, sm3Hash,
                              licenseFileData.signature, QByteArray())) {
            result.errorMessage = "数字签名验证失败";
            LOG_ERROR("VALIDATOR", result.errorMessage);
            return result;
        }
        LOG_INFO("VALIDATOR", "SM2 数字签名验证通过（基于哈希）");

        // 9. 验证有效期
        // 11. 验证有效期
        QDateTime now = QDateTime::currentDateTime();
        if (now > licenseInfo.expireDate) {
            result.errorMessage = QString("授权已过期\n过期时间: %1\n当前时间: %2")
                                      .arg(licenseInfo.expireDate.toString("yyyy-MM-dd HH:mm:ss"))
                                      .arg(now.toString("yyyy-MM-dd HH:mm:ss"));
            LOG_ERROR("VALIDATOR",result.errorMessage);
            return result;
        }

        // 检查是否在有效期内（从签发日期到过期日期）
        if (now < licenseInfo.issueDate) {
            result.errorMessage = QString("授权尚未生效\n生效时间: %1\n当前时间: %2")
                                      .arg(licenseInfo.issueDate.toString("yyyy-MM-dd HH:mm:ss"))
                                      .arg(now.toString("yyyy-MM-dd HH:mm:ss"));
            LOG_ERROR("VALIDATOR",result.errorMessage);
            return result;
        }

        // 计算有效期总天数
        int totalDays = licenseInfo.issueDate.daysTo(licenseInfo.expireDate);
        // 计算剩余天数
        int daysLeft = now.daysTo(licenseInfo.expireDate);

        LOG_DEBUG("VALIDATOR", "有效期验证通过");
        LOG_DEBUG( "签发日期:" , licenseInfo.issueDate.toString("yyyy-MM-dd HH:mm:ss"));
        LOG_DEBUG(  "过期日期:" , licenseInfo.expireDate.toString("yyyy-MM-dd HH:mm:ss"));
        LOG_DEBUG(  "有效期总天数:" , QString("%1天").arg(totalDays));
        LOG_DEBUG(  "剩余天数:" , QString("%1天").arg(daysLeft));

        // 12. 填充验证结果
        result.version = licenseInfo.version;
        result.issueDate = licenseInfo.issueDate;
        result.expireDate = licenseInfo.expireDate;
        result.macAddress = licenseInfo.macAddress;
        result.extraData = licenseInfo.extraData;
        result.isValid = true;
        result.statusText = QString("授权验证通过 (剩余 %1 天，有效期共 %2 天)")
                                .arg(daysLeft)
                                .arg(totalDays);

        LOG_DEBUG("VALIDATOR","========================================");
        LOG_DEBUG("VALIDATOR","授权文件验证成功!");
        LOG_DEBUG("VALIDATOR","========================================");

    } catch (const std::exception &e) {
        result.errorMessage = QString("验证过程中出错：%1").arg(e.what());
        LOG_CRITICAL("VALIDATOR", result.errorMessage);
    }

    return result;
}

bool LicenseValidator::parseLicenseFile(const QByteArray &data, LicenseFileData &licenseFileData)
{
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        LOG_ERROR("VALIDATOR", "授权文件 JSON 解析失败");
        return false;
    }

    QJsonObject obj = doc.object();

    // 验证格式
    QString format = obj["format"].toString();
    if (format != "SM2_LICENSE_V2" && format != "SM2_LICENSE_V1") {
        LOG_ERROR("VALIDATOR", QString("不支持的授权文件格式：%1").arg(format));
        return false;
    }

    // 提取各部分数据（Base64 解码）
    licenseFileData.publicKey = QByteArray::fromBase64(obj["public_key"].toString().toLatin1());
    licenseFileData.signature = QByteArray::fromBase64(obj["signature"].toString().toLatin1());
    licenseFileData.encryptedData = QByteArray::fromBase64(obj["encrypted_data"].toString().toLatin1());
    licenseFileData.combinedSm4Mac = QByteArray::fromBase64(obj["combined_sm4_mac"].toString().toLatin1());
    licenseFileData.macAddress = QByteArray::fromBase64(obj["macaddresses"].toString().toLatin1());
    // 获取明文显示信息（可选）
    if (obj.contains("license_info")) {
        licenseFileData.licenseInfo = obj["license_info"].toObject();
    }

    // 验证数据完整性
    if (licenseFileData.publicKey.isEmpty() ||
        licenseFileData.signature.isEmpty() ||
        licenseFileData.encryptedData.isEmpty() ||
        licenseFileData.combinedSm4Mac.isEmpty() ||
        licenseFileData.macAddress.isEmpty()) {
        LOG_ERROR("VALIDATOR", "授权文件数据不完整");
        LOG_ERROR("VALIDATOR", QString("  publicKey: %1").arg(licenseFileData.publicKey.isEmpty() ? "空" : "OK"));
        LOG_ERROR("VALIDATOR", QString("  signature: %1").arg(licenseFileData.signature.isEmpty() ? "空" : "OK"));
        LOG_ERROR("VALIDATOR", QString("  encryptedData: %1").arg(licenseFileData.encryptedData.isEmpty() ? "空" : "OK"));
        LOG_ERROR("VALIDATOR", QString("  combinedSm4Mac: %1").arg(licenseFileData.combinedSm4Mac.isEmpty() ? "空" : "OK"));
        LOG_ERROR("VALIDATOR", QString("  macAddress: %1").arg(licenseFileData.macAddress.isEmpty() ? "空" : "OK"));
        LOG_ERROR("VALIDATOR", "授权文件数据不完整");
        return false;
    }

    return true;
}

LicenseValidator::LicenseInfo LicenseValidator::parseLicenseData(const QByteArray &data)
{
    LicenseInfo info;

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        throw std::runtime_error("授权数据 JSON 解析失败");
    }

    QJsonObject obj = doc.object();

    info.version = obj["version"].toString();
    info.issueDate = QDateTime::fromString(obj["issue_date"].toString(), Qt::ISODate);
    info.expireDate = QDateTime::fromString(obj["expire_date"].toString(), Qt::ISODate);
    info.macAddress = obj["mac_address"].toString();

    // 额外数据
    if (obj.contains("extra_data")) {
        info.extraData = obj["extra_data"].toObject();
    }

    return info;
}
