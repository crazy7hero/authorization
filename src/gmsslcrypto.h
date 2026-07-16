#ifndef GMSSCRYPTO_H
#define GMSSCRYPTO_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QDateTime>

extern "C"{
#include "gmssl/sm2.h"
#include "gmssl/sm3.h"
#include "gmssl/sm4.h"
#include "gmssl/rand.h"
#include "gmssl/mem.h"
}

#define SM2_SIGNI_KEY_PASSWORD "123456781234578"

class GmSSLCrypto : public QObject
{
    Q_OBJECT

public:
    // 单例模式
    static GmSSLCrypto& instance();

    // SM2密钥操作
    bool generatem_sm2KeyPair();
    bool saveSm2PrivateKeyPem(const QString &filePath, const QString &password);
    bool saveSm2PublicKeyPem(const QString &filePath);
    bool loadSm2PrivateKeyPem(const QString &filePath, const QString &password);
    bool loadSm2PublicKeyPem(const QString &filePath);

    // SM4密钥操作
    QByteArray generateSm4Key();
    bool saveSm4Key(const QString &filePath, const QByteArray &sm4Key);
    bool loadSm4Key(const QString &filePath, QByteArray &sm4Key);

    // SM4与MAC地址的算法
    QByteArray combineSm4WithMac(const QByteArray &sm4Key, const QString &macAddress);
    QByteArray extractSm4FromCombined(const QByteArray &combinedData, const QString &macAddress);

    // SM2签名/验签
    bool sm2Sign(const QByteArray &data, QByteArray &signature);
    bool sm2Verify(const QByteArray &publicKey, const QByteArray &data,
                   const QByteArray &signature, const QByteArray &id);
    bool sm2SignWithKey(const QByteArray &privateKey, const QByteArray &data, QByteArray &signature, const QByteArray &id);

    // SM4加密/解密
    bool sm4Encrypt(const QByteArray &key, const QByteArray &data, QByteArray &encrypted);
    bool sm4Decrypt(const QByteArray &key, const QByteArray &encrypted, QByteArray &decrypted);

    // SM3哈希
    QByteArray sm3Hash(const QByteArray &data);

    // 辅助函数
    QByteArray getSm2PublicKey() const;
    QByteArray getSm2PrivateKey() const;

    // 生成随机数
    static QByteArray generateRandomBytes(int size);

    // 工具函数
    QString normalizeMacAddress(const QString &mac);

private:
    GmSSLCrypto();
    ~GmSSLCrypto();

    // 禁用拷贝
    GmSSLCrypto(const GmSSLCrypto&) = delete;
    GmSSLCrypto& operator=(const GmSSLCrypto&) = delete;

    SM2_KEY m_sm2Key;           // 当前SM2密钥对
    QByteArray m_currentSm4Key; // 当前SM4密钥

    // PKCS7填充
    QByteArray pkcs7Padding(const QByteArray &data, int blockSize = 16);
    QByteArray pkcs7Unpadding(const QByteArray &data);

};

#endif // GMSSCRYPTO_H
