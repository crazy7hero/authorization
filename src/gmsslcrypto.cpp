#include "gmsslcrypto.h"
#include "logmanager.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDebug>
#include <QByteArray>
#include <stdexcept>
#include <QRegularExpression>

GmSSLCrypto::GmSSLCrypto()
{
    // 初始化密钥
    memset(&m_sm2Key, 0, sizeof(SM2_KEY));
}

GmSSLCrypto::~GmSSLCrypto()
{
    // 清理内存
    gmssl_secure_clear(&m_sm2Key, sizeof(m_sm2Key));
    gmssl_secure_clear(m_currentSm4Key.data(), m_currentSm4Key.size());
}

GmSSLCrypto& GmSSLCrypto::instance()
{
    static GmSSLCrypto instance;
    return instance;
}

bool GmSSLCrypto::generatem_sm2KeyPair()
{
    LOG_DEBUG("GMSSCRYPTO", "开始生成SM2密钥对");

    // 清理旧密钥
    memset(&m_sm2Key, 0, sizeof(m_sm2Key));

    // 生成SM2密钥对
    if (sm2_key_generate(&m_sm2Key) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2密钥对生成失败");
        return false;
    }

    LOG_INFO("GMSSCRYPTO", "SM2密钥对生成成功");
    return true;
}

bool GmSSLCrypto::saveSm2PrivateKeyPem(const QString &filePath, const QString &password)
{
    LOG_DEBUG("GMSSCRYPTO", QString("保存SM2私钥PEM到: %1").arg(filePath));
#ifdef _WIN32
    FILE *fp = _wfopen((const wchar_t*)filePath.utf16(), L"wb");
#else
    FILE *fp = fopen(filePath.toUtf8().constData(), "wb");
#endif

 if (!fp) {
        LOG_ERROR("GMSSCRYPTO", QString("无法打开私钥文件: %1").arg(filePath));
        return false;
    }

    int result;
    if (!password.isEmpty()) {
        // 加密保存私钥
        result = sm2_private_key_info_encrypt_to_pem(&m_sm2Key,
                                                     password.toUtf8().constData(),
                                                     fp);
    } else {
        // 明文保存私钥
        result = sm2_private_key_to_pem(&m_sm2Key, fp);
    }

    fclose(fp);

    bool success = result == 1;
    if (success) {
        LOG_INFO("GMSSCRYPTO", QString("SM2私钥保存成功: %1").arg(filePath));
    } else {
        LOG_ERROR("GMSSCRYPTO", "SM2私钥保存失败");
    }

    return success;
}

bool GmSSLCrypto::saveSm2PublicKeyPem(const QString &filePath)
{
    LOG_DEBUG("GMSSCRYPTO", QString("保存SM2公钥PEM到: %1").arg(filePath));
#ifdef _WIN32
    FILE *fp = _wfopen((const wchar_t*)filePath.utf16(), L"wb");
#else
    FILE *fp = fopen(filePath.toUtf8().constData(), "wb");
#endif
    if (!fp) {
        LOG_ERROR("GMSSCRYPTO", QString("无法打开公钥文件: %1").arg(filePath));
        return false;
    }

    int result = sm2_public_key_info_to_pem(&m_sm2Key, fp);
    fclose(fp);

    bool success = result == 1;
    if (success) {
        LOG_INFO("GMSSCRYPTO", QString("SM2公钥保存成功: %1").arg(filePath));
    } else {
        LOG_ERROR("GMSSCRYPTO", "SM2公钥保存失败");
    }

    return success;
}

bool GmSSLCrypto::loadSm2PrivateKeyPem(const QString &filePath, const QString &password)
{
    LOG_DEBUG("GMSSCRYPTO", QString("从PEM文件加载SM2私钥: %1").arg(filePath));

#ifdef _WIN32
    FILE *fp = _wfopen((const wchar_t*)filePath.utf16(), L"rb");
#else
    FILE *fp = fopen(filePath.toUtf8().constData(), "rb");
#endif
    if (!fp) {
        LOG_ERROR("GMSSCRYPTO", QString("无法打开私钥文件: %1").arg(filePath));
        return false;
    }

    // 清理旧密钥
    memset(&m_sm2Key, 0, sizeof(SM2_KEY));

    int result;
    if (!password.isEmpty()) {
        // 解密加载私钥
        result = sm2_private_key_info_decrypt_from_pem(&m_sm2Key,
                                                       password.toUtf8().constData(),
                                                       fp);
    } else {
        // 明文加载私钥
        result = sm2_private_key_from_pem(&m_sm2Key, fp);
    }

    fclose(fp);

    bool success = result == 1;
    if (success) {
        LOG_INFO("GMSSCRYPTO", "SM2私钥加载成功");
    } else {
        LOG_ERROR("GMSSCRYPTO", "SM2私钥加载失败");
    }

    return success;
}

bool GmSSLCrypto::loadSm2PublicKeyPem(const QString &filePath)
{
    LOG_DEBUG("GMSSCRYPTO", QString("从PEM文件加载SM2公钥: %1").arg(filePath));
    bool success ;
#ifdef _WIN32
    FILE *fp = _wfopen((const wchar_t*)filePath.utf16(), L"rb");
#else
    FILE *fp = fopen(filePath.toUtf8().constData(), "rb");
#endif
    if (!fp) {
        LOG_ERROR("GMSSCRYPTO", QString("无法打开公钥文件: %1").arg(filePath));
        return false;
    }

    // 清理旧密钥
    memset(&m_sm2Key, 0, sizeof(SM2_KEY));

    int result = sm2_public_key_info_from_pem(&m_sm2Key, fp);
    fclose(fp);


    if (result == 1) {
        LOG_INFO("GMSSCRYPTO", "SM2公钥加载成功");
        success = 1;
    } else {
        LOG_ERROR("GMSSCRYPTO", "SM2公钥加载失败");
        success = 0;
    }

    return success;
}

QByteArray GmSSLCrypto::generateSm4Key()
{
    LOG_DEBUG("GMSSCRYPTO", "开始生成SM4密钥");

    // 使用GmSSL的随机数生成器
    QByteArray key(16, 0);
    uint8_t *buf = (uint8_t*)key.data();

    if (rand_bytes(buf, 16) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4密钥生成失败");
        return QByteArray();
    }

    m_currentSm4Key = key;
    LOG_INFO("GMSSCRYPTO", "SM4密钥生成成功");
    return key;
}

QByteArray GmSSLCrypto::generateRandomBytes(int size)
{
    QByteArray bytes(size, 0);
    uint8_t *buf = (uint8_t*)bytes.data();

    if (rand_bytes(buf, size) != 1) {
        LOG_ERROR("GMSSCRYPTO", QString("随机数生成失败，大小: %1").arg(size));
        return QByteArray();
    }

    return bytes;
}


bool GmSSLCrypto::saveSm4Key(const QString &filePath, const QByteArray &sm4Key)
{
    LOG_DEBUG("GMSSCRYPTO", QString("保存SM4密钥到: %1").arg(filePath));

    // 验证SM4密钥长度
    if (sm4Key.size() != 16) {
        LOG_ERROR("GMSSCRYPTO", QString("SM4密钥必须是16字节，实际大小: %1 字节").arg(sm4Key.size()));
        return false;
    }

    // 创建目录（如果不存在）
    QFileInfo fileInfo(filePath);
    QDir dir = fileInfo.absoluteDir();
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            LOG_ERROR("GMSSCRYPTO", QString("无法创建目录: %1").arg(dir.absolutePath()));
            return false;
        }
        LOG_DEBUG("GMSSCRYPTO", QString("目录已创建: %1").arg(dir.absolutePath()));
    }

    // 将16进制转换为Base64
    QString hexString = sm4Key.toHex();
    QByteArray base64Data = hexString.toUtf8().toBase64();

    LOG_DEBUG("GMSSCRYPTO", QString("原始16进制: %1").arg(hexString));
    LOG_DEBUG("GMSSCRYPTO", QString("Base64编码后: %1").arg(QString(base64Data)));

    // 写入文件
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        LOG_ERROR("GMSSCRYPTO", QString("无法打开SM4密钥文件: %1, 错误: %2").arg(filePath).arg(file.errorString()));
        return false;
    }

    QTextStream out(&file);
    out.setCodec("UTF-8");
    out << base64Data;
    file.close();

    // 验证文件是否成功写入
    if (file.error() != QFile::NoError) {
        LOG_ERROR("GMSSCRYPTO", QString("写入文件时发生错误: %1").arg(file.errorString()));
        return false;
    }

    // 检查文件大小
    qint64 fileSize = fileInfo.size();
    LOG_DEBUG("GMSSCRYPTO", QString("文件大小: %1 字节").arg(fileSize));

    if (fileSize > 0) {
        LOG_INFO("GMSSCRYPTO", QString("SM4密钥成功保存到: %1").arg(filePath));
        LOG_INFO("GMSSCRYPTO", QString("保存格式: 16进制 -> Base64"));
        return true;
    } else {
        LOG_ERROR("GMSSCRYPTO", "SM4密钥保存失败，文件为空");
        return false;
    }
}

bool GmSSLCrypto::loadSm4Key(const QString &filePath, QByteArray &sm4Key)
{
    LOG_DEBUG("GMSSCRYPTO", QString("从文件加载SM4密钥: %1").arg(filePath));

    QFile file(filePath);
    if (!file.exists()) {
        LOG_ERROR("GMSSCRYPTO", QString("SM4密钥文件不存在: %1").arg(filePath));
        return false;
    }

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        LOG_ERROR("GMSSCRYPTO", QString("无法打开SM4密钥文件: %1, 错误: %2").arg(filePath).arg(file.errorString()));
        return false;
    }

    QTextStream in(&file);
    in.setCodec("UTF-8");
    QString base64Data = in.readAll();
    file.close();

    LOG_DEBUG("GMSSCRYPTO", QString("读取的Base64数据: %1").arg(base64Data));

    // Base64解码
    QByteArray hexData = QByteArray::fromBase64(base64Data.toUtf8());
    QString hexString = QString::fromUtf8(hexData);

    LOG_DEBUG("GMSSCRYPTO", QString("Base64解码后: %1").arg(hexString));

    // 16进制转换为字节数组
   sm4Key = QByteArray::fromHex(hexString.toUtf8());

    if (sm4Key.size() != 16) {
        LOG_ERROR("GMSSCRYPTO", QString("加载的SM4密钥无效，大小应为16字节，实际: %1 字节").arg(sm4Key.size()));
        return false;
    }

    LOG_INFO("GMSSCRYPTO", "SM4密钥加载成功");
    return true;
}

QByteArray GmSSLCrypto::combineSm4WithMac(const QByteArray &sm4Key, const QString &deviceIdentifier)
{
    LOG_DEBUG("GMSSCRYPTO", "开始合并SM4密钥和设备标识符");

    if (sm4Key.size() != 16) {
        LOG_ERROR("GMSSCRYPTO", "SM4密钥必须是16字节");
        return QByteArray();
    }

    if (deviceIdentifier.isEmpty()) {
        LOG_ERROR("GMSSCRYPTO", "设备标识符为空");
        return QByteArray();
    }

    QByteArray deviceBytes;

#ifdef USE_MAC_ADDRESS
    // ===== MAC 地址模式 =====
    QString normalizedMac = normalizeMacAddress(deviceIdentifier);
    if (normalizedMac.isEmpty()) {
        LOG_ERROR("GMSSCRYPTO", "MAC地址格式无效");
        return QByteArray();
    }
    deviceBytes = QByteArray::fromHex(normalizedMac.toLatin1());

    if (deviceBytes.size() != 6) {
        LOG_ERROR("GMSSCRYPTO", "MAC地址字节数不正确");
        return QByteArray();
    }
    LOG_DEBUG("GMSSCRYPTO", QString("MAC地址: %1").arg(normalizedMac));

#else
    // ===== 机器唯一 ID 模式 (SHA-256) =====
    // 移除所有非十六进制字符
    QString normalizedId = deviceIdentifier;
    normalizedId.remove(QRegularExpression("[^0-9A-Fa-f]")).toUpper();

    // 检查是否为 64 位十六进制 (SHA-256)
    if (normalizedId.length() != 64) {
        LOG_ERROR("GMSSCRYPTO", QString("机器唯一ID格式无效，长度应为64，实际为%1").arg(normalizedId.length()));
        return QByteArray();
    }

    deviceBytes = QByteArray::fromHex(normalizedId.toLatin1());
    if (deviceBytes.size() != 32) {  // SHA-256 是 32 字节
        LOG_ERROR("GMSSCRYPTO", "机器唯一ID字节数不正确");
        return QByteArray();
    }
    LOG_DEBUG("GMSSCRYPTO", QString("机器唯一ID: %1").arg(normalizedId.left(16) + "..."));
#endif

    // ===== 合并算法 =====
    QByteArray combined = sm4Key;

#ifdef USE_MAC_ADDRESS
    // MAC 地址模式：将 MAC 地址扩展到 16 字节进行异或
    for (int i = 0; i < 16; i++) {
        combined[i] = combined[i] ^ deviceBytes[i % 6];
    }
#else
    // 机器唯一 ID 模式：将 32 字节的 SHA-256 压缩到 16 字节进行异或
    // 方法：将前16字节和后16字节异或
    for (int i = 0; i < 16; i++) {
        combined[i] = combined[i] ^ deviceBytes[i] ^ deviceBytes[i + 16];
    }
#endif

    // 添加混淆因子（使合并结果更随机）
    for (int i = 0; i < 16; i++) {
        combined[i] = combined[i] ^ (i + 1);
    }

    LOG_DEBUG("GMSSCRYPTO", "SM4密钥和设备标识符合并完成");
    return combined;
}

QByteArray GmSSLCrypto::extractSm4FromCombined(const QByteArray &combined, const QString &deviceIdentifier)
{
    LOG_DEBUG("GMSSCRYPTO", "开始从合并数据中提取SM4密钥");

    if (combined.size() != 16) {
        LOG_ERROR("GMSSCRYPTO", "合并数据必须为16字节");
        return QByteArray();
    }

    if (deviceIdentifier.isEmpty()) {
        LOG_ERROR("GMSSCRYPTO", "设备标识符为空");
        return QByteArray();
    }

    QByteArray deviceBytes;

#ifdef USE_MAC_ADDRESS
    // ===== MAC 地址模式 =====
    QString normalizedMac = normalizeMacAddress(deviceIdentifier);
    if (normalizedMac.isEmpty()) {
        LOG_ERROR("GMSSCRYPTO", "MAC地址格式无效");
        return QByteArray();
    }
    deviceBytes = QByteArray::fromHex(normalizedMac.toLatin1());

    if (deviceBytes.size() != 6) {
        LOG_ERROR("GMSSCRYPTO", "MAC地址字节数不正确");
        return QByteArray();
    }
    LOG_DEBUG("GMSSCRYPTO", QString("MAC地址: %1").arg(normalizedMac));

#else
    // ===== 机器唯一 ID 模式 (SHA-256) =====
    QString normalizedId = deviceIdentifier;
    normalizedId.remove(QRegularExpression("[^0-9A-Fa-f]")).toUpper();

    if (normalizedId.length() != 64) {
        LOG_ERROR("GMSSCRYPTO", QString("机器唯一ID格式无效，长度应为64，实际为%1").arg(normalizedId.length()));
        return QByteArray();
    }

    deviceBytes = QByteArray::fromHex(normalizedId.toLatin1());
    if (deviceBytes.size() != 32) {
        LOG_ERROR("GMSSCRYPTO", "机器唯一ID字节数不正确");
        return QByteArray();
    }
    LOG_DEBUG("GMSSCRYPTO", QString("机器唯一ID: %1").arg(normalizedId.left(16) + "..."));
#endif

    // ===== 提取 SM4 密钥（逆向操作） =====
    QByteArray sm4Key = combined;

    // 先移除混淆因子
    for (int i = 0; i < 16; i++) {
        sm4Key[i] = sm4Key[i] ^ (i + 1);
    }

#ifdef USE_MAC_ADDRESS
    // MAC 地址模式
    for (int i = 0; i < 16; i++) {
        sm4Key[i] = sm4Key[i] ^ deviceBytes[i % 6];
    }
#else
    // 机器唯一 ID 模式
    for (int i = 0; i < 16; i++) {
        sm4Key[i] = sm4Key[i] ^ deviceBytes[i] ^ deviceBytes[i + 16];
    }
#endif

    LOG_DEBUG("GMSSCRYPTO", "SM4密钥提取完成");
    return sm4Key;
}

QString GmSSLCrypto::normalizeMacAddress(const QString &mac)
{
    // 移除所有非十六进制字符
    QString normalized = mac;
    normalized.remove(QRegularExpression("[^0-9A-Fa-f]")).toUpper();

    // 检查长度（应该是12个字符）
    if (normalized.length() != 12) {
        return QString();
    }

    return normalized.toUpper();
}

bool GmSSLCrypto::sm2Sign(const QByteArray &data, QByteArray &signature)
{
    LOG_DEBUG("GMSSCRYPTO", "开始SM2签名");

    // 使用默认ID
    const char *id = SM2_DEFAULT_ID;

    // 初始化签名上下文
    SM2_SIGN_CTX sign_ctx;
    if (sm2_sign_init(&sign_ctx, &m_sm2Key, id, strlen(id)) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2签名初始化失败");
        return false;
    }

    // 更新数据
    if (sm2_sign_update(&sign_ctx,
                        (const uint8_t*)data.constData(),
                        data.size()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2签名更新失败");
        gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
        return false;
    }

    // 完成签名
    uint8_t sig_buf[SM2_MAX_SIGNATURE_SIZE];
    size_t sig_len = 0;

    if (sm2_sign_finish(&sign_ctx, sig_buf, &sig_len) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2签名完成失败");
        gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
        return false;
    }

    signature = QByteArray((char*)sig_buf, sig_len);

    // 清理上下文
    gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

    LOG_INFO("GMSSCRYPTO", QString("SM2签名成功，签名长度: %1").arg(sig_len));
    return true;
}

bool GmSSLCrypto::sm2SignWithKey(const QByteArray &privateKey, const QByteArray &data,
                                 QByteArray &signature, const QByteArray &id)
{
    LOG_DEBUG("GMSSCRYPTO", "开始SM2签名（使用指定私钥）");

    // 加载私钥
    SM2_KEY key;
    const uint8_t *pri_ptr = (const uint8_t*)privateKey.constData();
    size_t pri_len = privateKey.size();

    if (sm2_private_key_from_der(&key, &pri_ptr, &pri_len) != 1) {
        LOG_ERROR("GMSSCRYPTO", "私钥加载失败");
        gmssl_secure_clear(&key, sizeof(key));
        return false;
    }

    // 如果没有提供ID，使用默认值
    QByteArray sign_id = id;
    if (sign_id.isEmpty()) {
        sign_id = QByteArray(SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID));
    }

    // 初始化签名上下文
    SM2_SIGN_CTX sign_ctx;
    if (sm2_sign_init(&sign_ctx, &key,
                      sign_id.constData(),
                      sign_id.size()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2签名初始化失败");
        gmssl_secure_clear(&key, sizeof(key));
        return false;
    }

    // 更新数据到签名上下文
    if (sm2_sign_update(&sign_ctx,
                        (const uint8_t*)data.constData(),
                        data.size()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2签名更新失败");
        gmssl_secure_clear(&key, sizeof(key));
        gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
        return false;
    }

    // 完成签名
    uint8_t sig_buf[SM2_MAX_SIGNATURE_SIZE];
    size_t sig_len = 0;

    if (sm2_sign_finish(&sign_ctx, sig_buf, &sig_len) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2签名完成失败");
        gmssl_secure_clear(&key, sizeof(key));
        gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
        return false;
    }

    signature = QByteArray((char*)sig_buf, sig_len);

    // 清理敏感数据
    gmssl_secure_clear(&key, sizeof(key));
    gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

    LOG_INFO("GMSSCRYPTO", QString("SM2签名成功，签名长度: %1").arg(sig_len));
    return true;
}

bool GmSSLCrypto::sm2Verify(const QByteArray &publicKey, const QByteArray &data,
                            const QByteArray &signature, const QByteArray &id)
{
    LOG_DEBUG("GMSSCRYPTO", "开始SM2验签");

    // 加载公钥
    SM2_KEY key;
    const uint8_t *pub_ptr = (const uint8_t*)publicKey.constData();
    size_t pub_len = publicKey.size();

    if (sm2_public_key_from_der(&key, &pub_ptr, &pub_len) != 1) {
        LOG_ERROR("GMSSCRYPTO", "公钥加载失败");
        return false;
    }

    // 如果没有提供ID，使用默认值
    QByteArray verify_id = id;
    if (verify_id.isEmpty()) {
        verify_id = QByteArray(SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID));
    }

    // 初始化验签上下文
    SM2_VERIFY_CTX verify_ctx;
    if (sm2_verify_init(&verify_ctx, &key,
                        verify_id.constData(),
                        verify_id.size()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2验签初始化失败");
        return false;
    }

    // 更新数据到验签上下文
    if (sm2_verify_update(&verify_ctx,
                          (const uint8_t*)data.constData(),
                          data.size()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM2验签更新失败");
        gmssl_secure_clear(&verify_ctx, sizeof(verify_ctx));
        return false;
    }

    // 完成验签
    int ret = sm2_verify_finish(&verify_ctx,
                                (const uint8_t*)signature.constData(),
                                signature.size());

    gmssl_secure_clear(&verify_ctx, sizeof(verify_ctx));

    if (ret == 1) {
        LOG_INFO("GMSSCRYPTO", "SM2验签成功");
        return true;
    } else {
        LOG_WARNING("GMSSCRYPTO", "SM2验签失败");
        return false;
    }
}

bool GmSSLCrypto::sm4Encrypt(const QByteArray &key, const QByteArray &data,
                             QByteArray &encrypted)
{
    if (key.size() != 16) {
        LOG_ERROR("GMSSCRYPTO", "SM4密钥必须是16字节");
        return false;
    }

    LOG_DEBUG("GMSSCRYPTO", QString("开始SM4加密，数据大小: %1").arg(data.size()));

    // 生成随机IV
    QByteArray iv = generateRandomBytes(16);
    if (iv.isEmpty()) {
        LOG_ERROR("GMSSCRYPTO", "无法生成随机IV");
        return false;
    }

    // 初始化加密上下文
    SM4_CBC_CTX ctx;
    if (sm4_cbc_encrypt_init(&ctx,
                             (const uint8_t*)key.constData(),
                             (const uint8_t*)iv.constData()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4加密初始化失败");
        gmssl_secure_clear(&ctx, sizeof(ctx));
        return false;
    }

    // 准备输出缓冲区
    size_t outlen = data.size() + 32; // 预留填充空间
    QByteArray output;
    output.resize(outlen);

    uint8_t *outbuf = (uint8_t*)output.data();
    size_t total_outlen = 0;

    // 更新数据
    size_t update_outlen;
    if (sm4_cbc_encrypt_update(&ctx,
                               (const uint8_t*)data.constData(),
                               data.size(),
                               outbuf,
                               &update_outlen) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4加密更新失败");
        gmssl_secure_clear(&ctx, sizeof(ctx));
        return false;
    }

    total_outlen += update_outlen;
    outbuf += update_outlen;

    // 完成加密
    size_t final_outlen;
    if (sm4_cbc_encrypt_finish(&ctx, outbuf, &final_outlen) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4加密完成失败");
        gmssl_secure_clear(&ctx, sizeof(ctx));
        return false;
    }

    total_outlen += final_outlen;
    output.resize(total_outlen);

    // 将IV添加到加密数据前面
    encrypted = iv + output;

    // 清理上下文
    gmssl_secure_clear(&ctx, sizeof(ctx));

    LOG_DEBUG("GMSSCRYPTO", QString("SM4加密成功，数据大小: %1 -> %2")
                                .arg(data.size()).arg(encrypted.size()));
    return true;
}

bool GmSSLCrypto::sm4Decrypt(const QByteArray &key, const QByteArray &encrypted,
                             QByteArray &decrypted)
{
    if (key.size() != 16) {
        LOG_ERROR("GMSSCRYPTO", "SM4密钥必须是16字节");
        return false;
    }

    if (encrypted.size() < 32) { // IV + 至少1个数据块
        LOG_ERROR("GMSSCRYPTO", "加密数据太短");
        return false;
    }

    LOG_DEBUG("GMSSCRYPTO", QString("开始SM4解密，数据大小: %1").arg(encrypted.size()));

    // 提取IV
    QByteArray iv = encrypted.left(16);
    QByteArray ciphertext = encrypted.mid(16);

    // 初始化解密上下文
    SM4_CBC_CTX ctx;
    if (sm4_cbc_decrypt_init(&ctx,
                             (const uint8_t*)key.constData(),
                             (const uint8_t*)iv.constData()) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4解密初始化失败");
        gmssl_secure_clear(&ctx, sizeof(ctx));
        return false;
    }

    // 准备输出缓冲区
    size_t outlen = ciphertext.size() + 16; // 预留额外空间
    QByteArray output;
    output.resize(outlen);

    uint8_t *outbuf = (uint8_t*)output.data();
    size_t total_outlen = 0;

    // 更新数据
    size_t update_outlen;
    if (sm4_cbc_decrypt_update(&ctx,
                               (const uint8_t*)ciphertext.constData(),
                               ciphertext.size(),
                               outbuf,
                               &update_outlen) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4解密更新失败");
        gmssl_secure_clear(&ctx, sizeof(ctx));
        return false;
    }

    total_outlen += update_outlen;
    outbuf += update_outlen;

    // 完成解密
    size_t final_outlen;
    if (sm4_cbc_decrypt_finish(&ctx, outbuf, &final_outlen) != 1) {
        LOG_ERROR("GMSSCRYPTO", "SM4解密完成失败（可能是MAC地址不正确或者密钥错误或数据损坏）");
        gmssl_secure_clear(&ctx, sizeof(ctx));
        return false;
    }

    total_outlen += final_outlen;
    output.resize(total_outlen);
    decrypted = output;

    // 清理上下文
    gmssl_secure_clear(&ctx, sizeof(ctx));

    LOG_DEBUG("GMSSCRYPTO", QString("SM4解密成功，数据大小: %1 -> %2")
                                .arg(encrypted.size()).arg(decrypted.size()));
    return true;
}


QByteArray GmSSLCrypto::sm3Hash(const QByteArray &data)
{
    LOG_DEBUG("GMSSCRYPTO", QString("开始SM3哈希计算，数据大小: %1").arg(data.size()));

    SM3_CTX ctx;
    uint8_t hash[32];

    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t*)data.constData(), data.size());
    sm3_finish(&ctx, hash);

    gmssl_secure_clear(&ctx, sizeof(ctx));

    LOG_DEBUG("GMSSCRYPTO", "SM3哈希计算完成");
    return QByteArray((char*)hash, 32);
}

QByteArray GmSSLCrypto::getSm2PublicKey() const
{
    uint8_t buf[512];
    uint8_t *p = buf;
    size_t len = 0;

    if (sm2_public_key_to_der(&m_sm2Key, &p, &len) != 1) {
        return QByteArray();
    }

    return QByteArray((char*)buf, len);
}

QByteArray GmSSLCrypto::getSm2PrivateKey() const
{
    uint8_t buf[512];
    uint8_t *p = buf;
    size_t len = 0;

    if (sm2_private_key_to_der(&m_sm2Key, &p, &len) != 1) {
        return QByteArray();
    }

    return QByteArray((char*)buf, len);
}

QByteArray GmSSLCrypto::pkcs7Padding(const QByteArray &data, int blockSize)
{
    int padding = blockSize - (data.size() % blockSize);
    if (padding == 0) padding = blockSize;

    QByteArray padded = data;
    padded.append(padding, padding);
    return padded;
}

QByteArray GmSSLCrypto::pkcs7Unpadding(const QByteArray &data)
{
    if (data.isEmpty()) return data;

    int padding = data[data.size() - 1];
    if (padding <= 0 || padding > 16) {
        return data; // 不是有效的PKCS7填充
    }

    // 验证填充
    for (int i = 0; i < padding; ++i) {
        if (data[data.size() - 1 - i] != padding) {
            return data; // 填充无效
        }
    }

    return data.left(data.size() - padding);
}
