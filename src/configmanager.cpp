#include "configmanager.h"
#include "logmanager.h"
#include "logmanager.h"
#include <QApplication>
#include <QStandardPaths>
#include <QFileInfo>
#include <QDir>

ConfigManager::ConfigManager()
{
    QString configPath = QApplication::applicationDirPath() + "/config.ini";
    m_settings = new QSettings(configPath, QSettings::IniFormat);
    //loadConfig();
}

ConfigManager& ConfigManager::instance()
{
    static ConfigManager instance;
    return instance;
}

// configmanager.cpp
void ConfigManager::initDefaultConfig()
{
    QString appDir = QApplication::applicationDirPath();

    // 默认配置
    m_settings->beginGroup("Keys");
    m_settings->setValue("sm2_private_key", appDir + "/keys/sm2_private.pem");
    m_settings->setValue("sm2_public_key", appDir + "/keys/sm2_public.pem");
    m_settings->setValue("sm4_key", appDir + "/keys/sm4_key.bin");
    m_settings->endGroup();

    m_settings->beginGroup("Security");
    m_settings->setValue("sm2_key_password", "1234567812345678");
    m_settings->endGroup();

    m_settings->beginGroup("License");
    m_settings->setValue("default_license_path", appDir + "/licenses/");
    m_settings->endGroup();

    saveConfig();
}

bool ConfigManager::loadConfig()
{
    LOG_INFO("CONFIG", "开始加载配置文件");

    QString configPath = m_settings->fileName();
    LOG_INFO("CONFIG", QString("配置文件路径: %1").arg(configPath));

    if (m_settings->allKeys().isEmpty()) {
        LOG_INFO("CONFIG", "配置文件为空，创建默认配置");
        initDefaultConfig();
        createDefaultDirs();
        return true;
    }

    LOG_INFO("CONFIG", "配置文件加载完成");

    // 输出所有配置项
    QStringList allKeys = m_settings->allKeys();
    LOG_DEBUG("CONFIG", QString("配置项数量: %1").arg(allKeys.size()));

    // 在循环中检查日志系统是否可用
    for (const QString &key : allKeys) {
        QString value = m_settings->value(key).toString();

        // 对于敏感信息（如密码），进行掩码处理
        if (key.contains("password", Qt::CaseInsensitive) ||
            key.contains("passwd", Qt::CaseInsensitive)) {
            value = "********";
        }

        LOG_DEBUG("CONFIG", QString("  %1 = %2").arg(key, 25).arg(value));
    }

    // 使用更安全的输出方式
    LOG_INFO("CONFIG", QString("私钥路径: %1").arg(getPrivateKeyPath()));
    LOG_INFO("CONFIG", QString("公钥路径: %1").arg(getPublicKeyPath()));
    LOG_INFO("CONFIG", QString("SM4密钥路径: %1").arg(getSm4KeyPath()));

    return checkConfig();
}

bool ConfigManager::saveConfig()
{
    m_settings->sync();
    bool ok = m_settings->status() == QSettings::NoError;

    if (ok) {
        LOG_INFO("CONFIG", "配置文件保存成功");
    } else {
        LOG_ERROR("CONFIG", "配置文件保存失败");
    }

    return ok;
}

bool ConfigManager::checkConfig()
{
    QStringList errors;

    // 检查关键文件路径
    if (getPrivateKeyPath().isEmpty()) {
        LOG_WARNING("CONFIG", "私钥路径未设置");
    }
    if (getPublicKeyPath().isEmpty()) {
        LOG_WARNING("CONFIG", "公钥路径未设置");
    }
    if (getSm4KeyPath().isEmpty()) {
        LOG_WARNING("CONFIG", "SM4密钥路径未设置");
    }

    // 检查目录是否存在
    if (!createDefaultDirs()) {
        LOG_WARNING("CONFIG", "无法创建必要的目录");
    }

    if (!errors.isEmpty()) {
        for (const QString &error : errors) {
            LOG_ERROR("CONFIG", error);
        }
        return false;
    }

    LOG_INFO("CONFIG", "配置检查通过");
    return true;
}

QStringList ConfigManager::getConfigErrors()
{
    QStringList errors;

    if (getPrivateKeyPath().isEmpty()) errors << "私钥路径未设置";
    if (getPublicKeyPath().isEmpty()) errors << "公钥路径未设置";
    if (getSm4KeyPath().isEmpty()) errors << "SM4密钥路径未设置";
//    if (getLogFilePath().isEmpty()) errors << "日志文件路径未设置";

    return errors;
}

bool ConfigManager::createDefaultDirs()
{
    QString appDir = QApplication::applicationDirPath();
    QStringList dirs;

    dirs << appDir + "/keys"
         << appDir + "/licenses"
         << appDir + "/logs";

    bool allOk = true;
    for (const QString &dir : dirs) {
        QDir qdir(dir);
        if (!qdir.exists()) {
            if (!qdir.mkpath(".")) {
                LOG_ERROR("CONFIG", QString("无法创建目录: %1").arg(dir));
                allOk = false;
            } else {
                LOG_DEBUG("CONFIG", QString("创建目录: %1").arg(dir));
            }
        }
    }

    if (allOk) {
        LOG_INFO("CONFIG", "目录结构检查/创建完成");
    }

    return allOk;
}

// Getter方法
QString ConfigManager::getPrivateKeyPath() const
{
    return m_settings->value("Keys/sm2_private_key").toString();
}

QString ConfigManager::getPublicKeyPath() const
{
    return m_settings->value("Keys/sm2_public_key").toString();
}

QString ConfigManager::getSm4KeyPath() const
{
    return m_settings->value("Keys/sm4_key").toString();
}

QString ConfigManager::getDefaultLicensePath() const
{
    return m_settings->value("License/default_license_path").toString();
}

QString ConfigManager::getLogFilePath() const
{
    return m_settings->value("Log/log_file").toString();
}

QString ConfigManager::getSm2KeyPassword() const
{
    return m_settings->value("Security/sm2_key_password").toString();
}

// Setter方法
void ConfigManager::setPrivateKeyPath(const QString &path)
{
    m_settings->setValue("Keys/sm2_private_key", path);
    LOG_INFO("CONFIG", QString("设置私钥路径: %1").arg(path));
}

void ConfigManager::setPublicKeyPath(const QString &path)
{
    m_settings->setValue("Keys/sm2_public_key", path);
    LOG_INFO("CONFIG", QString("设置公钥路径: %1").arg(path));
}

void ConfigManager::setSm4KeyPath(const QString &path)
{
    m_settings->setValue("Keys/sm4_key", path);
    LOG_INFO("CONFIG", QString("设置SM4密钥路径: %1").arg(path));
}

void ConfigManager::setDefaultLicensePath(const QString &path)
{
    m_settings->setValue("License/default_license_path", path);
    LOG_INFO("CONFIG", QString("设置默认授权路径: %1").arg(path));
}

void ConfigManager::setLogFilePath(const QString &path)
{
    m_settings->setValue("Log/log_file", path);
    LOG_INFO("CONFIG", QString("设置日志文件路径: %1").arg(path));
}

void ConfigManager::setSm2KeyPassword(const QString &password)
{
    m_settings->setValue("Security/sm2_key_password", password);
    LOG_INFO("CONFIG", "更新SM2密钥密码");
}
