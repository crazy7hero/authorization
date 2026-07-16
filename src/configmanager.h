#ifndef CONFIGMANAGER_H
#define CONFIGMANAGER_H

#include <QObject>
#include <QSettings>
#include <QDir>

class ConfigManager : public QObject
{
    Q_OBJECT

public:
    static ConfigManager& instance();

    // 配置项
    QString getPrivateKeyPath() const;
    QString getPublicKeyPath() const;
    QString getSm4KeyPath() const;
    QString getDefaultLicensePath() const;
    QString getLogFilePath() const;
    QString getSm2KeyPassword() const;

    // 设置配置项
    void setPrivateKeyPath(const QString &path);
    void setPublicKeyPath(const QString &path);
    void setSm4KeyPath(const QString &path);
    void setDefaultLicensePath(const QString &path);
    void setLogFilePath(const QString &path);
    void setSm2KeyPassword(const QString &password);

    // 文件操作
    bool saveConfig();
    bool loadConfig();

    // 检查配置
    bool checkConfig();
    QStringList getConfigErrors();

    // 创建默认目录结构
    bool createDefaultDirs();

private:
    ConfigManager();
    ~ConfigManager() = default;

    QSettings *m_settings;

    void initDefaultConfig();
};

#endif // CONFIGMANAGER_H
