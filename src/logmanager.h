// logmanager.h
#ifndef LOGMANAGER_H
#define LOGMANAGER_H

#include <QObject>
#include <QTextEdit>
#include <QFile>
#include <QMutex>
#include <QDateTime>
#include <QTextStream>
#include <QApplication>

class LogManager : public QObject
{
    Q_OBJECT

public:
    enum LogLevel {
        LEVEL_DEBUG = 0,
        LEVEL_INFO,
        LEVEL_WARNING,
        LEVEL_ERROR,
        LEVEL_CRITICAL
    };

    static LogManager& instance();

    bool initialize(const QString &logFilePath = QString(), QTextEdit *textEdit = nullptr);

    void log(LogLevel level, const QString &module, const QString &message);
    void debug(const QString &module, const QString &message);
    void info(const QString &module, const QString &message);
    void warning(const QString &module, const QString &message);
    void error(const QString &module, const QString &message);
    void critical(const QString &module, const QString &message);

    void setDisplayLevel(LogLevel level) { m_displayLevel = level; }
    void clearDisplay();
    QString getLogFilePath() const { return m_logFilePath; }
    bool exportLog(const QString &filePath);
    static QString levelToString(LogLevel level);
    void reconnectSignalSlot();

signals:
    void logMessageAdded(const QString &message);

private:
    LogManager();
    ~LogManager();

    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;

    void writeToFile(LogLevel level, const QString &module, const QString &message);
    void displayToUI(LogLevel level, const QString &module, const QString &message);
    QString formatLog(LogLevel level, const QString &module, const QString &message);
    QString getColorForLevel(LogLevel level);
    void rotateLogIfNeeded();

    QTextEdit *m_textEdit;
    QFile m_logFile;
    QTextStream m_textStream;
    QMutex m_mutex;
    LogLevel m_displayLevel;
    QString m_logFilePath;
    bool m_initialized = false;
    static const qint64 MAX_LOG_FILE_SIZE = 10 * 1024 * 1024;
};

// logmanager.h
// 安全的日志宏 - 检查LogManager是否初始化
// 获取默认日志路径的内联函数
inline QString defaultLogPath()
{
    QString date = QDateTime::currentDateTime().toString("yyyyMMdd");
    return QApplication::applicationDirPath() + "/logs/license_system_" + date + ".log";
}

// 统一的日志宏
#define LOG(level, module, msg) do { \
if (LogManager::instance().getLogFilePath().isEmpty()) { \
        LogManager::instance().initialize(defaultLogPath()); \
} \
    LogManager::instance().log(level, module, msg); \
} while(0)

// 便捷宏 - 自动传入日志级别
#define LOG_DEBUG(module, msg)   LOG(LogManager::LEVEL_DEBUG, module, msg)
#define LOG_INFO(module, msg)    LOG(LogManager::LEVEL_INFO, module, msg)
#define LOG_WARNING(module, msg) LOG(LogManager::LEVEL_WARNING, module, msg)
#define LOG_ERROR(module, msg)   LOG(LogManager::LEVEL_ERROR, module, msg)
#define LOG_CRITICAL(module, msg) LOG(LogManager::LEVEL_CRITICAL, module, msg)

#endif // LOGMANAGER_H
