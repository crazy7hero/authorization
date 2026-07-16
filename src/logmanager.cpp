#include "logmanager.h"
#include <QTextStream>
#include <QDir>
#include <QApplication>
#include <QScrollBar>
#include <QTextCursor>
#include <QDateTime>
#include <QDebug>
#include <QTextCodec>

LogManager::LogManager()
    : m_textEdit(nullptr)
    , m_displayLevel(LEVEL_INFO)
    , m_logFile()
    , m_textStream()
    , m_initialized(false)
{
}

LogManager::~LogManager()
{
    if (m_logFile.isOpen()) {
        m_logFile.close();
    }
}

LogManager& LogManager::instance()
{
    static LogManager instance;
    return instance;
}

bool LogManager::initialize(const QString &logFilePath, QTextEdit *textEdit)
{
    QMutexLocker locker(&m_mutex);

    // 更新 textEdit（即使已初始化也要更新）
    if (textEdit != nullptr) {
        m_textEdit = textEdit;
    }

    // 如果已经初始化，重新连接信号槽后返回
    if (m_initialized) {
        reconnectSignalSlot();
        return true;
    }

    // 如果提供了logFilePath，使用它；否则使用默认路径
    if (!logFilePath.isEmpty()) {
        m_logFilePath = logFilePath;
    } else if (m_logFilePath.isEmpty()) {
        QString appDir = QApplication::applicationDirPath();
        QString date = QDateTime::currentDateTime().toString("yyyyMMdd");
        m_logFilePath = appDir + QString("/logs/license_system_%1.log").arg(date);
    }

    // 确保日志目录存在
    QDir logDir = QFileInfo(m_logFilePath).absoluteDir();
    if (!logDir.exists()) {
        if (!logDir.mkpath(".")) {
            qWarning() << "Failed to create log directory:" << logDir.absolutePath();
            return false;
        }
    }

    // 检查并轮转日志文件
    rotateLogIfNeeded();

    // 如果文件已打开，先关闭
    if (m_logFile.isOpen()) {
        m_logFile.close();
    }

    // 打开日志文件
    m_logFile.setFileName(m_logFilePath);
    if (!m_logFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        qWarning() << "Failed to open log file:" << m_logFilePath;
        return false;
    }

    // 设置编码
    m_textStream.setCodec("UTF-8");
    m_textStream.setDevice(&m_logFile);

    // 如果是新文件，写入UTF-8 BOM
    if (m_logFile.size() == 0) {
        m_logFile.write("\xEF\xBB\xBF");
        m_logFile.flush();
    }

    // 重新连接信号槽
    reconnectSignalSlot();

    m_initialized = true;
    //qDebug() << "LogManager initialized, log file:" << m_logFilePath;
    return true;
}

void LogManager::reconnectSignalSlot()
{
    // 断开之前的连接
    disconnect(this, &LogManager::logMessageAdded, nullptr, nullptr);

    if (!m_textEdit) {
        //qDebug() << "LogManager: m_textEdit is null, cannot connect signal";
        return;
    }

    // 重新连接
    connect(this, &LogManager::logMessageAdded,
            this, [this](const QString &message) {
                if (m_textEdit) {
                    QMetaObject::invokeMethod(m_textEdit, [this, message]() {
                        if (!m_textEdit) return;
                        m_textEdit->append(message);
                        QScrollBar *scrollBar = m_textEdit->verticalScrollBar();
                        if (scrollBar) {
                            scrollBar->setValue(scrollBar->maximum());
                        }
                    });
                }
            }, Qt::QueuedConnection);

    //qDebug() << "LogManager signal connected to m_textEdit";
}

void LogManager::rotateLogIfNeeded()
{
    if (QFile::exists(m_logFilePath)) {
        QFileInfo fileInfo(m_logFilePath);
        if (fileInfo.size() > MAX_LOG_FILE_SIZE) {
            // 先关闭当前文件
            if (m_logFile.isOpen()) {
                m_logFile.close();
            }

            // 生成备份文件名
            QString backupFile = QString("%1.%2.bak")
                                     .arg(m_logFilePath)
                                     .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));

            // 重命名当前日志文件
            if (QFile::rename(m_logFilePath, backupFile)) {
                // 删除旧的备份文件（保留最近5个）
                QDir logDir = QFileInfo(m_logFilePath).absoluteDir();
                QStringList backupFiles = logDir.entryList(
                    QStringList() << "*.bak", QDir::Files, QDir::Time);

                for (int i = 5; i < backupFiles.size(); i++) {
                    logDir.remove(backupFiles[i]);
                }
            }

            // 重新打开日志文件
            if (m_logFile.open(QIODevice::WriteOnly | QIODevice::Append)) {
                QTextCodec *codec = QTextCodec::codecForName("UTF-8");
                m_textStream.setDevice(&m_logFile);
                m_textStream.setCodec(codec);
            }
        }
    }
}

void LogManager::log(LogLevel level, const QString &module, const QString &message)
{
    QMutexLocker locker(&m_mutex);

    // 记录到文件
    writeToFile(level, module, message);

    // 显示到UI
    if (level >= m_displayLevel) {
        displayToUI(level, module, message);
    }
}

// logmanager.cpp
// logmanager.cpp
void LogManager::writeToFile(LogLevel level, const QString &module, const QString &message)
{
    if (!m_logFile.isOpen() || !m_textStream.device()) {
        return;
    }

    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");
    QString levelStr = levelToString(level);

    // 分割多行消息，每条日志独立一行
    //QStringList lines = message.split("\n", Qt::SkipEmptyParts);
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    QStringList lines = message.split("\n", Qt::SkipEmptyParts);
#else
    QStringList lines = message.split("\n", QString::SkipEmptyParts);
#endif

    if (lines.isEmpty()) {
        // 如果是空消息，只写时间戳和模块
        m_textStream << QString("[%1] [%2] [%3] \n")
                            .arg(timestamp)
                            .arg(levelStr, -7)
                            .arg(module, -15);
    } else {
        // 每行都写完整的日志头
        for (const QString &line : lines) {
            m_textStream << QString("[%1] [%2] [%3] %4\n")
            .arg(timestamp)
                .arg(levelStr, -7)
                .arg(module, -15)
                .arg(line);
        }
    }

    m_textStream.flush();
}

void LogManager::displayToUI(LogLevel level, const QString &module, const QString &message)
{
    QString formattedMsg = formatLog(level, module, message);
    emit logMessageAdded(formattedMsg);
}

// logmanager.cpp
QString LogManager::formatLog(LogLevel level, const QString &module, const QString &message)
{
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString levelStr = levelToString(level);
    QString color = getColorForLevel(level);

    // 处理消息中的换行符，将 \n 转换为 <br/>
    QString formattedMessage = message;
    formattedMessage = formattedMessage.toHtmlEscaped();  // 转义HTML特殊字符
    formattedMessage.replace("\n", "<br/>");
    // 同时处理 Windows 风格的换行符 \r\n
    formattedMessage.replace("\r\n", "<br/>");

    // 返回完整的HTML格式，包含<div>标签
    return QString("<div style='margin: 1px 0; padding: 1px;'>"
                   "<span style='color: #888888;'>[%1]</span> "
                   "<span style='color: %2; font-weight: bold;'>%3</span> "
                   "<span style='color: #0066CC; font-weight: bold;'>[%4]</span> "
                   "<span style='color: #333333;'>%5</span>"
                   "</div>")
        .arg(timestamp)
        .arg(color)
        .arg(levelStr)
        .arg(module)
        .arg(formattedMessage);
}

QString LogManager::getColorForLevel(LogLevel level)
{
    switch (level) {
    case LEVEL_DEBUG:    return "#666666";
    case LEVEL_INFO:     return "#009900";
    case LEVEL_WARNING:  return "#FF9900";
    case LEVEL_ERROR:    return "#FF0000";
    case LEVEL_CRITICAL: return "#990000";
    default:             return "#000000";
    }
}

void LogManager::debug(const QString &module, const QString &message)
{
    log(LEVEL_DEBUG, module, message);
}

void LogManager::info(const QString &module, const QString &message)
{
    log(LEVEL_INFO, module, message);
}

void LogManager::warning(const QString &module, const QString &message)
{
    log(LEVEL_WARNING, module, message);
}

void LogManager::error(const QString &module, const QString &message)
{
    log(LEVEL_ERROR, module, message);
}

void LogManager::critical(const QString &module, const QString &message)
{
    log(LEVEL_CRITICAL, module, message);
}

QString LogManager::levelToString(LogLevel level)
{
    switch (level) {
    case LEVEL_DEBUG:    return "DEBUG";
    case LEVEL_INFO:     return "INFO";
    case LEVEL_WARNING:  return "WARNING";
    case LEVEL_ERROR:    return "ERROR";
    case LEVEL_CRITICAL: return "CRITICAL";
    default:             return "UNKNOWN";
    }
}

void LogManager::clearDisplay()
{
    if (m_textEdit) {
        m_textEdit->clear();
    }
}

bool LogManager::exportLog(const QString &filePath)
{
    QMutexLocker locker(&m_mutex);

    if (!m_logFile.isOpen()) {
        return false;
    }

    m_textStream.flush();
    m_logFile.flush();

    return QFile::copy(m_logFilePath, filePath);
}
