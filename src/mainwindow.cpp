#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "licensegenerator.h"
#include "licensevalidator.h"
#include "configmanager.h"
#include "logmanager.h"
#include "gmsslcrypto.h"
#include "keyconfigdialog.h"
#include "machine_id.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStyleFactory>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QTabWidget>
#include <QGroupBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QDateTimeEdit>
#include <QListWidget>
#include <QCheckBox>
#include <QComboBox>
#include <QSpinBox>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QStatusBar>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QToolBar>
#include <QTimer>
#include <QRandomGenerator>
#include <QApplication>
#include <QFileInfo>
#include <QDir>
#include <QScrollArea>
#include <QRegularExpression>
#include <QNetworkInterface>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setupUI();

    setWindowIcon(QIcon(":/images/icon.png"));
    // 设置日志文本框的文本交互格式(启用富文本（Rich Text）支持,HTML格式的文本，可以显示不同颜色、字体、大小、加粗、斜体等格式化文本)
    ui->logTextEdit->setAcceptRichText(true);
    // 设置日志框为只读但可选
    ui->logTextEdit->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    // 初始化日志系统
    if (!LogManager::instance().initialize(NULL, ui->logTextEdit)) {
        QMessageBox::warning(this, "警告", "日志系统初始化失败");
    }
    setWindowFlags(Qt::Window | Qt::WindowTitleHint |
                   Qt::WindowMinimizeButtonHint | Qt::WindowCloseButtonHint);

    LOG_INFO("SYSTEM", "国密授权管理系统启动");
    LOG_INFO("SYSTEM", QString("版本: %1").arg(QApplication::applicationVersion()));

    // 默认切换到"授权文件生成"标签页（索引为1）
    ui->tabWidget->setCurrentIndex(1);

    // ========== 根据宏设置标签文本 ==========
    ui->label_mac->setText(getIdentifierLabel() + ":");
    ui->label_validateMac->setText(getIdentifierLabel() + ":");
    ui->label_10->setText(getIdentifierLabel() + ":");

    ui->macAddressEdit->setPlaceholderText(getIdentifierPlaceholder());
    ui->validateMacEdit->setPlaceholderText(getIdentifierPlaceholder());

    // ========== DEBUG 模式自动填充测试数据 ==========
#ifdef DEBUG
    QString versiontemp = "1.0";
    ui->versionEdit->setText(versiontemp);

#ifdef USE_MAC_ADDRESS
    QString testIdentifier = "00-11-22-33-44-55";
#else
    // 使用 machine_id 获取当前机器的唯一ID
    QString testIdentifier = QString::fromStdString(MachineId::GetHashedHardwareId());
#endif
    ui->macAddressEdit->setText(testIdentifier);
    ui->validateMacEdit->setText(testIdentifier);
#endif

    // 方便密码管理,隐藏密码输入,所有生成的密钥都为"123456781234578"
    ui->label_password->setVisible(false);
    ui->keyPasswordEdit->setVisible(false);
    ui->showPasswordCheck->setVisible(false);

    // 定时更新状态栏
    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::updateStatusBar);
    timer->start(1000);
}

MainWindow::~MainWindow()
{
    LOG_INFO("SYSTEM", "应用程序退出");
    delete ui;
}

// ============================================================================
// 根据宏定义的标识符处理函数
// ============================================================================

QString MainWindow::getCurrentIdentifier()
{
#ifdef USE_MAC_ADDRESS
    // MAC 地址模式：获取当前机器的 MAC 地址
    QString macAddress;
    foreach (const QNetworkInterface &interface, QNetworkInterface::allInterfaces()) {
        if (interface.flags().testFlag(QNetworkInterface::IsLoopBack))
            continue;
        if (interface.flags().testFlag(QNetworkInterface::IsPointToPoint))
            continue;
        if (interface.hardwareAddress().isEmpty())
            continue;
        if (interface.hardwareAddress() == "00:00:00:00:00:00")
            continue;
        QString name = interface.name().toLower();
        if (name.contains("virtual") || name.contains("vmware") ||
            name.contains("vbox") || name.contains("docker") ||
            name.contains("veth") || name.contains("br-")) {
            continue;
        }
        macAddress = interface.hardwareAddress();
        break;
    }
    return macAddress.toUpper();
#else
    // 机器唯一 ID 模式：使用 SHA-256 哈希
    return QString::fromStdString(MachineId::GetHashedHardwareId());
#endif
}

bool MainWindow::validateIdentifier(const QString &identifier)
{
    if (identifier.isEmpty()) {
        return false;
    }

#ifdef USE_MAC_ADDRESS
    QString normalized = identifier;
    normalized.remove(QRegularExpression("[^0-9A-Fa-f]"));
    return (normalized.length() == 12);
#else
    QString normalized = identifier;
    normalized.remove(QRegularExpression("[^0-9A-Fa-f]"));
    return (normalized.length() == 64);
#endif
}

QString MainWindow::getIdentifierLabel()
{
#ifdef USE_MAC_ADDRESS
    return "MAC地址";
#else
    return "机器唯一ID";
#endif
}

QString MainWindow::getIdentifierPlaceholder()
{
#ifdef USE_MAC_ADDRESS
    return "例如：00-11-22-33-44-55 或 00:11:22:33:44:55";
#else
    return "请输入64位机器唯一ID (SHA-256)";
#endif
}

QString MainWindow::normalizeMacAddress(const QString &mac)
{
    QString normalized = mac;
    normalized.remove(QRegularExpression("[^0-9A-Fa-f]"));

    if (normalized.length() != 12) {
        return QString();
    }

    QString result;
    for (int i = 0; i < normalized.length(); i += 2) {
        if (!result.isEmpty()) {
            result += "-";
        }
        result += normalized.mid(i, 2).toUpper();
    }

    return result;
}

// ============================================================================
// UI 设置
// ============================================================================

void MainWindow::setupUI()
{
    // 设置窗口标题
    setWindowTitle("国密授权管理系统 V2.0");

    // 设置窗口大小
    resize(800, 500);

    QAction *exitAction = new QAction("退出", this);
    connect(exitAction, &QAction::triggered, this, &MainWindow::close);

    QAction *configAction = new QAction("配置信息", this);
    connect(configAction, &QAction::triggered, this, &MainWindow::showConfigDialog);

    QAction *reloadconfig = new QAction("配置密钥", this);
    connect(reloadconfig, &QAction::triggered, this, &MainWindow::showKeyConfigDialog);

    QAction *aboutAction = new QAction("关于", this);
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);

    QAction *helpAction = new QAction("帮助", this);
    connect(helpAction, &QAction::triggered, this, &MainWindow::showhelp);

    // 创建工具栏
    QToolBar *toolBar = addToolBar("主工具栏");
    toolBar->addAction(helpAction);
    toolBar->addAction(aboutAction);
    toolBar->setMovable(false);
    toolBar->setFloatable(false);

    // 设置日志文本编辑框
    ui->logTextEdit->setReadOnly(true);
    ui->logTextEdit->setFont(QFont("Consolas", 9));

    // 连接信号槽
    // 密钥管理页
    connect(ui->generateKeysButton, &QPushButton::clicked, this, &MainWindow::onGenerateKeysClicked);
    connect(ui->browseKeyDirButton, &QPushButton::clicked, this, &MainWindow::onBrowseKeyDirClicked);

    // 授权生成页
    connect(ui->createLicenseButton, &QPushButton::clicked, this, &MainWindow::onCreateLicenseClicked);
    connect(ui->browseLicenseOutputButton, &QPushButton::clicked, this, &MainWindow::onBrowseLicenseOutputClicked);
    connect(ui->btn_key, &QPushButton::clicked, this, &MainWindow::onBrowseLicKeyDirClicked);

    // 授权验证页
    connect(ui->verifyLicenseButton, &QPushButton::clicked, this, &MainWindow::onVerifyLicenseClicked);
    connect(ui->browseLicenseFileButton, &QPushButton::clicked, this, &MainWindow::onBrowseLicenseFileClicked);

    // 日志页
    connect(ui->clearLogButton, &QPushButton::clicked, this, &MainWindow::onClearLogClicked);
    connect(ui->exportLogButton, &QPushButton::clicked, this, &MainWindow::onExportLogClicked);
    connect(ui->logLevelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onLogLevelChanged);

    // 设置默认值
    ui->issueDateEdit->setDateTime(QDateTime::currentDateTime());
    ui->expireDateEdit->setDateTime(QDateTime::currentDateTime().addDays(365));

    // 设置日志级别选择框
    ui->logLevelCombo->addItem("INFO", LogManager::LEVEL_INFO);
    ui->logLevelCombo->addItem("WARNING", LogManager::LEVEL_WARNING);
    ui->logLevelCombo->addItem("ERROR", LogManager::LEVEL_ERROR);

#ifdef DEBUG
    ui->logLevelCombo->addItem("DEBUG", LogManager::LEVEL_DEBUG);
    int debugIndex = ui->logLevelCombo->findData(LogManager::LEVEL_DEBUG);
    if (debugIndex != -1) {
        ui->logLevelCombo->setCurrentIndex(debugIndex);
    }
#else
    int infoIndex = ui->logLevelCombo->findData(LogManager::LEVEL_INFO);
    if (infoIndex != -1) {
        ui->logLevelCombo->setCurrentIndex(infoIndex);
    }
#endif

    ui->keyPasswordEdit->setEchoMode(QLineEdit::Password);
    ui->keyPasswordEdit->setPlaceholderText("输入SM2密钥密码（至少8位）");

    if (ui->showPasswordCheck) {
        ui->showPasswordCheck->setChecked(false);
        ui->showPasswordCheck->setToolTip("勾选以显示明文密码");
        connect(ui->showPasswordCheck, &QCheckBox::stateChanged,
                this, [this](int state) {
                    bool isChecked = (state == Qt::Checked);
                    ui->keyPasswordEdit->setEchoMode(
                        isChecked ? QLineEdit::Normal : QLineEdit::Password
                        );
                });
    }
}

void MainWindow::loadConfig()
{
    LOG_INFO("SYSTEM", "正在加载配置...");
    ConfigManager &config = ConfigManager::instance();
    config.loadConfig();
    LOG_INFO("CONFIG", "配置加载完成");
}

bool MainWindow::checkKeysExist(const QString &dirPath)
{
    QDir dir(dirPath);
    QStringList keyFiles = {
        "sm4_key.bin",
        "sm2_private.pem",
        "sm2_public.pem"
    };

    QStringList foundFiles;

    for (const QString &fileName : keyFiles) {
        if (QFile::exists(dir.absoluteFilePath(fileName))) {
            foundFiles.append(fileName);
        }
    }

    if (!foundFiles.isEmpty()) {
        LOG_WARNING("KEYGEN", QString("发现已存在的密钥文件: %1").arg(foundFiles.join(", ")));
        return true;
    }

    return false;
}

bool MainWindow::confirmOverwrite(const QString &dirPath)
{
    QDir dir(dirPath);
    QStringList foundFiles;

    QStringList exactFileNames = {
                                  "sm4_key.bin", "sm2_private.pem", "sm2_public.pem",
                                  "key_config.ini"};

    for (const QString &fileName : exactFileNames) {
        if (QFile::exists(dir.absoluteFilePath(fileName))) {
            QFileInfo fileInfo(dir.absoluteFilePath(fileName));
            foundFiles.append(QString("%1 (%2 字节)").arg(fileName).arg(fileInfo.size()));
        }
    }

    if (foundFiles.isEmpty()) {
        QStringList patterns = {"*key*.pem", "*key*.bin", "*config*.ini"};
        for (const QString &pattern : patterns) {
            QStringList files = dir.entryList(QStringList() << pattern, QDir::Files);
            for (const QString &file : files) {
                bool alreadyAdded = false;
                for (const QString &existing : foundFiles) {
                    if (existing.startsWith(file + " (")) {
                        alreadyAdded = true;
                        break;
                    }
                }
                if (!alreadyAdded) {
                    QFileInfo fileInfo(dir.absoluteFilePath(file));
                    foundFiles.append(QString("%1 (%2 字节)").arg(file).arg(fileInfo.size()));
                }
            }
        }
    }

    if (foundFiles.isEmpty()) {
        return true;
    }

    QString message = QString("目录 %1 中已存在以下密钥文件:\n\n")
                          .arg(QDir::toNativeSeparators(dirPath));

    int maxDisplay = 5;
    for (int i = 0; i < qMin(foundFiles.size(), maxDisplay); i++) {
        message += QString("• %1\n").arg(foundFiles[i]);
    }

    if (foundFiles.size() > maxDisplay) {
        message += QString("... 还有 %1 个文件\n").arg(foundFiles.size() - maxDisplay);
    }

    message += "\n继续生成将会覆盖这些文件。\n是否要继续？";

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("确认覆盖");
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setText("检测到已存在的密钥文件");
    msgBox.setInformativeText(message);
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    msgBox.button(QMessageBox::Yes)->setText("继续生成");
    msgBox.button(QMessageBox::No)->setText("取消");

    int result = msgBox.exec();

    if (result == QMessageBox::Yes) {
        LOG_INFO("KEYGEN", "用户选择覆盖现有密钥文件");
        return true;
    } else {
        LOG_INFO("KEYGEN", "用户取消了密钥生成");
        return false;
    }
}

void MainWindow::onGenerateKeysClicked()
{
    QString password = SM2_SIGNI_KEY_PASSWORD;
    QString keyDir = ui->keyDirEdit->text();
    if (keyDir.isEmpty()) {
        LOG_WARNING("KEYGEN", "请选择密钥目录");
        QMessageBox::warning(this, "警告", "请选择密钥目录");
        return;
    }

    if (checkKeysExist(keyDir)) {
        if (!confirmOverwrite(keyDir)) {
            ui->statusbar->showMessage("密钥生成已取消", 3000);
            return;
        }
    }

    LOG_INFO("KEYGEN", "开始生成密钥...");
    ui->keyProgressBar->setVisible(true);
    ui->keyProgressBar->setRange(0, 0);
    ui->generateKeysButton->setEnabled(false);
    ui->statusbar->showMessage("正在生成密钥...");

    QTimer::singleShot(100, this, [this, password, keyDir]() {
        LicenseGenerator generator;
        bool success = generator.generateKeys(password, keyDir);
        ui->keyProgressBar->setVisible(false);
        ui->generateKeysButton->setEnabled(true);

        if (success) {
            LOG_INFO("KEYGEN", "密钥生成成功");
            QMessageBox::information(this, "密钥生成成功",
                                     "密钥文件已生成！\n\n"
                                     "私钥文件: sm2_private.pem\n"
                                     "公钥文件: sm2_public.pem\n"
                                     "SM4密钥: sm4_key.bin\n\n");
        } else {
            LOG_ERROR("KEYGEN", QString("密钥生成失败: %1").arg(generator.getLastError()));
            QMessageBox::critical(this, "失败",
                                  QString("密钥生成失败:\n%1").arg(generator.getLastError()));
            ui->statusbar->showMessage("密钥生成失败", 3000);
        }
    });
}

void MainWindow::onBrowseKeyDirClicked()
{
    QString defaultDir = QCoreApplication::applicationDirPath() + "/keys";
    QString dirPath = QFileDialog::getExistingDirectory(
        this,
        "选择密钥保存目录",
        defaultDir,
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
        );

    if (!dirPath.isEmpty()) {
        ui->keyDirEdit->setText(dirPath);
        LOG_INFO("UI",  (QString("选择密钥保存目录: %1").arg(dirPath)));
    }
}

void MainWindow::onBrowseLicKeyDirClicked()
{
    QString defaultDir = QCoreApplication::applicationDirPath() + "/keys";
    QString dirPath = QFileDialog::getExistingDirectory(
        this,
        "选择密钥目录",
        QApplication::applicationDirPath(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
        );

    if (!dirPath.isEmpty()) {
        ui->lineEdit_key->setText(dirPath);
        LOG_INFO("UI",  (QString("选择密钥目录: %1").arg(dirPath)));
    }
}

void MainWindow::onCreateLicenseClicked()
{
    LOG_INFO("LICENSE", "开始生成授权文件...");

    QString keypath = ui->lineEdit_key->text().trimmed();
    if (keypath.isEmpty()) {
        showMessage("请选择密钥！", true);
        LOG_ERROR("LICENSE", "未选择加密密钥");
        return;
    }

    // ================ 1. 验证版本号 ================
    QString version = ui->versionEdit->text().trimmed();
    if (version.isEmpty()) {
        showMessage("版本号不能为空！", true);
        LOG_ERROR("LICENSE", "版本号为空");
        return;
    }

    // ================ 2. 验证标识符 (MAC地址 或 机器唯一ID) ================
    QString identifier = ui->macAddressEdit->text().trimmed();
    if (identifier.isEmpty()) {
        showMessage(getIdentifierLabel() + "不能为空！", true);
        LOG_ERROR("LICENSE", getIdentifierLabel() + "为空");
        return;
    }

#ifdef USE_MAC_ADDRESS
    // MAC 地址模式：验证 MAC 地址格式
    QString normalizedIdentifier = normalizeMacAddress(identifier);
    if (normalizedIdentifier.isEmpty()) {
        showMessage("MAC地址格式不正确，请使用以下格式：\n"
                    "00:11:22:33:44:55 或 00-11-22-33-44-55", true);
        LOG_ERROR("LICENSE", QString("MAC地址格式错误: %1").arg(identifier));
        return;
    }
#else
    // 机器唯一 ID 模式：验证是否为 64 位十六进制
    QString normalizedIdentifier = identifier;
    normalizedIdentifier.remove(QRegularExpression("[^0-9A-Fa-f]"));
    if (normalizedIdentifier.length() != 64) {
        showMessage("机器唯一ID格式不正确，应为64位十六进制字符 (SHA-256)", true);
        LOG_ERROR("LICENSE", QString("机器唯一ID格式错误: %1").arg(identifier));
        return;
    }
    normalizedIdentifier = normalizedIdentifier.toUpper();
#endif

    // ================ 3. 验证有效期 ================
    QDateTime issueDate = ui->issueDateEdit->dateTime();
    QDateTime expireDate = ui->expireDateEdit->dateTime();

    if (issueDate.isNull() || !issueDate.isValid()) {
        showMessage("签发日期无效", true);
        LOG_ERROR("LICENSE", "签发日期无效");
        return;
    }

    if (expireDate.isNull() || !expireDate.isValid()) {
        showMessage("过期日期无效", true);
        LOG_ERROR("LICENSE", "过期日期无效");
        return;
    }

    if (expireDate <= issueDate) {
        showMessage("过期日期必须晚于签发日期", true);
        LOG_ERROR("LICENSE", "过期日期早于签发日期");
        return;
    }

    // ================ 4. 验证输出路径 ================
    QString outputPath = ui->outputPathEdit->text();
    if (outputPath.isEmpty()) {
        showMessage("请选择授权文件保存路径", true);
        LOG_ERROR("LICENSE", "授权文件保存路径为空");
        return;
    }

    // ================ 5. 验证密钥文件 ================
    QString privateKeyPath = keypath + "/sm2_private.pem";
    QString sm4KeyPath = keypath + "/sm4_key.bin";
    QString password = SM2_SIGNI_KEY_PASSWORD;

    if (privateKeyPath.isEmpty() || !QFile::exists(privateKeyPath)) {
        showMessage("私钥文件不存在，请重新配置密钥路径或者重新生成密钥", true);
        LOG_ERROR("LICENSE", QString("私钥文件不存在: %1").arg(privateKeyPath));
        return;
    }

    if (sm4KeyPath.isEmpty() || !QFile::exists(sm4KeyPath)) {
        showMessage("SM4密钥文件不存在，请重新配置密钥路径或者重新生成密钥", true);
        LOG_ERROR("LICENSE", QString("SM4密钥文件不存在: %1").arg(sm4KeyPath));
        return;
    }

    // ================ 6. 加载SM4密钥 ================
    GmSSLCrypto &crypto = GmSSLCrypto::instance();
    QByteArray sm4Key;
    if (!crypto.loadSm4Key(sm4KeyPath, sm4Key)) {
        showMessage("SM4密钥加载失败，请检查密钥文件", true);
        LOG_ERROR("LICENSE", "SM4密钥加载失败");
        return;
    }

    if (sm4Key.size() != 16) {
        showMessage("SM4密钥长度不正确（应为16字节）", true);
        LOG_ERROR("LICENSE", QString("SM4密钥长度错误: %1 字节").arg(sm4Key.size()));
        return;
    }

    LOG_INFO("LICENSE", QString("SM4密钥加载成功，长度: %1 字节").arg(sm4Key.size()));

    // ================ 7. 构建授权信息 ================
    LicenseGenerator::LicenseInfo licenseInfo;
    licenseInfo.version = version;
    licenseInfo.issueDate = issueDate;
    licenseInfo.expireDate = expireDate;
    licenseInfo.macAddress = normalizedIdentifier;

    // 禁用生成按钮，显示进度
    ui->createLicenseButton->setEnabled(false);
    ui->statusbar->showMessage("正在生成授权文件...");
    ui->keyProgressBar->setVisible(true);
    ui->keyProgressBar->setRange(0, 0);

    // 使用延迟执行避免阻塞UI
    QTimer::singleShot(100, this, [=]() {
        LicenseGenerator generator;

        bool success = generator.generateLicenseWithHashAndSign(licenseInfo,
                                                                privateKeyPath,
                                                                password,
                                                                sm4Key,
                                                                outputPath);

        if (success) {
            QString successMessage = QString("授权文件生成成功！\n\n"
                                             "文件: %1\n"
                                             "版本: %2\n"
                                             "%3: %4\n"
                                             "有效期: %5 至 %6")
                                         .arg(QFileInfo(outputPath).fileName())
                                         .arg(version)
                                         .arg(getIdentifierLabel())
                                         .arg(normalizedIdentifier)
                                         .arg(issueDate.toString("yyyy-MM-dd"))
                                         .arg(expireDate.toString("yyyy-MM-dd"));

            QMessageBox::information(this, "成功", successMessage);
            LOG_INFO("LICENSE", QString("授权文件生成成功: %1").arg(outputPath));
        } else {
            QMessageBox::critical(this, "错误",
                                  QString("授权文件生成失败:\n%1").arg(generator.getLastError()));
            LOG_ERROR("LICENSE", QString("授权文件生成失败: %1").arg(generator.getLastError()));
        }

        ui->createLicenseButton->setEnabled(true);
        ui->statusbar->clearMessage();
        ui->keyProgressBar->setVisible(false);
    });
}

void MainWindow::onBrowseLicenseOutputClicked()
{
    QString defaultDir = QCoreApplication::applicationDirPath() + "/licenses";
    QDir dir(defaultDir);
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    QString fileName = QFileDialog::getSaveFileName(
        this,
        "保存授权文件",
        defaultDir + "/license.lic",
        "授权文件 (*.lic);;所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->outputPathEdit->setText(fileName);
        LOG_INFO("UI", QString("选择保存路径: %1").arg(fileName));
    }
}

void MainWindow::onVerifyLicenseClicked()
{
    QString licensePath = ui->licenseFileEdit->text();
    if (licensePath.isEmpty()) {
        QMessageBox::warning(this, "警告", "请选择授权文件");
        return;
    }

    QString identifier = ui->validateMacEdit->text();

    LOG_INFO("VALIDATE", QString("开始验证授权文件: %1").arg(licensePath));
    ui->statusbar->showMessage("正在验证授权...");

    LicenseValidator validator;
    LicenseValidator::ValidatedInfo result = validator.validateLicenseFile(licensePath, identifier);

    if (result.isValid) {
        QDateTime now = QDateTime::currentDateTime();
        int daysLeft = now.daysTo(result.expireDate);
        if (daysLeft < 0) daysLeft = 0;

        ui->parsedVersionEdit->setText(result.version);
        ui->parsedIssueDateEdit->setText(result.issueDate.toString("yyyy-MM-dd"));
        ui->parsedExpireDateEdit->setText(result.expireDate.toString("yyyy-MM-dd"));
        ui->parsedMacEdit->setText(result.macAddress);

        QString statusText;
        QString color;

        if (daysLeft == 0) {
            statusText = "已过期";
            color = "#e74c3c";
        } else if (daysLeft <= 7) {
            statusText = QString("即将过期 (%1天)").arg(daysLeft);
            color = "#f39c12";
        } else {
            statusText = QString("有效 (%1天)").arg(daysLeft);
            color = "#27ae60";
        }

        ui->parsedStatusEdit->setText(statusText);
        ui->parsedStatusEdit->setStyleSheet(QString(
                                                "QLineEdit {"
                                                "    font-weight: bold;"
                                                "    padding: 6px;"
                                                "    border: 2px solid %1;"
                                                "    background-color: %1;"
                                                "    color: white;"
                                                "    border-radius: 3px;"
                                                "}"
                                                ).arg(color));

        QString infoText = QString("✅ 授权验证通过！\n\n"
                                   "版本号: %1\n"
                                   "%2: %3\n"
                                   "签发日期: %4\n"
                                   "过期日期: %5\n"
                                   "剩余天数: %6天")
                               .arg(result.version)
                               .arg(getIdentifierLabel())
                               .arg(result.macAddress)
                               .arg(result.issueDate.toString("yyyy-MM-dd"))
                               .arg(result.expireDate.toString("yyyy-MM-dd"))
                               .arg(daysLeft);

        if (daysLeft == 0) {
            QMessageBox::information(this, "授权验证", "✅ 授权验证通过！\n\n⚠️ 警告：授权已过期！");
        } else if (daysLeft <= 7) {
            QMessageBox::information(this, "授权验证",
                                     QString("✅ 授权验证通过！\n\n⚠️ 注意：剩余%1天，授权即将过期！").arg(daysLeft));
        } else {
            QMessageBox::information(this, "授权验证", infoText);
        }

        LOG_INFO("VALIDATE", QString("授权验证通过，剩余%1天").arg(daysLeft));
        ui->statusbar->showMessage(QString("授权验证通过，剩余%1天").arg(daysLeft), 5000);

    } else {
        clearValidationFields();

        QString errorText = QString("❌ 授权验证失败！\n\n错误信息:\n%1").arg(result.errorMessage);
        LOG_ERROR("VALIDATE", errorText);

        ui->parsedStatusEdit->setText("验证失败");
        ui->parsedStatusEdit->setStyleSheet(
            "QLineEdit {"
            "    font-weight: bold;"
            "    padding: 6px;"
            "    border: 2px solid #e74c3c;"
            "    background-color: #e74c3c;"
            "    color: white;"
            "    border-radius: 3px;"
            "}"
            );

        QMessageBox::critical(this, "验证失败", result.errorMessage);
        ui->statusbar->showMessage("授权验证失败", 3000);
    }
}

void MainWindow::clearValidationFields()
{
    ui->parsedVersionEdit->clear();
    ui->parsedIssueDateEdit->clear();
    ui->parsedExpireDateEdit->clear();
    ui->parsedMacEdit->clear();

    ui->parsedStatusEdit->clear();
    ui->parsedStatusEdit->setStyleSheet(
        "QLineEdit {"
        "    font-weight: bold;"
        "    padding: 2px;"
        "}"
        );
}

void MainWindow::onBrowseLicenseFileClicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,
        "选择授权文件",
        QCoreApplication::applicationDirPath(),
        "授权文件 (*.lic);;所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->licenseFileEdit->setText(fileName);
        LOG_INFO("UI", (QString("选择授权文件: %1").arg(fileName)));
    }
}

void MainWindow::onClearLogClicked()
{
    LogManager::instance().clearDisplay();
}

void MainWindow::onExportLogClicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, "导出日志",
                                                    QDir::homePath() + "/license_log.txt",
                                                    "文本文件 (*.txt);;所有文件 (*.*)");
    if (!fileName.isEmpty()) {
        if (LogManager::instance().exportLog(fileName)) {
            LOG_INFO("LOG", QString("日志已导出到: %1").arg(fileName));
            QMessageBox::information(this, "成功", "日志导出成功");
        } else {
            LOG_ERROR("LOG", "日志导出失败");
            QMessageBox::warning(this, "失败", "日志导出失败");
        }
    }
}

void MainWindow::onLogLevelChanged(int index)
{
    int level = ui->logLevelCombo->itemData(index).toInt();
    LogManager::instance().setDisplayLevel(static_cast<LogManager::LogLevel>(level));
}

void MainWindow::updateStatusBar()
{
    QString status = QString("就绪 | 时间: %1")
                         .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));
    ui->statusbar->showMessage(status);
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, "关于国密授权管理系统",
                       "<h3>国密授权管理系统 V2.0</h3>"
                       "<p>版本: 2.0</p>"
                       "<p>基于GMSSL的SM2/SM3/SM4国密算法</p>"
                       "<p>支持 MAC地址 和 机器唯一ID 两种绑定方式</p>"
                       "<p>用于生成和验证软件授权文件</p>"
                       "<p>@ 2026 国密授权管理系统</p>");
}

void MainWindow::showConfigDialog()
{
    ConfigManager &config = ConfigManager::instance();
    config.loadConfig();

    QString privateKeyPath = config.getPrivateKeyPath();
    QString pubKeyPath = config.getPublicKeyPath();
    QString sm4KeyPath = config.getSm4KeyPath();

    QString configInfo = QString("当前配置:\n\n"
                                 "私钥路径: %1\n"
                                 "公钥路径: %2\n"
                                 "SM4密钥路径: %3\n")
                             .arg(privateKeyPath.isEmpty() || !QFile::exists(privateKeyPath) ?
                                      "❌ 不存在" : privateKeyPath)
                             .arg(pubKeyPath.isEmpty() || !QFile::exists(pubKeyPath) ?
                                      "❌ 不存在" : pubKeyPath)
                             .arg(sm4KeyPath.isEmpty() || !QFile::exists(sm4KeyPath) ?
                                      "❌ 不存在" : sm4KeyPath);

    QMessageBox::about(this, "配置管理", configInfo);
}

void MainWindow::showKeyConfigDialog()
{
    KeyConfigDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        ui->logTextEdit->append("<font color='green'>[INFO] 密钥配置已更新</font>");
    }
}

void MainWindow::showMessage(const QString &message, bool isError)
{
    if (isError) {
        LOG_ERROR("UI", message);
        QMessageBox::warning(this, "警告", message);
    } else {
        LOG_INFO("UI", message);
        ui->statusbar->showMessage(message, 3000);
    }
}

// ============================================================================
// 帮助对话框
// ============================================================================

void MainWindow::showhelp()
{
    QDialog *helpDialog = new QDialog(this);
    helpDialog->setWindowTitle("使用帮助 - V2.0");
    helpDialog->setMinimumSize(600, 550);
    helpDialog->setModal(false);
    helpDialog->setWindowFlags(Qt::Dialog | Qt::WindowTitleHint |
                               Qt::WindowCloseButtonHint);

    QVBoxLayout *mainLayout = new QVBoxLayout(helpDialog);

    // 标题
    QLabel *titleLabel = new QLabel("📖 国密授权管理系统 V2.0 - 使用指南", helpDialog);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("color: #2c3e50; margin: 10px;");
    mainLayout->addWidget(titleLabel);

    // 版本信息标签
    QLabel *versionLabel = new QLabel(
#ifdef USE_MAC_ADDRESS
        "🔹 当前模式: MAC地址绑定"
#else
        "🔹 当前模式: 机器唯一ID绑定 (SHA-256)"
#endif
        , helpDialog);
    versionLabel->setAlignment(Qt::AlignCenter);
    versionLabel->setStyleSheet("color: #2980b9; font-weight: bold; margin: 5px;");
    mainLayout->addWidget(versionLabel);

    // 选项卡
    QTabWidget *tabWidget = new QTabWidget(helpDialog);
    tabWidget->addTab(createQuickStartTab(), "🚀 快速入门");
    tabWidget->addTab(createOperationTab(), "📝 详细操作");
    tabWidget->addTab(createFaqTab(), "❓ 常见问题");
    mainLayout->addWidget(tabWidget);

    // 关闭按钮
    QPushButton *closeBtn = new QPushButton("关闭", helpDialog);
    closeBtn->setFixedWidth(80);
    closeBtn->setStyleSheet(
        "QPushButton {"
        "   background-color: #3498db;"
        "   color: white;"
        "   padding: 6px 15px;"
        "   border: none;"
        "   border-radius: 4px;"
        "}"
        "QPushButton:hover { background-color: #2980b9; }"
        );

    connect(closeBtn, &QPushButton::clicked, helpDialog, &QDialog::close);

    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    btnLayout->addWidget(closeBtn);
    btnLayout->addStretch();
    mainLayout->addLayout(btnLayout);

    connect(helpDialog, &QDialog::finished, helpDialog, &QDialog::deleteLater);

    helpDialog->show();
}

// 快速入门选项卡
QWidget* MainWindow::createQuickStartTab()
{
    QWidget *widget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(widget);

#ifdef USE_MAC_ADDRESS
    QString idType = "MAC地址";
    QString idExample = "00-11-22-33-44-55";
#else
    QString idType = "机器唯一ID";
    QString idExample = "64位十六进制字符串 (SHA-256)";
#endif

    QLabel *content = new QLabel(
        "【三步搞定授权】\n\n"
        "🔑 第1步：生成密钥（只需做一次）\n"
        "   ① 点击【密钥生成】标签\n"
        "   ② 点击【浏览...】选择保存文件夹\n"
        "   ③ 点击【生成密钥】按钮\n"
        "   → 会生成 sm2_private.pem、sm2_public.pem、sm4_key.bin 三个文件\n\n"
        "📄 第2步：生成授权文件（提供给用户）\n"
        "   ① 点击【授权文件生成】标签\n"
        "   ② 点击【浏览...】选择密钥文件夹\n"
        "   ③ 填写授权信息：版本号、" + idType + "、签发/到期日期\n"
                   "   ※ " + idType + " 格式: " + idExample + "\n"
                                             "   ④ 点击【浏览...】选择保存位置\n"
                                             "   ⑤ 点击【生成授权文件】\n"
                                             "   → 生成的 .lic 文件发给用户\n\n"
                                             "✅ 第3步：验证授权（测试生成的授权文件有效性）\n"
                                             "   ① 点击【授权文件验证】标签\n"
                                             "   ② 点击【浏览...】选择 .lic 文件\n"
                                             "   ③ 输入授权电脑的 " + idType + "\n"
                   "   ④ 点击【验证授权】\n"
                   "   → 绿色=有效，橙色=即将过期，红色=已过期"
        );
    content->setWordWrap(true);
    content->setStyleSheet("padding: 10px; line-height: 1.6;");
    layout->addWidget(content);
    layout->addStretch();

    return widget;
}

// 详细操作选项卡
QWidget* MainWindow::createOperationTab()
{
    QWidget *widget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(widget);

#ifdef USE_MAC_ADDRESS
    QString idType = "MAC地址";
    QString idHelp =
        "【如何查看MAC地址】\n\n"
        "🪟 Windows：\n"
        "   方法1：Win + R → 输入 cmd 回车 → 输入 ipconfig /all → 找\"物理地址\"\n"
        "   方法2：设置 → 网络和Internet → 查看网络属性 → 找\"物理地址(MAC)\"\n\n"
        "🐧 Linux：\n"
        "   方法1：终端输入 ip addr 或 ifconfig → 找 link/ether 后面的值\n"
        "   方法2：终端输入 cat /sys/class/net/eth0/address（eth0换成你的网卡名）\n\n"
        "💡 MAC地址格式示例：00-11-22-33-44-55 或 00:11:22:33:44:55\n\n";
#else
    QString idType = "机器唯一ID";
    QString idHelp =
        "【如何获取机器唯一ID】\n\n"
        "💡 机器唯一ID是基于硬件信息生成的 SHA-256 哈希值\n"
        "   • 自动采集 CPU、主板、硬盘、MAC 地址等硬件信息\n"
        "   • 同一台机器每次生成的 ID 都是相同的\n"
        "   • 不同机器的 ID 不同，可用于软件授权绑定\n\n"
        "🪟 Windows / 🐧 Linux / 🍎 macOS：\n"
        "   • 程序会自动获取当前机器的唯一ID\n"
        "   • 格式为 64 位十六进制字符串\n\n"
        "💡 机器唯一ID示例：\n"
        "   a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678\n\n";
#endif

    QLabel *content = new QLabel(
        idHelp +
        "════════════════════════════════════════\n\n"
        "【各页面说明】\n\n"
        "• 密钥生成 → 制作加密用的密钥，第一次使用必做\n"
        "• 授权文件生成 → 给用户制作授权文件\n"
        "• 授权文件验证 → 检查授权是否有效\n"
        "• 系统日志 → 查看操作记录，出问题时看红色错误\n\n"
        "════════════════════════════════════════\n\n"
        "💡 小贴士：\n"
        "• 密钥文件请妥善保管，不要丢失\n"
        "• 出问题先去【系统日志】看红色错误信息"
        );
    content->setWordWrap(true);
    content->setStyleSheet("padding: 10px; line-height: 1.6;");
    layout->addWidget(content);
    layout->addStretch();

    return widget;
}

// 常见问题选项卡
QWidget* MainWindow::createFaqTab()
{
    QWidget *widget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(widget);

    QScrollArea *scrollArea = new QScrollArea(widget);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget *contentWidget = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);

#ifdef USE_MAC_ADDRESS
    QString idType = "MAC地址";
#else
    QString idType = "机器唯一ID";
#endif

    QLabel *faq = new QLabel(
        "❓ 提示\"私钥文件不存在\"？\n"
        "   选错文件夹了，要选包含那3个密钥文件的文件夹\n\n"
        "❓ 提示\"" + idType + "不匹配\"？\n"
                   "   用户" + idType + "填错了，重新问正确的" + idType + "重新生成\n\n"
                                                               "❓ 授权已过期怎么办？\n"
                                                               "   重新生成一份有效期更长的授权文件\n\n"
                                                               "❓ 换电脑了怎么办？\n"
                                                               "   把密钥文件夹复制过去就行。密钥丢了的话，之前发的授权都失效\n\n"
                                                               "❓ 日志里都是红色错误看不懂？\n"
                                                               "   把日志内容复制下来，发给技术支持人员"
        );
    faq->setWordWrap(true);
    faq->setStyleSheet("padding: 10px; line-height: 1.8;");
    contentLayout->addWidget(faq);
    contentLayout->addStretch();

    scrollArea->setWidget(contentWidget);
    layout->addWidget(scrollArea);

    return widget;
}
