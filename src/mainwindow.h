// mainwindow.h
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

// SM2 签名密钥密码（固定）
#define SM2_SIGNI_KEY_PASSWORD "123456781234578"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // 密钥管理标签页
    void onGenerateKeysClicked(); //生成密钥
    void onBrowseKeyDirClicked(); //生成密钥路径

    // 授权生成标签页
    void onCreateLicenseClicked(); //生成授权文件
    void onBrowseLicenseOutputClicked(); //授权文件路径
    void onBrowseLicKeyDirClicked();

    // 授权验证标签页
    void onVerifyLicenseClicked(); //验证授权文件
    void onBrowseLicenseFileClicked(); //授权文件路径

    // 日志标签页
    void onClearLogClicked(); //清空日志
    void onExportLogClicked();// 导出日志
    void onLogLevelChanged(int index); //日志等级

    // 通用
    void updateStatusBar();//时间
    void showAbout(); //版本信息
    void showConfigDialog(); //配置信息
    void showhelp();

    bool checkKeysExist(const QString &dirPath); //密钥查询
    bool confirmOverwrite(const QString &dirPath); //文件覆盖检查
    void clearValidationFields();// 清空验证字段
    void showKeyConfigDialog(); //密钥配置界面

private:
    Ui::MainWindow *ui;

    void setupUI(); //界面初始化
    void loadConfig(); //配置文件初始化

    // 提示框
    void showMessage(const QString &message, bool isError = false);

    // ===== 根据宏定义的标识符处理函数 =====

    // 获取当前机器的标识符
    QString getCurrentIdentifier();

    // 验证标识符格式
    bool validateIdentifier(const QString &identifier);

    // 获取标识符的标签文本
    QString getIdentifierLabel();

    // 获取标识符的占位提示文本
    QString getIdentifierPlaceholder();

    // MAC 地址相关（仅在 MAC 地址模式下使用）
    QString normalizeMacAddress(const QString &mac);

    // 帮助对话框的辅助函数
    QWidget* createQuickStartTab();
    QWidget* createOperationTab();
    QWidget* createFaqTab();
};

#endif // MAINWINDOW_H
