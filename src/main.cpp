#include "mainwindow.h"
#include "logmanager.h"
#include "configmanager.h"
#include <QApplication>
#include <QStyleFactory>
#include <QTextCodec>
#include <QDir>
#include <QDebug>

int main(int argc, char *argv[])
{
    // 设置UTF-8编码
    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::setCodecForLocale(codec);

    QApplication a(argc, argv);

    // 设置应用程序信息
    QApplication::setApplicationName("国密授权管理系统");
    QApplication::setApplicationVersion("1.0");

    // 设置字体
    QFont font;
    font.setFamily("Microsoft YaHei");
    font.setPointSize(10);
    a.setFont(font);


    LOG_INFO("SYSTEM", "========================================");
    LOG_INFO("SYSTEM", "国密授权管理系统启动");
    LOG_INFO("SYSTEM", QString("版本: %1").arg(QApplication::applicationVersion()));
    LOG_INFO("SYSTEM", "========================================");

    // 创建并显示主窗口
    MainWindow w;
    w.show();


    return a.exec();
}
