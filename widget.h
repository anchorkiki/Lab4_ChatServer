#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTcpServer>  // 服务器类（监听连接）
#include <QTcpSocket>  // 通信套接字类（和客户端通信）
#include <QList>       // 存储所有连接的客户端套接字
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

    QString formatClientIP(const QString &rawIP);

private slots:
    // 启动服务器按钮的点击事件（UI 设计器自动关联）
    void on_startBtn_clicked();

    // 新客户端连接的处理槽函数
    void on_new_client_connected();

    // 读取客户端发送的消息
    void read_client_message();

    // 客户端断开连接的处理
    void client_disconnected();

private:
    Ui::Widget *ui;
    QTcpServer *tcpServer;  // 服务器对象指针
    QList<QTcpSocket*> clientSockets;  // 存储所有已连接的客户端套接字
    QMap<QTcpSocket*, QString> clientUsers;  // 存储socket对应的用户名
};

#endif // WIDGET_H
