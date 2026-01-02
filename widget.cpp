#include "widget.h"
#include "ui_widget.h"
#include <QDateTime>
#include <QJsonArray>
Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    this->setWindowTitle("聊天服务器");  // 设置窗口标题

    // 初始化服务器对象（指定父对象，自动释放资源）
    tcpServer = new QTcpServer(this);

    // 关联“新客户端连接”信号到槽函数（有客户端连接时触发）
    connect(tcpServer, &QTcpServer::newConnection, this, &Widget::on_new_client_connected);
}

Widget::~Widget()
{
    delete ui;
}

// 启动服务器按钮点击事件
void Widget::on_startBtn_clicked()
{
    int port = 1234;  // 监听端口（自定义，1024-65535 之间，避免用 80、443 等常用端口）

    // 开始监听：监听所有网卡的 port 端口，允许最大连接数为 10（可调整）
    bool isListening = tcpServer->listen(QHostAddress::Any, port);

    if (isListening) {
        QString log = QString("[%1] 服务器启动成功 → 监听端口：%2")
                          .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                          .arg(port);
        ui->statusLabel->setText(QString("服务器状态：监听中（端口%1）").arg(port));
        ui->logTextEdit->append(log);
        ui->startBtn->setEnabled(false);
    } else {
        QString log = QString("[%1] 服务器启动失败 → 原因：%2")
                          .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                          .arg(tcpServer->errorString());
        ui->logTextEdit->append(log);
        ui->statusLabel->setText(QString("服务器状态：启动失败"));
    }
}

// 处理新客户端连接
void Widget::on_new_client_connected()
{
    // 获取新连接的客户端套接字（必须用 nextPendingConnection()）
    QTcpSocket *clientSocket = tcpServer->nextPendingConnection();

    // 将套接字添加到列表（管理多客户端）
    clientSockets.append(clientSocket);

    // 显示客户端连接状态（客户端的 IP 和端口）
    QString rawIP = clientSocket->peerAddress().toString();
    QString cleanIP = formatClientIP(rawIP); // 调用辅助函数清理IP
    QString clientInfo = QString("[%1] 客户端已连接 → %2:%3")
                             .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                             .arg(cleanIP)
                             .arg(clientSocket->peerPort());
    ui->logTextEdit->append(clientInfo);

    // 关联“客户端发消息”信号到槽函数（客户端发消息时触发）
    connect(clientSocket, &QTcpSocket::readyRead, this, &Widget::read_client_message);

    // 关联“客户端断开连接”信号到槽函数（客户端断开时触发）
    connect(clientSocket, &QTcpSocket::disconnected, this, &Widget::client_disconnected);
}

// 读取客户端消息
void Widget::read_client_message()
{
    QTcpSocket *senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) return;

    QByteArray messageData = senderSocket->readAll();

    // 解析 JSON
    QJsonParseError jsonError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(messageData, &jsonError);

    if (jsonError.error != QJsonParseError::NoError) {
        // ... 原有代码保持不变 ...
        return;
    }

    QJsonObject jsonObj = jsonDoc.object();

    // 获取消息类型
    QString messageType = jsonObj.value("type").toString();

    if (messageType == "message") {
        // ... 原有代码保持不变 ...

    } else if (messageType == "connect") {
        // 处理连接消息（客户端首次连接时发送）
        QString clientName = jsonObj.value("name").toString();
        QString rawIP = senderSocket->peerAddress().toString();
        QString cleanIP = formatClientIP(rawIP);

        // 如果没有指定用户名，使用IP
        if (clientName.isEmpty()) {
            clientName = cleanIP;
        }

        // 存储用户名
        clientUsers.insert(senderSocket, clientName);

        // 通知其他客户端有新用户加入
        QJsonObject notifyJson;
        notifyJson.insert("type", "user_join");
        notifyJson.insert("username", clientName);
        notifyJson.insert("time", QDateTime::currentDateTime().toString("HH:mm:ss"));

        // 添加当前在线用户列表
        QJsonArray userArray;
        for (QTcpSocket *socket : clientSockets) {
            if (clientUsers.contains(socket)) {
                userArray.append(clientUsers.value(socket));
            }
        }
        notifyJson.insert("userList", userArray);

        QJsonDocument notifyDoc(notifyJson);
        QByteArray notifyData = notifyDoc.toJson(QJsonDocument::Compact);

        for (QTcpSocket *socket : clientSockets) {
            if (socket != senderSocket && socket->state() == QTcpSocket::ConnectedState) {
                socket->write(notifyData);
            }
        }

        // 向新连接的用户发送当前在线用户列表
        QJsonObject userListJson;
        userListJson.insert("type", "user_list_update");
        userListJson.insert("userList", userArray);
        QJsonDocument userListDoc(userListJson);
        senderSocket->write(userListDoc.toJson(QJsonDocument::Compact));

    } else if (messageType == "disconnect") {
        // 处理断开连接消息（客户端正常断开时发送）
        // 类似上面的处理
    }
}

// 处理客户端断开连接
void Widget::client_disconnected()
{
    // 找到断开连接的客户端套接字
    QTcpSocket *disconnectedSocket = qobject_cast<QTcpSocket*>(sender());
    if (!disconnectedSocket) return;

    // 获取断开用户的用户名
    QString disconnectedUser = clientUsers.value(disconnectedSocket);
    QString rawIP = disconnectedSocket->peerAddress().toString();
    QString cleanIP = formatClientIP(rawIP);

    if (disconnectedUser.isEmpty()) {
        disconnectedUser = cleanIP;
    }

    // 显示断开状态
    QString clientInfo = QString("[%1] 客户端已断开 → %2:%3")
                             .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                             .arg(cleanIP)
                             .arg(disconnectedSocket->peerPort());
    ui->logTextEdit->append(clientInfo);

    // 从列表中移除套接字
    clientSockets.removeOne(disconnectedSocket);

    // 从用户映射中移除
    clientUsers.remove(disconnectedSocket);

    // 通知其他客户端有用户离开
    QJsonObject notifyJson;
    notifyJson.insert("type", "user_leave");
    notifyJson.insert("username", disconnectedUser);
    notifyJson.insert("time", QDateTime::currentDateTime().toString("HH:mm:ss"));

    // 添加更新后的在线用户列表
    QJsonArray userArray;
    for (QTcpSocket *socket : clientSockets) {
        if (clientUsers.contains(socket)) {
            userArray.append(clientUsers.value(socket));
        }
    }
    notifyJson.insert("userList", userArray);

    QJsonDocument notifyDoc(notifyJson);
    QByteArray notifyData = notifyDoc.toJson(QJsonDocument::Compact);

    for (QTcpSocket *socket : clientSockets) {
        if (socket->state() == QTcpSocket::ConnectedState) {
            socket->write(notifyData);
        }
    }

    // 释放资源
    disconnectedSocket->deleteLater();
}


QString Widget::formatClientIP(const QString &rawIP)
{
    QString cleanIP = rawIP;
    // 移除IPv4映射IPv6的冗余前缀
    if (cleanIP.startsWith("::ffff:")) {
        cleanIP = cleanIP.remove("::ffff:");
    }
    // 处理纯IPv6的localhost（可选，根据需求）
    if (cleanIP == "::1") {
        cleanIP = "127.0.0.1";
    }
    return cleanIP;
}
