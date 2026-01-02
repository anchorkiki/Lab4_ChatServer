#include "widget.h"
#include "ui_widget.h"
#include <QDateTime>
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

// 读取客户端消息并广播
void Widget::read_client_message()
{
    // 找到发送消息的客户端套接字（sender() 返回触发信号的对象）
    QTcpSocket *senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) return;  // 防止空指针

    // 读取消息（QTcpSocket 用 readAll() 读取所有可用数据）
    QByteArray messageData = senderSocket->readAll();
    QString message = QString::fromUtf8(messageData);  // 转换为 UTF-8 字符串（避免乱码）

    // 拼接消息（包含发送者的 IP 和端口）
    QString rawIP = senderSocket->peerAddress().toString();
    QString cleanIP = formatClientIP(rawIP);
    // 拼接广播消息（简洁格式）
    QString broadcastMessage = QString("[%1:%2] %3")
                                   .arg(cleanIP)
                                   .arg(senderSocket->peerPort())
                                   .arg(message);

    // 广播消息：遍历所有客户端，发送消息
    for (QTcpSocket *socket : clientSockets) {
        if (socket == senderSocket) {
            continue; // 跳过当前发送者，不发送给自己
        }

        // 只有客户端处于“已连接”状态才发送
        if (socket->state() == QTcpSocket::ConnectedState) {
            socket->write(broadcastMessage.toUtf8());  // 转换为字节数组发送
        }
    }

    // 更新服务器状态（显示最新消息）
    QString log = QString("[%1] 转发消息 → %2")
                      .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                      .arg(broadcastMessage);
    ui->logTextEdit->append(log);
}

// 处理客户端断开连接
void Widget::client_disconnected()
{
    // 找到断开连接的客户端套接字
    QTcpSocket *disconnectedSocket = qobject_cast<QTcpSocket*>(sender());
    if (!disconnectedSocket) return;

    // 显示断开状态
    QString rawIP = disconnectedSocket->peerAddress().toString();
    QString cleanIP = formatClientIP(rawIP);
    QString clientInfo = QString("[%1] 客户端已断开 → %2:%3")
                             .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                             .arg(cleanIP)
                             .arg(disconnectedSocket->peerPort());
    ui->logTextEdit->append(clientInfo);
    // 从列表中移除套接字，并释放资源
    clientSockets.removeOne(disconnectedSocket);
    disconnectedSocket->deleteLater();  // 延迟释放，避免野指针
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
