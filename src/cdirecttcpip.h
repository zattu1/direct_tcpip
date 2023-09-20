#ifndef CDIRECTTCPIP_H
#define CDIRECTTCPIP_H

#include <QObject>
#include <QEventLoop>
#include <QTimer>
#include "libssh2.h"

#include <WinSock2.h>
#include <ws2tcpip.h>  /* for socklen_t */
#define recv(s, b, l, f)  recv((s), (b), (int)(l), (f))
#define send(s, b, l, f)  send((s), (b), (int)(l), (f))

class CDirectTcpip : public QObject
{
    Q_OBJECT
public:
    enum {
        AUTH_NONE = 0,
        AUTH_PASSWORD = 1,
        AUTH_PUBLICKEY = 2
    };
    CDirectTcpip();
    ~CDirectTcpip();

    QString m_strServerName;
    QString m_strUserName;
    QString m_strPassword;
    QString m_strRemoteDestHost;
    QString m_strPrivateKeyPath;
    QString m_strPublicKeyPath;
    int m_nLocalListenPort = 0;
    int m_nRemoteDestPort = 0;
    int m_nSocket = -1;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    struct sockaddr ai_addr;
    ulong ai_addrlen;
    bool m_bIsPrivateKey = false;

signals:
    void finished();

public slots:
    void onStarted();

private:
    bool connectRemote();
    bool sshInitialize();
    bool connectSsh();
    bool forwardPacket();
    void freeSession();
    void msleep(int msec) {
        QEventLoop loop;
        QTimer::singleShot(msec, &loop, SLOT(quit()));
        loop.exec();
    }

    LIBSSH2_SESSION *m_session = nullptr;
    LIBSSH2_CHANNEL *m_channel = nullptr;
    libssh2_socket_t m_forwardsock;
    char *m_pLocalHost;
    uint m_nLocalPort;
    int m_listensock = -1;
    char *m_pBuffer = nullptr;
    bool m_Loop = true;
};

#endif // CDIRECTTCPIP_H
