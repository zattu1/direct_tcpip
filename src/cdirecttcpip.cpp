#include "cdirecttcpip.h"
#include <QDebug>

#define BUFFER_LEN 16384

CDirectTcpip::CDirectTcpip()
{
    qDebug() << Q_FUNC_INFO;
}

CDirectTcpip::~CDirectTcpip()
{
    m_Loop = false;
}

void CDirectTcpip::onStarted()
{
    do {
        do {
            if(!connectRemote()) {
                msleep(5000);
                break;
            }
            if(!sshInitialize()) {
                msleep(5000);
                break;
            }
            if(!connectSsh()) {
                msleep(5000);
                break;
            }
            forwardPacket();
        }while(0);

        freeSession();

    }while(m_Loop);
}

bool CDirectTcpip::connectRemote()
{
    qDebug() << Q_FUNC_INFO;
    m_nSocket = socket(ai_family, ai_socktype, ai_protocol);
    if(m_nSocket == -1) {
        qWarning() << "socket create error:" << m_nSocket;
        return false;
    }
    int rc = ::connect(m_nSocket, &ai_addr, ai_addrlen);
    if(rc == -1) {
        qWarning() << "connect error:" << rc;
        return false;
    }

    return true;
}

bool CDirectTcpip::sshInitialize()
{
    qDebug() << Q_FUNC_INFO;
    int i, auth = AUTH_NONE;
    int rc;
    const char *fingerprint;
    char *userauthlist;

    /* Create a session instance */
    m_session = libssh2_session_init();
    if(!m_session) {
        qWarning() << "Could not initialize SSH session!";
    }
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(m_session, m_nSocket);
    if(rc) {
        qWarning() <<  "Error when starting up SSH session:" << rc;
        return false;
    }

    /* At this point we have not yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(m_session, LIBSSH2_HOSTKEY_HASH_SHA1);
    QString str;
    str = "Fingerprint: ";
    for(i = 0; i < 20; i++)
        str += QString("%1 ").arg((uchar)fingerprint[i], 2, 16, QChar('0'));
    qDebug() << str;

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(m_session, m_strUserName.toStdString().c_str(),
                                         (unsigned int)m_strUserName.length());
    if(userauthlist) {
        qDebug() << "Authentication methods:" << userauthlist;
        if(strstr(userauthlist, "password"))
            auth |= AUTH_PASSWORD;
        if(strstr(userauthlist, "publickey"))
            auth |= AUTH_PUBLICKEY;

        /* check for options */
        if(!m_strUserName.isEmpty()) {
            if((auth & AUTH_PASSWORD) && !m_bIsPrivateKey)
                auth = AUTH_PASSWORD;
            if((auth & AUTH_PUBLICKEY) && m_bIsPrivateKey)
                auth = AUTH_PUBLICKEY;
        }

        if(auth & AUTH_PASSWORD) {
            if(libssh2_userauth_password(m_session,
                                          m_strUserName.toStdString().c_str(),
                                          m_strPassword.toStdString().c_str())) {
                qWarning() << "Authentication by password failed!";
                return false;
            }
        }
        else if(auth & AUTH_PUBLICKEY) {
            if(libssh2_userauth_publickey_fromfile(m_session,
                                                    m_strUserName.toStdString().c_str(),
                                                    m_strPublicKeyPath.toStdString().c_str(),
                                                    m_strPrivateKeyPath.toStdString().c_str(),
                                                    m_strPassword.toStdString().c_str())) {
                qWarning() << "Authentication by public key failed!";
                return false;
            }
            else {
                qDebug() << "Authentication by public key succeeded.";
            }
        }
        else {
            qWarning() << "No supported authentication methods found!";
            return false;
        }
    }
    return true;
}

bool CDirectTcpip::connectSsh()
{
    qDebug() << Q_FUNC_INFO;
    m_listensock = socket(PF_INET, SOCK_STREAM, 0);
    if(m_listensock == LIBSSH2_INVALID_SOCKET) {
        qWarning() << "failed to open listen socket!";
        return false;
    }
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons((unsigned short)m_nLocalListenPort);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(INADDR_NONE == sin.sin_addr.s_addr) {
        qWarning() << "failed in inet_addr()!";
        return false;
    }
    char sockopt = 1;
    setsockopt(m_listensock, SOL_SOCKET, SO_REUSEADDR, &sockopt,
               sizeof(sockopt));
    int sinlen = sizeof(sin);
    if(-1 == bind(m_listensock, (struct sockaddr *)&sin, sinlen)) {
        qWarning() << "failed to bind()!";
        return false;
    }
    if(-1 == listen(m_listensock, 2)) {
        qWarning() << "failed to listen()!";
        return false;
    }

    qDebug() << QString("Waiting for TCP connection on %1:%2...")
                    .arg(inet_ntoa(sin.sin_addr)).arg(ntohs(sin.sin_port));

    m_forwardsock = ::accept(m_listensock, (struct sockaddr *)&sin, &sinlen);
    if(m_forwardsock == LIBSSH2_INVALID_SOCKET) {
        qWarning() << "failed to accept forward socket!";
        return false;
    }

    m_pLocalHost = inet_ntoa(sin.sin_addr);
    m_nLocalPort = ntohs(sin.sin_port);

    qDebug() << QString("Forwarding connection from %1:%2 here to remote %3:%4")
                    .arg(m_pLocalHost).arg(m_nLocalPort)
                    .arg(m_strRemoteDestHost).arg(m_nRemoteDestPort);

    m_channel = libssh2_channel_direct_tcpip_ex(m_session,
                                                m_strRemoteDestHost.toStdString().c_str(),
                                                m_nRemoteDestPort,
                                                m_pLocalHost,
                                                m_nLocalPort);
    if(!m_channel) {
        qWarning() << "Could not open the direct-tcpip channel!\n"
                      "(Note that this can be a problem at the server!\n"
                      " Please review the server logs.)\n";
        return false;
    }

    /* Must use non-blocking IO hereafter due to the current libssh2 API */
    libssh2_session_set_blocking(m_session, 0);

    return true;
}

bool CDirectTcpip::forwardPacket()
{
    qDebug() << Q_FUNC_INFO;
    int rc;
    fd_set fds;
    struct timeval tv;
    ssize_t len, wr;
    m_pBuffer = new char[BUFFER_LEN];
    for(;;) {
        FD_ZERO(&fds);
        FD_SET(m_forwardsock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        rc = select((int)(m_forwardsock + 1), &fds, NULL, NULL, &tv);
        if(-1 == rc) {
            qWarning() << "failed to select()!";
            return false;
        }
        if(rc && FD_ISSET(m_forwardsock, &fds)) {
            len = recv(m_forwardsock, m_pBuffer, BUFFER_LEN, 0);
            if(len < 0) {
                qWarning() << "failed to recv()!";
                return false;
            }
            else if(len == 0) {
                qWarning() << QString("The client at %1:%2 disconnected!").arg(m_pLocalHost).arg(m_nLocalPort);
                return false;
            }
            qDebug() << "forward read:" << len;
            wr = 0;
            while(wr < len) {
                ssize_t nwritten = libssh2_channel_write(m_channel,
                                                         m_pBuffer + wr, len - wr);
                if(nwritten == LIBSSH2_ERROR_EAGAIN) {
                    continue;
                }
                if(nwritten < 0) {
                    qWarning() << "libssh2_channel_write:" << nwritten;
                    return false;
                }
                wr += nwritten;
            }
        }
        for(;;) {
            len = libssh2_channel_read(m_channel, m_pBuffer, BUFFER_LEN);
            if(LIBSSH2_ERROR_EAGAIN == len)
                break;
            else if(len < 0) {
                qWarning() << "libssh2_channel_read:" << len;
                return false;
            }
            qDebug() << "libssh2 read:" << len;
            wr = 0;
            while(wr < len) {
                ssize_t nsent = send(m_forwardsock, m_pBuffer + wr, len - wr, 0);
                if(nsent <= 0) {
                    qWarning() << "failed to send()!";
                    return false;
                }
                wr += nsent;
            }
            if(libssh2_channel_eof(m_channel)) {
                qDebug() << QString("The server at %1:%2 disconnected!")
                                .arg(m_strRemoteDestHost).arg(m_nRemoteDestPort);
                return false;
            }
        }
    }
    return true;
}

void CDirectTcpip::freeSession()
{
    qDebug() << Q_FUNC_INFO;
    if(m_pBuffer) {
        delete[] m_pBuffer;
        m_pBuffer = nullptr;
    }
    if(m_forwardsock != LIBSSH2_INVALID_SOCKET) {
        shutdown(m_forwardsock, 2);
        closesocket(m_forwardsock);
        m_forwardsock = LIBSSH2_INVALID_SOCKET;
    }
    if(m_listensock != -1) {
        shutdown(m_listensock, 2);
        closesocket(m_listensock);
        m_listensock = -1;
    }
    if(m_channel) {
        libssh2_channel_free(m_channel);
        m_channel = nullptr;
    }
    if(m_session) {
        libssh2_session_disconnect(m_session, "Normal Shutdown");
        libssh2_session_free(m_session);
        m_session = nullptr;
    }
    if(m_nSocket > 0) {
        shutdown(m_nSocket, 2);
        closesocket(m_nSocket);
        m_nSocket = -1;
    }
}
