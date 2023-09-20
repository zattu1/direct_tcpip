#include <QCoreApplication>
#include <QThread>
#include "cdirecttcpip.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if(argc != 9 && argc != 11)
        return -1;

    WSADATA wsadata;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if(rc) {
        qWarning() << "WSAStartup failed with error:" << rc;
        return -1;
    }
    rc = libssh2_init(0);
    if(rc) {
        qWarning() << "libssh2 initialization failed" << rc;
        return -1;
    }

    CDirectTcpip *directTcpip = new CDirectTcpip;
    directTcpip->m_nLocalListenPort = atoi(argv[3]);
    directTcpip->m_strRemoteDestHost = argv[4];
    directTcpip->m_nRemoteDestPort = atoi(argv[5]);
    directTcpip->m_bIsPrivateKey = !strcmp(argv[6], "-p")? false: !strcmp(argv[6], "-k")? true: false;
    directTcpip->m_strUserName = argv[7];
    directTcpip->m_strPassword = argv[8];
    if(argc > 10) {
        directTcpip->m_strPrivateKeyPath = argv[9];
        directTcpip->m_strPublicKeyPath = argv[10];
    }
    int nRet = 0;
    do {
        struct addrinfo *result = nullptr;
        struct addrinfo *ptr = nullptr;
        struct addrinfo hints;
        struct sockaddr_in  *sockaddr_ipv4;
        LPSOCKADDR sockaddr_ip;
        TCHAR ipstringbuffer[46];
        DWORD ipbufferlength = 46;
        char numericname[INET6_ADDRSTRLEN] = { 0 };

        ZeroMemory( &hints, sizeof(hints) );
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        int iRetval = getaddrinfo(argv[1], argv[2], &hints, &result);
        if( iRetval != 0 ) {
            qWarning() << "getaddrinfo failed with error:" << iRetval;
            break;
        }
        int i = 1;
        // Retrieve each address and print out the hex bytes
        for(ptr=result; ptr != nullptr ; ptr=ptr->ai_next) {
            qDebug() << "getaddrinfo response" << i++;
            qDebug() << "\tFlags:" << ptr->ai_flags;
            qDebug() << "\tFamily:";
            switch (ptr->ai_family) {
            case AF_UNSPEC:
                qDebug() << "Unspecified";
                break;
            case AF_INET:
                qDebug() << "AF_INET (IPv4)";
                sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
                qDebug() << "\tIPv4 address " <<
                    inet_ntop(ptr->ai_family, (void *)&sockaddr_ipv4->sin_addr, numericname, sizeof(numericname));
                goto loop_end;
            case AF_INET6:
                qDebug() << "AF_INET6 (IPv6)";
                // the InetNtop function is available on Windows Vista and later
                // sockaddr_ipv6 = (struct sockaddr_in6 *) ptr->ai_addr;
                // printf("\tIPv6 address %s\n",
                //    InetNtop(AF_INET6, &sockaddr_ipv6->sin6_addr, ipstringbuffer, 46) );

                // We use WSAAddressToString since it is supported on Windows XP and later
                sockaddr_ip = (LPSOCKADDR) ptr->ai_addr;
                // The buffer length is changed by each call to WSAAddresstoString
                // So we need to set it for each iteration through the loop for safety
                ipbufferlength = 46;
                iRetval = WSAAddressToString(sockaddr_ip, (DWORD) ptr->ai_addrlen, NULL,
                                             ipstringbuffer, &ipbufferlength );
                if (iRetval)
                    qDebug() << "WSAAddressToString failed with" << WSAGetLastError();
                else
                    qDebug() << "\tIPv6 address" << ipstringbuffer;
                break;
            case AF_NETBIOS:
                qDebug() << "AF_NETBIOS (NetBIOS)";
                break;
            default:
                qDebug() << "Other" << ptr->ai_family;
                break;
            }
        }
loop_end:
        if(ptr) {
            if(ptr->ai_family != AF_INET)   // IPv4のみ
                break;
            directTcpip->ai_family = ptr->ai_family;
            directTcpip->ai_socktype = ptr->ai_socktype;
            directTcpip->ai_protocol = ptr->ai_protocol;
            memcpy(&directTcpip->ai_addr, ptr->ai_addr, sizeof(directTcpip->ai_addr));
            directTcpip->ai_addrlen = ptr->ai_addrlen;
            freeaddrinfo(result);

            QThread *thread = new QThread;
            directTcpip->moveToThread(thread);
            QObject::connect(thread, SIGNAL(started()), directTcpip, SLOT(onStarted()));
            QObject::connect(directTcpip, SIGNAL(finished()), thread, SLOT(quit()));
            QObject::connect(directTcpip, SIGNAL(finished()), thread, SLOT(deleteLater()));
            thread->start();
            nRet = a.exec();
            emit directTcpip->finished();
        }
    }while(0);

    WSACleanup();
    libssh2_exit();
    directTcpip->deleteLater();
    return nRet;
}
