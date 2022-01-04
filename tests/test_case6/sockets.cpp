#include "sockets.h"

#pragma comment(lib,"Ws2_32.lib")
#include <iostream>

bool switch_state(char *buf, char *resp)
{
    switch (resp[0]) {
    case 0:
        if (buf[0] != '9') break;
        resp[0] = 'Y';
        return true;
    case 'Y':
        if (buf[0] != '3') break;
        resp[0] = 'E';
        return true;
    case 'E':
        if (buf[0] != '5') break;
        resp[0] = 'S';
        return true;
    default:
        resp[0] = 0; break;
    }
    return false;
}

bool listen_for_connect(char buf[CONN_BUF_SIZE], int port)
{
    bool got_resp = false;
    static char resp[4] = { 0 };
    WSADATA wsaData = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    struct sockaddr_in sock_config = { 0 };

    SOCKET listen_socket = 0;
    if ((listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        std::cerr << "Creating the socket failed!\n";
        WSACleanup();
        return false;
    }
    sock_config.sin_family = AF_INET;
    const char *localhost = "127.0.0.1";
    sock_config.sin_addr.s_addr = inet_addr(localhost);
    sock_config.sin_port = htons(port);

    if (bind(listen_socket, (SOCKADDR*)&sock_config, sizeof(sock_config)) != SOCKET_ERROR
        && listen(listen_socket, SOMAXCONN) != SOCKET_ERROR
        )
    {
        std::cout << "The socket is listening...\n";
        SOCKET conn_sock = SOCKET_ERROR;
        while ((conn_sock = accept(listen_socket, 0, 0)) != SOCKET_ERROR) {
            if (recv(conn_sock, buf, CONN_BUF_SIZE, 0) > 0) {
                got_resp = true;
                if (switch_state(buf, resp)) {
                    send(conn_sock, resp, CONN_BUF_SIZE, 0);
                    closesocket(conn_sock);
                    break;
                }
            }
            closesocket(conn_sock);
        }
    }
    else {
        std::cerr << "Binding the socket failed!\n";
    }
    closesocket(listen_socket);
    WSACleanup();
    return got_resp;
}
