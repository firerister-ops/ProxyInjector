// test_client.cpp — simple TCP test client with delay for DLL injection
// Usage: test_client.exe [delay_sec] [host] [port]
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char* argv[]) {
    int delay = argc > 1 ? atoi(argv[1]) : 3;
    const char* host = argc > 2 ? argv[2] : "api.ipify.org";
    int port = argc > 3 ? atoi(argv[3]) : 80;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    printf("[test_client] PID=%lu — sleeping %d sec for DLL injection\n", GetCurrentProcessId(), delay);
    fflush(stdout);
    Sleep(delay * 1000);

    printf("[test_client] Resolving %s:%d...\n", host, port);
    addrinfo hints = {}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = NULL;
    if (getaddrinfo(host, "80", &hints, &ai) != 0) {
        printf("[test_client] DNS FAILED\n"); return 1;
    }
    char resolvedIP[64] = {0};
    inet_ntop(AF_INET, &((sockaddr_in*)ai->ai_addr)->sin_addr, resolvedIP, sizeof(resolvedIP));
    printf("[test_client] Resolved to %s\n", resolvedIP);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { printf("[test_client] socket FAILED\n"); return 1; }

    printf("[test_client] Calling connect()...\n");
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) != 0) {
        printf("[test_client] connect FAILED err=%d\n", WSAGetLastError());
        return 1;
    }
    printf("[test_client] CONNECTED!\n");

    const char* req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: test_client/1.0\r\nConnection: close\r\n\r\n";
    send(s, req, (int)strlen(req), 0);

    char buf[8192] = {0};
    int total = 0, n;
    while ((n = recv(s, buf + total, sizeof(buf) - total - 1, 0)) > 0) total += n;
    buf[total] = 0;
    printf("[test_client] Received %d bytes\n%s\n", total, buf);

    closesocket(s);
    freeaddrinfo(ai);
    WSACleanup();
    printf("[test_client] DONE\n");
    return 0;
}
