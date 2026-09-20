// ProxyPayload v2 — Clean SOCKS5 proxy routing via inline hooks
//
// ARCHITECTURE (based on runetfreedom/force-proxy):
//   1. Hook connect() — redirect TCP through SOCKS5
//   2. Hook bind/sendto/recvfrom/WSASendTo/WSARecvFrom — UDP via SOCKS5 UDP ASSOCIATE
//   3. Hook ioctlsocket/WSAEventSelect — track non-blocking sockets
//   4. Hook closesocket — cleanup
//
// KEY INSIGHT: Chrome uses regular connect() (confirmed in Chromium source
// tcp_socket_win.cc), so the game tunnels through the ws2_32 connect hook.
// .NET applications (DreamPoeBot) perform async connects through ConnectEx and
// may resolve it directly from mswsock via GetProcAddress — so ConnectEx is
// hooked INLINE at mswsock (covers WSAIoctl queries, GetProcAddress, and static
// imports) and routed through SOCKS5 with synchronous overlapped completion.
//
// SOCKS5 negotiation is bounded and completes synchronously. A non-blocking
// connect may therefore complete immediately and returns success; unsupported
// overlapped paths fail closed instead of fabricating completion notifications.
//
// Config: reads ABF_PROXY_CONFIG_PATH, or proxy_config.txt next to the DLL for late injection.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <algorithm>
#include <limits>

#include "minhook/MinHook.h"

// ============================================================================
// Config
// ============================================================================
struct ProxyConfig {
    char socks5Host[64];
    uint16_t socks5Port;
    char socks5User[128];
    char socks5Pass[128];
    BOOL enabled;
    int timeoutSec;
    // When non-empty, My_CreateProcessInternalW rewrites any spawned child's
    // `--language <X>` argument to this value. Used to force the PoE game client
    // to a fixed language regardless of the OS locale (the launcher otherwise
    // passes `--language <system-locale>`, which overrides the account setting
    // for the whole session). Example: "en".
    char languageOverride[8];
};

static ProxyConfig g_config = { "", 0, "", "", FALSE, 3, "" };
static wchar_t g_dllPath[MAX_PATH] = {0};
static HANDLE g_readyEvent = NULL;

// ============================================================================
// Logging
// ============================================================================
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;
static char g_logDir[MAX_PATH] = {0};  // directory holding log files (no trailing separator)

static void Log(const char* fmt, ...) {
    if (!g_logFile) return;
    EnterCriticalSection(&g_logLock);
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "[%02d:%02d:%02d.%03d][PID=%lu] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentProcessId());
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
    LeaveCriticalSection(&g_logLock);
}

// ============================================================================
// Original function pointers
// ============================================================================
typedef int (WINAPI *pfn_connect)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *pfn_bind)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *pfn_closesocket)(SOCKET);
typedef int (WINAPI *pfn_send)(SOCKET, const char*, int, int);
typedef int (WINAPI *pfn_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *pfn_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WINAPI *pfn_recvfrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WINAPI *pfn_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *pfn_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *pfn_WSAEventSelect)(SOCKET, WSAEVENT, long);
typedef int (WSAAPI *pfn_WSAAsyncSelect)(SOCKET, HWND, unsigned int, long);
typedef int (WSAAPI *pfn_ioctlsocket)(SOCKET, long, u_long*);
typedef int (WINAPI *pfn_WSAConnect)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef INT (WINAPI *pfn_WSAConnectByNameW)(SOCKET, LPCWSTR, LPCWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, LPTIMEVAL, LPOVERLAPPED);
typedef INT (WINAPI *pfn_WSAConnectByNameA)(SOCKET, PCSTR, PCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, LPTIMEVAL, LPOVERLAPPED);
typedef INT (WINAPI *pfn_WSAConnectByList)(SOCKET, PSOCKET_ADDRESS_LIST, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, LPTIMEVAL, LPOVERLAPPED);
typedef int (WINAPI *pfn_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *pfn_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WINAPI *pfn_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef struct hostent* (WINAPI *pfn_gethostbyname)(const char*);
typedef SOCKET (WINAPI *pfn_socket)(int, int, int);
typedef BOOL (WINAPI *pfn_CreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION, PHANDLE);

// ConnectEx extension function pointer type
typedef BOOL (PASCAL *pfn_ConnectEx)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);

// ConnectEx GUID (official WSAID_CONNECTEX from MSWSock.h)
static const GUID g_WSAID_CONNECTEX = {
    0x25a207b9, 0xddf3, 0x4660,
    {0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}
};

static pfn_connect g_orig_connect = NULL;
static pfn_bind g_orig_bind = NULL;
static pfn_closesocket g_orig_closesocket = NULL;
static pfn_send g_orig_send = NULL;
static pfn_WSASend g_orig_WSASend = NULL;
static pfn_sendto g_orig_sendto = NULL;
static pfn_recvfrom g_orig_recvfrom = NULL;
static pfn_WSASendTo g_orig_WSASendTo = NULL;
static pfn_WSARecvFrom g_orig_WSARecvFrom = NULL;
static pfn_WSAEventSelect g_orig_WSAEventSelect = NULL;
static pfn_WSAAsyncSelect g_orig_WSAAsyncSelect = NULL;
static pfn_ioctlsocket g_orig_ioctlsocket = NULL;
static pfn_WSAConnect g_orig_WSAConnect = NULL;
static pfn_WSAConnectByNameW g_orig_WSAConnectByNameW = NULL;
static pfn_WSAConnectByNameA g_orig_WSAConnectByNameA = NULL;
static pfn_WSAConnectByList g_orig_WSAConnectByList = NULL;
static pfn_getaddrinfo g_orig_getaddrinfo = NULL;
static pfn_GetAddrInfoW g_orig_GetAddrInfoW = NULL;
static pfn_gethostbyname g_orig_gethostbyname = NULL;
static pfn_socket g_orig_socket = NULL;
// Trampoline to the real mswsock!ConnectEx (inline hook target)
static pfn_ConnectEx g_orig_ConnectEx = NULL;
static pfn_CreateProcessInternalW g_orig_CreateProcessInternalW = NULL;

// ============================================================================
// Non-blocking socket tracking + UDP association map
// ============================================================================
static std::shared_mutex g_socketsMutex;
static std::map<SOCKET, long> g_nonBlockingSockets;  // socket -> network events

// UDP association: each UDP socket has a dedicated TCP control socket to proxy
struct UdpAssoc {
    SOCKET proxySock;            // TCP socket to proxy (for UDP ASSOCIATE)
    sockaddr_storage udpProxyAddr;
    int udpProxyAddrLen;

    UdpAssoc() : proxySock(INVALID_SOCKET), udpProxyAddr(), udpProxyAddrLen(0) {}
    ~UdpAssoc() {
        if (proxySock != INVALID_SOCKET && g_orig_closesocket) {
            g_orig_closesocket(proxySock);
            proxySock = INVALID_SOCKET;
        }
    }
};
static std::map<SOCKET, std::shared_ptr<UdpAssoc>> g_udpAssocMap;

static bool IsNonBlocking(SOCKET s) {
    std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
    return g_nonBlockingSockets.count(s) > 0;
}

static void MarkNonBlocking(SOCKET s, long events) {
    std::unique_lock<std::shared_mutex> lock(g_socketsMutex);
    if (events != 0) g_nonBlockingSockets[s] = events;
    else g_nonBlockingSockets.erase(s);
}

static void UntrackSocket(SOCKET s) {
    std::shared_ptr<UdpAssoc> association;
    {
        std::unique_lock<std::shared_mutex> lock(g_socketsMutex);
        g_nonBlockingSockets.erase(s);
        auto it = g_udpAssocMap.find(s);
        if (it != g_udpAssocMap.end()) {
            association = it->second;
            g_udpAssocMap.erase(it);
        }
    }
}

static bool IsUdpSocket(SOCKET s) {
    int t = 0;
    int len = sizeof(t);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&t, &len) != 0) return false;
    return t == SOCK_DGRAM;
}

// ============================================================================
// Dummy IP ↔ Hostname mapping (DNS leak prevention)
//
// DNS hooks return fake IPs in 240.x.x.x range. connect() detects dummy IP,
// looks up original hostname, sends SOCKS5 CONNECT with ATYP=0x03 (domain).
// The proxy resolves the hostname — ISP DNS is never queried.
// ============================================================================
#define DUMMY_IP_BASE 0xC6120000u  // 198.18.0.0 host-order (RFC 2544 benchmarking range)
#define DUMMY_IP_MASK 0x0000FFFFu

struct DummyEntry {
    uint32_t netOrderIp;     // stored as network order for direct compare
    char hostname[256];
    uint16_t port;
    bool used;
};
#define DUMMY_HASH_SIZE 1024
static DummyEntry g_dummyTable[DUMMY_HASH_SIZE];
static CRITICAL_SECTION g_dummyLock;

static uint32_t HashStr(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}

static BOOL IsDummyIp(uint32_t netOrderIp) {
    return (ntohl(netOrderIp) >> 16) == (DUMMY_IP_BASE >> 16);  // 198.18.x.x
}

static BOOL IsNumericIp(const char* s) {
    if (!s || !*s) return FALSE;
    IN_ADDR v4 = {};
    IN6_ADDR v6 = {};
    return InetPtonA(AF_INET, s, &v4) == 1 || InetPtonA(AF_INET6, s, &v6) == 1;
}

static BOOL IsLoopbackHostname(const char* s) {
    return s && _stricmp(s, "localhost") == 0;
}

// Store hostname → collision-free dummy IP. Returns false when the bounded table is full.
static bool StoreDummy(const char* hostname, uint16_t port, uint32_t* outNetIp) {
    if (!hostname || !*hostname || !outNetIp) return false;
    uint32_t h = HashStr(hostname);
    EnterCriticalSection(&g_dummyLock);
    uint32_t idx = h % DUMMY_HASH_SIZE;
    for (uint32_t i = 0; i < DUMMY_HASH_SIZE; i++) {
        uint32_t s = (idx + i) % DUMMY_HASH_SIZE;
        if (g_dummyTable[s].used && _stricmp(g_dummyTable[s].hostname, hostname) == 0) {
            if (port != 0) g_dummyTable[s].port = port;
            *outNetIp = g_dummyTable[s].netOrderIp;
            LeaveCriticalSection(&g_dummyLock);
            return true;
        }
        if (!g_dummyTable[s].used) {
            g_dummyTable[s].netOrderIp = htonl(DUMMY_IP_BASE | ((s + 1) & DUMMY_IP_MASK));
            strncpy(g_dummyTable[s].hostname, hostname, 255);
            g_dummyTable[s].hostname[255] = 0;
            g_dummyTable[s].port = port;
            g_dummyTable[s].used = true;
            *outNetIp = g_dummyTable[s].netOrderIp;
            LeaveCriticalSection(&g_dummyLock);
            return true;
        }
    }
    LeaveCriticalSection(&g_dummyLock);
    return false;
}

// Look up hostname from dummy IP and copy it while holding the lock.
static bool LookupDummy(uint32_t netOrderIp, char* hostname, size_t hostnameLength, uint16_t* outPort) {
    if (!hostname || hostnameLength == 0) return false;
    hostname[0] = 0;
    EnterCriticalSection(&g_dummyLock);
    bool found = false;
    for (uint32_t i = 0; i < DUMMY_HASH_SIZE; i++) {
        if (g_dummyTable[i].used && g_dummyTable[i].netOrderIp == netOrderIp) {
            if (outPort) *outPort = g_dummyTable[i].port;
            strncpy(hostname, g_dummyTable[i].hostname, hostnameLength - 1);
            hostname[hostnameLength - 1] = 0;
            found = true;
            break;
        }
    }
    LeaveCriticalSection(&g_dummyLock);
    return found;
}

// ============================================================================
// SOCKS5 helpers (non-blocking aware via select())
// ============================================================================
static ULONGLONG NewDeadline() {
    int timeout = g_config.timeoutSec;
    if (timeout < 1) timeout = 1;
    if (timeout > 30) timeout = 30;
    return GetTickCount64() + (ULONGLONG)timeout * 1000ULL;
}

static bool WaitForSocket(SOCKET s, bool writable, ULONGLONG deadline) {
    ULONGLONG now = GetTickCount64();
    if (now >= deadline) {
        WSASetLastError(WSAETIMEDOUT);
        return false;
    }
    ULONGLONG remaining = deadline - now;
    timeval timeout = { (long)(remaining / 1000ULL), (long)((remaining % 1000ULL) * 1000ULL) };
    fd_set readSet, writeSet, errorSet;
    FD_ZERO(&readSet); FD_ZERO(&writeSet); FD_ZERO(&errorSet);
    if (writable) FD_SET(s, &writeSet); else FD_SET(s, &readSet);
    FD_SET(s, &errorSet);
    int selected = select(0, writable ? NULL : &readSet, writable ? &writeSet : NULL, &errorSet, &timeout);
    if (selected == SOCKET_ERROR) return false;
    if (selected == 0) {
        WSASetLastError(WSAETIMEDOUT);
        return false;
    }
    int soError = 0;
    int soLength = sizeof(soError);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soError, &soLength) != 0) return false;
    if (soError != 0 || FD_ISSET(s, &errorSet)) {
        WSASetLastError(soError != 0 ? soError : WSAECONNABORTED);
        return false;
    }
    return true;
}

static bool SendAll(SOCKET s, const uint8_t* data, size_t length, ULONGLONG deadline) {
    size_t sent = 0;
    while (sent < length) {
        int chunk = (int)std::min<size_t>(length - sent, (size_t)std::numeric_limits<int>::max());
        int result = send(s, (const char*)data + sent, chunk, 0);
        if (result > 0) { sent += (size_t)result; continue; }
        if (result == 0) { WSASetLastError(WSAECONNRESET); return false; }
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK || !WaitForSocket(s, true, deadline)) return false;
    }
    return true;
}

static bool RecvExact(SOCKET s, uint8_t* data, size_t length, ULONGLONG deadline) {
    size_t received = 0;
    while (received < length) {
        int chunk = (int)std::min<size_t>(length - received, (size_t)std::numeric_limits<int>::max());
        int result = recv(s, (char*)data + received, chunk, 0);
        if (result > 0) { received += (size_t)result; continue; }
        if (result == 0) { WSASetLastError(WSAECONNRESET); return false; }
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK || !WaitForSocket(s, false, deadline)) return false;
    }
    return true;
}

static bool ResolveIpv4(const char* host, uint16_t port, sockaddr_in* endpoint) {
    if (!host || !*host || !endpoint || !g_orig_getaddrinfo) return false;
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->sin_family = AF_INET;
    endpoint->sin_port = htons(port);
    if (InetPtonA(AF_INET, host, &endpoint->sin_addr) == 1) return true;

    char service[8] = {0};
    _snprintf(service, sizeof(service) - 1, "%u", (unsigned)port);
    ADDRINFOA hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;
    PADDRINFOA result = NULL;
    int error = g_orig_getaddrinfo(host, service, &hints, &result);
    if (error != 0 || !result || !result->ai_addr) {
        if (result) freeaddrinfo(result);
        return false;
    }
    *endpoint = *(sockaddr_in*)result->ai_addr;
    freeaddrinfo(result);
    return true;
}

// .NET commonly uses dual-mode AF_INET6 sockets even when DNS returned an
// IPv4 address. In that case Winsock passes ::ffff:a.b.c.d to ConnectEx /
// WSAConnect. Treat that endpoint as IPv4 so it can still be sent through the
// IPv4 SOCKS5 proxy instead of falling through to the original ConnectEx.
static bool TryGetIpv4Endpoint(const sockaddr* address, int addressLength, sockaddr_in* ipv4) {
    if (!address || !ipv4) return false;
    memset(ipv4, 0, sizeof(*ipv4));
    if (address->sa_family == AF_INET && addressLength >= (int)sizeof(sockaddr_in)) {
        *ipv4 = *(const sockaddr_in*)address;
        return true;
    }
    if (address->sa_family != AF_INET6 || addressLength < (int)sizeof(sockaddr_in6))
        return false;

    const sockaddr_in6* ipv6 = (const sockaddr_in6*)address;
    if (!IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) return false;
    ipv4->sin_family = AF_INET;
    ipv4->sin_port = ipv6->sin6_port;
    memcpy(&ipv4->sin_addr, ((const uint8_t*)&ipv6->sin6_addr) + 12, sizeof(ipv4->sin_addr));
    return true;
}

static bool FormatProxyEndpointForSocket(SOCKET s, const sockaddr_in& ipv4,
                                         sockaddr_storage* endpoint, int* endpointLength) {
    if (!endpoint || !endpointLength) return false;
    WSAPROTOCOL_INFOA protocolInfo = {};
    int protocolInfoLength = sizeof(protocolInfo);
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char*)&protocolInfo, &protocolInfoLength) != 0)
        return false;

    memset(endpoint, 0, sizeof(*endpoint));
    if (protocolInfo.iAddressFamily == AF_INET) {
        memcpy(endpoint, &ipv4, sizeof(ipv4));
        *endpointLength = sizeof(ipv4);
        return true;
    }
    if (protocolInfo.iAddressFamily != AF_INET6) return false;

    sockaddr_in6* ipv6 = (sockaddr_in6*)endpoint;
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port = ipv4.sin_port;
    ipv6->sin6_addr.u.Byte[10] = 0xff;
    ipv6->sin6_addr.u.Byte[11] = 0xff;
    memcpy(&ipv6->sin6_addr.u.Byte[12], &ipv4.sin_addr, sizeof(ipv4.sin_addr));
    *endpointLength = sizeof(*ipv6);
    return true;
}

// Connect socket to SOCKS5 proxy. The configured proxy hostname is the only
// hostname deliberately resolved by the local resolver.
static bool ConnectToProxy(SOCKET s, ULONGLONG deadline, sockaddr_in* resolvedProxy = NULL) {
    sockaddr_in proxyAddress = {};
    if (!ResolveIpv4(g_config.socks5Host, g_config.socks5Port, &proxyAddress)) {
        Log("ConnectToProxy: proxy host resolution failed for %s", g_config.socks5Host);
        WSASetLastError(WSAHOST_NOT_FOUND);
        return false;
    }
    if (resolvedProxy) *resolvedProxy = proxyAddress;

    sockaddr_storage socketProxyAddress = {};
    int socketProxyAddressLength = 0;
    if (!FormatProxyEndpointForSocket(s, proxyAddress, &socketProxyAddress, &socketProxyAddressLength)) {
        Log("ConnectToProxy: unsupported socket address family");
        WSASetLastError(WSAEAFNOSUPPORT);
        return false;
    }

    int result = g_orig_connect(s, (sockaddr*)&socketProxyAddress, socketProxyAddressLength);
    if (result == 0) return true;
    int error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEALREADY) {
        Log("ConnectToProxy: connect failed err=%d", error);
        return false;
    }
    if (!WaitForSocket(s, true, deadline)) {
        Log("ConnectToProxy: completion failed err=%d", WSAGetLastError());
        return false;
    }
    return true;
}

// Perform SOCKS5 auth negotiation + CONNECT request.
// targetAddr is the original sockaddr_in (ip:port) the app wanted.
// Returns true on success.
// SOCKS5 auth negotiation (shared between IPv4 and domain modes).
// Returns true on success (proxy accepted auth, ready for CONNECT).
static bool Socks5NegotiateAuth(SOCKET s, ULONGLONG deadline) {
    uint8_t buffer[512] = {};
    bool useAuth = g_config.socks5User[0] != '\0';
    buffer[0] = 0x05;
    buffer[1] = useAuth ? 0x02 : 0x01;
    buffer[2] = 0x00;
    if (useAuth) buffer[3] = 0x02;
    if (!SendAll(s, buffer, useAuth ? 4 : 3, deadline)) return false;

    uint8_t response[2] = {};
    if (!RecvExact(s, response, sizeof(response), deadline) || response[0] != 0x05) return false;
    if (response[1] == 0x02) {
        size_t userLength = strlen(g_config.socks5User);
        size_t passLength = strlen(g_config.socks5Pass);
        if (userLength > 255 || passLength > 255) return false;
        size_t offset = 0;
        buffer[offset++] = 0x01;
        buffer[offset++] = (uint8_t)userLength;
        memcpy(buffer + offset, g_config.socks5User, userLength); offset += userLength;
        buffer[offset++] = (uint8_t)passLength;
        memcpy(buffer + offset, g_config.socks5Pass, passLength); offset += passLength;
        if (!SendAll(s, buffer, offset, deadline)) return false;
        uint8_t authResponse[2] = {};
        if (!RecvExact(s, authResponse, sizeof(authResponse), deadline)
            || authResponse[0] != 0x01 || authResponse[1] != 0x00) return false;
    } else if (response[1] != 0x00) {
        Log("Socks5: unsupported authentication method %u", (unsigned)response[1]);
        return false;
    }
    return true;
}

// Read SOCKS5 CONNECT response after sending CONNECT request.
// Returns true on success (REP=0x00).
static bool Socks5ReadResponse(SOCKET s, ULONGLONG deadline, sockaddr_storage* endpoint, int* endpointLength,
    char* boundAddress, size_t boundAddressLength) {
    if (boundAddress && boundAddressLength > 0) {
        _snprintf(boundAddress, boundAddressLength - 1, "%s", "unavailable");
        boundAddress[boundAddressLength - 1] = '\0';
    }
    uint8_t header[4] = {};
    if (!RecvExact(s, header, sizeof(header), deadline)
        || header[0] != 0x05 || header[2] != 0x00) return false;
    if (header[1] != 0x00) {
        Log("Socks5: request rejected rep=%u", (unsigned)header[1]);
        WSASetLastError(WSAECONNREFUSED);
        return false;
    }

    sockaddr_storage parsed = {};
    int parsedLength = 0;
    if (header[3] == 0x01) {
        uint8_t value[6] = {};
        if (!RecvExact(s, value, sizeof(value), deadline)) return false;
        sockaddr_in* ipv4 = (sockaddr_in*)&parsed;
        ipv4->sin_family = AF_INET;
        memcpy(&ipv4->sin_addr, value, 4);
        memcpy(&ipv4->sin_port, value + 4, 2);
        parsedLength = sizeof(sockaddr_in);
        if (boundAddress && boundAddressLength > 0)
            InetNtopA(AF_INET, &ipv4->sin_addr, boundAddress, boundAddressLength);
    } else if (header[3] == 0x04) {
        uint8_t value[18] = {};
        if (!RecvExact(s, value, sizeof(value), deadline)) return false;
        sockaddr_in6* ipv6 = (sockaddr_in6*)&parsed;
        ipv6->sin6_family = AF_INET6;
        memcpy(&ipv6->sin6_addr, value, 16);
        memcpy(&ipv6->sin6_port, value + 16, 2);
        parsedLength = sizeof(sockaddr_in6);
        if (boundAddress && boundAddressLength > 0)
            InetNtopA(AF_INET6, &ipv6->sin6_addr, boundAddress, boundAddressLength);
    } else if (header[3] == 0x03) {
        uint8_t domainLength = 0;
        if (!RecvExact(s, &domainLength, 1, deadline) || domainLength == 0) return false;
        uint8_t value[257] = {};
        if (!RecvExact(s, value, (size_t)domainLength + 2, deadline)) return false;
        char domain[256] = {0};
        memcpy(domain, value, domainLength);
        if (boundAddress && boundAddressLength > 0) {
            _snprintf(boundAddress, boundAddressLength - 1, "%s", domain);
            boundAddress[boundAddressLength - 1] = '\0';
        }
        uint16_t port = (uint16_t)(((uint16_t)value[domainLength] << 8) | value[domainLength + 1]);
        if (endpoint) {
            sockaddr_in ipv4 = {};
            if (!ResolveIpv4(domain, port, &ipv4)) return false;
            memcpy(&parsed, &ipv4, sizeof(ipv4));
            parsedLength = sizeof(ipv4);
        }
    } else {
        WSASetLastError(WSAEPROTONOSUPPORT);
        return false;
    }

    if (endpoint) *endpoint = parsed;
    if (endpointLength) *endpointLength = parsedLength;
    return true;
}

// SOCKS5 + CONNECT with IPv4 ATYP=0x01
static bool Socks5HandshakeAndConnect(SOCKET s, const sockaddr_in* target, ULONGLONG deadline,
    char* boundAddress, size_t boundAddressLength) {
    if (!Socks5NegotiateAuth(s, deadline)) return false;

    uint8_t buf[10] = { 0x05, 0x01, 0x00, 0x01 };
    memcpy(buf + 4, &target->sin_addr, 4);
    memcpy(buf + 8, &target->sin_port, 2);
    return SendAll(s, buf, sizeof(buf), deadline)
        && Socks5ReadResponse(s, deadline, NULL, NULL, boundAddress, boundAddressLength);
}

// SOCKS5 + CONNECT with domain ATYP=0x03 (proxy resolves hostname → no DNS leak)
static bool Socks5HandshakeAndConnectDomain(SOCKET s, const char* hostname, uint16_t port, ULONGLONG deadline,
    char* boundAddress, size_t boundAddressLength) {
    if (!hostname || !*hostname || strlen(hostname) > 255 || !Socks5NegotiateAuth(s, deadline)) return false;
    size_t hostnameLength = strlen(hostname);
    std::vector<uint8_t> request(7 + hostnameLength);
    request[0] = 0x05; request[1] = 0x01; request[2] = 0x00; request[3] = 0x03;
    request[4] = (uint8_t)hostnameLength;
    memcpy(request.data() + 5, hostname, hostnameLength);
    request[5 + hostnameLength] = (uint8_t)(port >> 8);
    request[6 + hostnameLength] = (uint8_t)(port & 0xFF);
    return SendAll(s, request.data(), request.size(), deadline)
        && Socks5ReadResponse(s, deadline, NULL, NULL, boundAddress, boundAddressLength);
}


static int RouteTcpCore(SOCKET s, const sockaddr_in* target, const char* hostname) {
    char ipString[INET_ADDRSTRLEN] = {0};
    InetNtopA(AF_INET, (PVOID)&target->sin_addr, ipString, sizeof(ipString));
    uint16_t port = ntohs(target->sin_port);
    bool originallyNonBlocking = IsNonBlocking(s);
    if (!originallyNonBlocking) {
        u_long enabled = 1;
        if (g_orig_ioctlsocket(s, FIONBIO, &enabled) != 0) return SOCKET_ERROR;
    }

    ULONGLONG deadline = NewDeadline();
    char boundAddress[256] = "unavailable";
    bool connected = ConnectToProxy(s, deadline);
    bool negotiated = connected && (hostname
        ? Socks5HandshakeAndConnectDomain(s, hostname, port, deadline, boundAddress, sizeof(boundAddress))
        : Socks5HandshakeAndConnect(s, target, deadline, boundAddress, sizeof(boundAddress)));

    if (!originallyNonBlocking) {
        u_long disabled = 0;
        if (g_orig_ioctlsocket(s, FIONBIO, &disabled) != 0) negotiated = false;
    }

    const char* targetText = hostname ? hostname : ipString;
    if (!negotiated) {
        int error = WSAGetLastError();
        Log("PROXY_FAIL phase=socks5 target=%s:%u reason=%d", targetText, (unsigned)port, error);
        shutdown(s, SD_BOTH);
        WSASetLastError(error != 0 ? error : WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    Log("PROXY_OK target=%s:%u via=%s:%u egress=%s", targetText, (unsigned)port,
        g_config.socks5Host, (unsigned)g_config.socks5Port, boundAddress);
    WSASetLastError(0);
    return 0;
}

static int RouteTcp(SOCKET s, const sockaddr_in* target) {
    char hostname[256] = {0};
    const char* hostnamePointer = NULL;
    if (IsDummyIp(target->sin_addr.s_addr)
        && LookupDummy(target->sin_addr.s_addr, hostname, sizeof(hostname), NULL)) {
        hostnamePointer = hostname;
    }
    return RouteTcpCore(s, target, hostnamePointer);
}

static int RouteTcpDomain(SOCKET s, const char* hostname, uint16_t port) {
    sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    return RouteTcpCore(s, &target, hostname);
}

static bool ParseServicePort(const char* service, uint16_t* port) {
    if (!service || !*service || !port) return false;
    char* end = NULL;
    unsigned long value = strtoul(service, &end, 10);
    if (end && *end == 0 && value > 0 && value <= 65535) {
        *port = (uint16_t)value;
        return true;
    }
    if (_stricmp(service, "http") == 0) { *port = 80; return true; }
    if (_stricmp(service, "https") == 0) { *port = 443; return true; }
    return false;
}

// ============================================================================
// Lazy SOCKS5 handshake for overlapped ConnectEx (IOCP correctness)
//
// My_ConnectEx calls the REAL ConnectEx against the proxy address so the OS
// delivers overlapped completion (IOCP/event) exactly as the application
// expects — synchronously fabricating the completion breaks async clients
// (TaskCanceledException timeouts in DreamPoeBot's auth HttpClient).
// The SOCKS5 greeting + CONNECT handshake then runs lazily inside the first
// send/WSASend on that socket, before any application payload leaves.
// ============================================================================

struct PendingConnect {
    char hostname[256];   // empty → target is a raw IPv4
    uint16_t port;
    uint32_t targetIp;    // network order (raw IPv4 mode)
};
static std::map<SOCKET, PendingConnect> g_pendingConnects;
static std::mutex g_pendingMutex;

static void StorePendingConnect(SOCKET s, const char* hostname, uint16_t port, uint32_t targetIp) {
    PendingConnect pending = {};
    pending.port = port;
    pending.targetIp = targetIp;
    if (hostname) {
        size_t hostnameLength = strnlen(hostname, sizeof(pending.hostname) - 1);
        memcpy(pending.hostname, hostname, hostnameLength);
        pending.hostname[hostnameLength] = 0;
    }
    std::lock_guard<std::mutex> lock(g_pendingMutex);
    g_pendingConnects[s] = pending;
}

static bool PopPendingConnect(SOCKET s, PendingConnect* out) {
    std::lock_guard<std::mutex> lock(g_pendingMutex);
    auto it = g_pendingConnects.find(s);
    if (it == g_pendingConnects.end()) return false;
    if (out) *out = it->second;
    g_pendingConnects.erase(it);
    return true;
}

static void DropPendingConnect(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_pendingMutex);
    g_pendingConnects.erase(s);
}

// Runs the SOCKS5 greeting + CONNECT on a socket already connected to the proxy.
// Socks5HandshakeAndConnect( Domain) performs the auth negotiation internally —
// do NOT call Socks5NegotiateAuth before them (a second greeting reaches the
// proxy instead of the CONNECT request and it replies 05 07).
// stage: 1=FIONBIO toggle, 2=SOCKS5 handshake+CONNECT; error is captured
// before any follow-up call can mask it.
static bool RunLazySocks5Handshake(SOCKET s, const PendingConnect& pending, int* stage, int* error) {
    *stage = 0;
    *error = 0;
    bool originallyNonBlocking = IsNonBlocking(s);
    if (!originallyNonBlocking) {
        u_long enabled = 1;
        if (g_orig_ioctlsocket(s, FIONBIO, &enabled) != 0) {
            *stage = 1;
            *error = WSAGetLastError();
            return false;
        }
    }
    ULONGLONG deadline = NewDeadline();
    bool ok;
    if (pending.hostname[0]) {
        ok = Socks5HandshakeAndConnectDomain(s, pending.hostname, pending.port, deadline, NULL, 0);
    } else {
        sockaddr_in target = {};
        target.sin_family = AF_INET;
        target.sin_port = htons(pending.port);
        target.sin_addr.s_addr = pending.targetIp;
        ok = Socks5HandshakeAndConnect(s, &target, deadline, NULL, 0);
    }
    if (!ok) {
        *stage = 2;
        *error = WSAGetLastError();
    }
    if (!originallyNonBlocking) {
        u_long disabled = 0;
        g_orig_ioctlsocket(s, FIONBIO, &disabled);
    }
    return ok;
}

// Called from My_send/My_WSASend: completes the deferred SOCKS5 handshake before
// the first application payload. Returns true when the socket is ready (or was
// never deferred), false when the handshake failed (fail-closed).
static bool CompletePendingSendHandshake(SOCKET s) {
    PendingConnect pending;
    if (!PopPendingConnect(s, &pending)) return true;
    char targetText[300] = {0};
    if (pending.hostname[0]) {
        _snprintf(targetText, sizeof(targetText) - 1, "%s:%u", pending.hostname, (unsigned)pending.port);
    } else {
        IN_ADDR address = {};
        address.s_addr = pending.targetIp;
        char ipString[INET_ADDRSTRLEN] = {0};
        InetNtopA(AF_INET, &address, ipString, sizeof(ipString));
        _snprintf(targetText, sizeof(targetText) - 1, "%s:%u", ipString, (unsigned)pending.port);
    }
    int stage = 0;
    int error = 0;
    if (RunLazySocks5Handshake(s, pending, &stage, &error)) {
        Log("PROXY_OK target=%s via=%s:%u (lazy ConnectEx)", targetText,
            g_config.socks5Host, (unsigned)g_config.socks5Port);
        return true;
    }
    Log("PROXY_FAIL phase=socks5-lazy target=%s stage=%d reason=%d", targetText, stage, error);
    WSASetLastError(WSAECONNREFUSED);
    return false;
}


// ============================================================================
// UDP via SOCKS5 UDP ASSOCIATE
// ============================================================================
static bool InitUdpAssociate(std::shared_ptr<UdpAssoc>* output) {
    if (!output) return false;
    auto association = std::make_shared<UdpAssoc>();
    association->proxySock = g_orig_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (association->proxySock == INVALID_SOCKET) return false;

    u_long nonBlocking = 1;
    if (g_orig_ioctlsocket(association->proxySock, FIONBIO, &nonBlocking) != 0) return false;
    ULONGLONG deadline = NewDeadline();
    sockaddr_in resolvedProxy = {};
    if (!ConnectToProxy(association->proxySock, deadline, &resolvedProxy)
        || !Socks5NegotiateAuth(association->proxySock, deadline)) return false;

    uint8_t request[10] = { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    if (!SendAll(association->proxySock, request, sizeof(request), deadline)
        || !Socks5ReadResponse(association->proxySock, deadline,
            &association->udpProxyAddr, &association->udpProxyAddrLen, NULL, 0)) return false;

    if (association->udpProxyAddr.ss_family != AF_INET) {
        Log("UDP ASSOCIATE returned an unsupported non-IPv4 relay");
        WSASetLastError(WSAEAFNOSUPPORT);
        return false;
    }
    sockaddr_in* relay = (sockaddr_in*)&association->udpProxyAddr;
    if (relay->sin_addr.s_addr == INADDR_ANY)
        relay->sin_addr = resolvedProxy.sin_addr;
    *output = association;
    return true;
}

static std::shared_ptr<UdpAssoc> GetOrCreateUdpAssociation(SOCKET s) {
    {
        std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
        auto existing = g_udpAssocMap.find(s);
        if (existing != g_udpAssocMap.end()) return existing->second;
    }

    std::shared_ptr<UdpAssoc> created;
    if (!InitUdpAssociate(&created)) return nullptr;
    std::unique_lock<std::shared_mutex> lock(g_socketsMutex);
    auto existing = g_udpAssocMap.find(s);
    if (existing != g_udpAssocMap.end()) return existing->second;
    g_udpAssocMap[s] = created;
    return created;
}

static bool BuildUdpPacket(const char* payload, size_t payloadLength, const sockaddr* destination,
    int destinationLength, std::vector<char>* packet) {
    if (!payload || !destination || !packet || destination->sa_family != AF_INET
        || destinationLength < (int)sizeof(sockaddr_in)) return false;
    const sockaddr_in* ipv4 = (const sockaddr_in*)destination;
    char hostname[256] = {0};
    if (IsDummyIp(ipv4->sin_addr.s_addr)
        && LookupDummy(ipv4->sin_addr.s_addr, hostname, sizeof(hostname), NULL)) {
        size_t hostnameLength = strlen(hostname);
        if (hostnameLength == 0 || hostnameLength > 255) return false;
        packet->resize(7 + hostnameLength + payloadLength);
        (*packet)[0] = 0; (*packet)[1] = 0; (*packet)[2] = 0; (*packet)[3] = 3;
        (*packet)[4] = (char)hostnameLength;
        memcpy(packet->data() + 5, hostname, hostnameLength);
        memcpy(packet->data() + 5 + hostnameLength, &ipv4->sin_port, 2);
        if (payloadLength > 0) memcpy(packet->data() + 7 + hostnameLength, payload, payloadLength);
        return true;
    }

    packet->resize(10 + payloadLength);
    (*packet)[0] = 0; (*packet)[1] = 0; (*packet)[2] = 0; (*packet)[3] = 1;
    memcpy(packet->data() + 4, &ipv4->sin_addr, 4);
    memcpy(packet->data() + 8, &ipv4->sin_port, 2);
    if (payloadLength > 0) memcpy(packet->data() + 10, payload, payloadLength);
    return true;
}

// ============================================================================
// Hooks
// ============================================================================
static bool IsLoopbackAddress(const sockaddr* address, int addressLength) {
    if (!address) return false;
    if (address->sa_family == AF_INET && addressLength >= (int)sizeof(sockaddr_in)) {
        return (ntohl(((const sockaddr_in*)address)->sin_addr.s_addr) & 0xff000000u) == 0x7f000000u;
    }
    if (address->sa_family == AF_INET6 && addressLength >= (int)sizeof(sockaddr_in6)) {
        const auto* ipv6 = &((const sockaddr_in6*)address)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(ipv6) != 0) return true;
        // SocketsHttpHandler commonly connects to 127.0.0.1 through an
        // IPv4-mapped IPv6 endpoint (::ffff:127.x.x.x). Treat it as local too;
        // otherwise the injected DPB2 process sends its ControlPanel handshake
        // into the external SOCKS proxy and times out.
        const auto* bytes = reinterpret_cast<const unsigned char*>(ipv6);
        const bool isIpv4Mapped = bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0
            && bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0
            && bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0xff && bytes[11] == 0xff;
        return isIpv4Mapped && bytes[12] == 127;
    }
    return false;
}

static int FailClosed(const char* operation, int error = WSAEOPNOTSUPP) {
    Log("%s: BLOCKED by fail-closed proxy policy", operation);
    WSASetLastError(error);
    return SOCKET_ERROR;
}

static INT FailClosedBoolean(const char* operation, int error = WSAEOPNOTSUPP) {
    FailClosed(operation, error);
    return FALSE;
}

static bool HasLoopbackPeer(SOCKET s) {
    sockaddr_storage peer = {};
    int peerLength = sizeof(peer);
    return getpeername(s, (sockaddr*)&peer, &peerLength) == 0
        && IsLoopbackAddress((sockaddr*)&peer, peerLength);
}

static int WINAPI My_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (!g_config.enabled || !name || namelen <= 0)
        return g_orig_connect(s, name, namelen);

    if (IsLoopbackAddress(name, namelen)) return g_orig_connect(s, name, namelen);
    if (IsUdpSocket(s)) return FailClosed("connect UDP");
    sockaddr_in ipv4 = {};
    if (TryGetIpv4Endpoint(name, namelen, &ipv4))
        return RouteTcp(s, &ipv4);
    return FailClosed("connect address family", WSAEAFNOSUPPORT);
}

static int WINAPI My_bind(SOCKET s, const sockaddr* name, int namelen) {
    return g_orig_bind(s, name, namelen);
}

static int WINAPI My_closesocket(SOCKET s) {
    UntrackSocket(s);
    DropPendingConnect(s);
    return g_orig_closesocket(s);
}

static int WINAPI My_sendto(SOCKET s, const char* buf, int len, int flags,
                            const struct sockaddr* to, int tolen) {
    if (!g_config.enabled) return g_orig_sendto(s, buf, len, flags, to, tolen);
    if (!buf || len < 0 || !to) return FailClosed("sendto invalid arguments", WSAEFAULT);
    if (IsLoopbackAddress(to, tolen)) return g_orig_sendto(s, buf, len, flags, to, tolen);
    if (to->sa_family != AF_INET || tolen < (int)sizeof(sockaddr_in))
        return FailClosed("sendto address family", WSAEAFNOSUPPORT);

    auto association = GetOrCreateUdpAssociation(s);
    if (!association) return FailClosed("sendto UDP ASSOCIATE", WSAECONNREFUSED);
    std::vector<char> packet;
    if (!BuildUdpPacket(buf, (size_t)len, to, tolen, &packet))
        return FailClosed("sendto packet encoding", WSAEINVAL);
    int sent = g_orig_sendto(s, packet.data(), (int)packet.size(), flags,
        (sockaddr*)&association->udpProxyAddr, association->udpProxyAddrLen);
    if (sent == SOCKET_ERROR) return SOCKET_ERROR;
    if ((size_t)sent != packet.size()) return FailClosed("sendto partial datagram", WSAEMSGSIZE);
    return len;
}

static int WINAPI My_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD nsent,
                               DWORD flags, const struct sockaddr* to, int tolen,
                               LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (!g_config.enabled)
        return g_orig_WSASendTo(s, bufs, count, nsent, flags, to, tolen, ov, cr);
    if (!bufs || count == 0 || !to) return FailClosed("WSASendTo invalid arguments", WSAEFAULT);
    if (IsLoopbackAddress(to, tolen))
        return g_orig_WSASendTo(s, bufs, count, nsent, flags, to, tolen, ov, cr);
    if (ov || cr) return FailClosed("WSASendTo overlapped");

    size_t totalLength = 0;
    for (DWORD i = 0; i < count; i++) {
        if (bufs[i].len > (size_t)std::numeric_limits<int>::max() - totalLength)
            return FailClosed("WSASendTo oversized payload", WSAEMSGSIZE);
        totalLength += bufs[i].len;
    }
    std::vector<char> payload(totalLength);
    size_t offset = 0;
    for (DWORD i = 0; i < count; i++) {
        if (bufs[i].len > 0 && !bufs[i].buf) return FailClosed("WSASendTo invalid buffer", WSAEFAULT);
        memcpy(payload.data() + offset, bufs[i].buf, bufs[i].len);
        offset += bufs[i].len;
    }
    int sent = My_sendto(s, payload.data(), (int)payload.size(), flags, to, tolen);
    if (sent == SOCKET_ERROR) return SOCKET_ERROR;
    if (nsent) *nsent = (DWORD)sent;
    return 0;
}

static std::shared_ptr<UdpAssoc> GetUdpAssociation(SOCKET s) {
    std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
    auto existing = g_udpAssocMap.find(s);
    return existing == g_udpAssocMap.end() ? nullptr : existing->second;
}

static bool IsRelaySource(const sockaddr* source, int sourceLength, const UdpAssoc& association) {
    if (!source || source->sa_family != association.udpProxyAddr.ss_family) return false;
    if (source->sa_family == AF_INET && sourceLength >= (int)sizeof(sockaddr_in)) {
        const sockaddr_in* left = (const sockaddr_in*)source;
        const sockaddr_in* right = (const sockaddr_in*)&association.udpProxyAddr;
        return left->sin_addr.s_addr == right->sin_addr.s_addr && left->sin_port == right->sin_port;
    }
    return false;
}

static bool DecodeUdpPacket(char* buffer, int received, sockaddr* source, int* sourceLength, int* payloadLength) {
    if (!buffer || received < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0) {
        WSASetLastError(WSAEPROTONOSUPPORT);
        return false;
    }

    size_t payloadOffset = 0;
    sockaddr_storage decoded = {};
    int decodedLength = 0;
    uint8_t addressType = (uint8_t)buffer[3];
    if (addressType == 0x01) {
        if (received < 10) return false;
        sockaddr_in* ipv4 = (sockaddr_in*)&decoded;
        ipv4->sin_family = AF_INET;
        memcpy(&ipv4->sin_addr, buffer + 4, 4);
        memcpy(&ipv4->sin_port, buffer + 8, 2);
        decodedLength = sizeof(sockaddr_in);
        payloadOffset = 10;
    } else if (addressType == 0x04) {
        if (received < 22) return false;
        sockaddr_in6* ipv6 = (sockaddr_in6*)&decoded;
        ipv6->sin6_family = AF_INET6;
        memcpy(&ipv6->sin6_addr, buffer + 4, 16);
        memcpy(&ipv6->sin6_port, buffer + 20, 2);
        decodedLength = sizeof(sockaddr_in6);
        payloadOffset = 22;
    } else if (addressType == 0x03) {
        if (received < 7) return false;
        uint8_t hostnameLength = (uint8_t)buffer[4];
        payloadOffset = 7 + hostnameLength;
        if (hostnameLength == 0 || payloadOffset > (size_t)received) return false;
        char hostname[256] = {0};
        memcpy(hostname, buffer + 5, hostnameLength);
        uint16_t networkPort = 0;
        memcpy(&networkPort, buffer + 5 + hostnameLength, 2);
        uint32_t dummyIp = 0;
        if (!StoreDummy(hostname, ntohs(networkPort), &dummyIp)) {
            WSASetLastError(WSAENOBUFS);
            return false;
        }
        sockaddr_in* ipv4 = (sockaddr_in*)&decoded;
        ipv4->sin_family = AF_INET;
        ipv4->sin_addr.s_addr = dummyIp;
        ipv4->sin_port = networkPort;
        decodedLength = sizeof(sockaddr_in);
    } else {
        WSASetLastError(WSAEPROTONOSUPPORT);
        return false;
    }

    if (source && sourceLength) {
        if (*sourceLength < decodedLength) {
            WSASetLastError(WSAEFAULT);
            return false;
        }
        memcpy(source, &decoded, decodedLength);
        *sourceLength = decodedLength;
    }
    int decodedPayloadLength = received - (int)payloadOffset;
    memmove(buffer, buffer + payloadOffset, decodedPayloadLength);
    if (payloadLength) *payloadLength = decodedPayloadLength;
    return true;
}

static bool ReceiveUdpPacket(SOCKET s, const UdpAssoc& association, int flags,
                             char* payload, int payloadCapacity,
                             sockaddr* source, int* sourceLength, int* payloadLength) {
    if (!payload || payloadCapacity < 0 || (source && !sourceLength)) {
        WSASetLastError(WSAEFAULT);
        return false;
    }

    // The largest SOCKS5 UDP header is 262 bytes (domain name with 255 bytes).
    // Receive into a separate wire buffer so protocol overhead never consumes
    // bytes from the application's requested payload capacity.
    const size_t maxHeaderLength = 262;
    size_t wireCapacity = std::min<size_t>((size_t)payloadCapacity + maxHeaderLength, 65535);

    std::vector<char> wireBuffer(wireCapacity);
    sockaddr_storage relaySource = {};
    int relaySourceLength = sizeof(relaySource);
    int received = g_orig_recvfrom(s, wireBuffer.data(), (int)wireBuffer.size(), flags,
        (sockaddr*)&relaySource, &relaySourceLength);
    if (received == SOCKET_ERROR) return false;
    if (!IsRelaySource((sockaddr*)&relaySource, relaySourceLength, association)) {
        Log("recvfrom non-relay source: BLOCKED by fail-closed proxy policy");
        WSASetLastError(WSAEHOSTUNREACH);
        return false;
    }

    int decodedLength = 0;
    if (!DecodeUdpPacket(wireBuffer.data(), received, source, sourceLength, &decodedLength))
        return false;
    if (decodedLength > payloadCapacity) {
        if (payloadCapacity > 0) memcpy(payload, wireBuffer.data(), payloadCapacity);
        WSASetLastError(WSAEMSGSIZE);
        return false;
    }
    if (decodedLength > 0) memcpy(payload, wireBuffer.data(), decodedLength);
    if (payloadLength) *payloadLength = decodedLength;
    return true;
}

static int WINAPI My_recvfrom(SOCKET s, char* buf, int len, int flags,
                              struct sockaddr* from, int* fromlen) {
    auto association = GetUdpAssociation(s);
    if (!association) {
        if (!g_config.enabled || HasLoopbackPeer(s))
            return g_orig_recvfrom(s, buf, len, flags, from, fromlen);
        return FailClosed("recvfrom without UDP proxy association", WSAENOTCONN);
    }
    int payloadLength = 0;
    return ReceiveUdpPacket(s, *association, flags, buf, len, from, fromlen, &payloadLength)
        ? payloadLength
        : SOCKET_ERROR;
}

static int WINAPI My_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd,
                                 LPDWORD flags, struct sockaddr* from, LPINT fromlen,
                                 LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    auto association = GetUdpAssociation(s);
    if (!association) {
        if (!g_config.enabled || HasLoopbackPeer(s))
            return g_orig_WSARecvFrom(s, bufs, count, recvd, flags, from, fromlen, ov, cr);
        return FailClosed("WSARecvFrom without UDP proxy association", WSAENOTCONN);
    }
    if (!bufs || count != 1 || !recvd) return FailClosed("WSARecvFrom buffer shape", WSAEOPNOTSUPP);
    if (ov || cr) return FailClosed("WSARecvFrom overlapped");
    if ((bufs[0].len > 0 && !bufs[0].buf) || (from && !fromlen))
        return FailClosed("WSARecvFrom invalid arguments", WSAEFAULT);
    if (bufs[0].len > (size_t)std::numeric_limits<int>::max())
        return FailClosed("WSARecvFrom oversized buffer", WSAEMSGSIZE);

    const size_t maxHeaderLength = 262;
    size_t wireCapacity = std::min<size_t>((size_t)bufs[0].len + maxHeaderLength, 65535);
    std::vector<char> wireBuffer(wireCapacity);
    WSABUF wire = { (ULONG)wireBuffer.size(), wireBuffer.data() };
    DWORD wireReceived = 0;
    sockaddr_storage relaySource = {};
    int relaySourceLength = sizeof(relaySource);
    int result = g_orig_WSARecvFrom(s, &wire, 1, &wireReceived, flags,
        (sockaddr*)&relaySource, &relaySourceLength, NULL, NULL);
    if (result != 0) return result;
    if (!IsRelaySource((sockaddr*)&relaySource, relaySourceLength, *association))
        return FailClosed("WSARecvFrom non-relay source", WSAEHOSTUNREACH);

    int payloadLength = 0;
    if (!DecodeUdpPacket(wireBuffer.data(), (int)wireReceived, from, fromlen, &payloadLength))
        return SOCKET_ERROR;
    if (payloadLength > (int)bufs[0].len) {
        if (bufs[0].len > 0) memcpy(bufs[0].buf, wireBuffer.data(), bufs[0].len);
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }
    if (payloadLength > 0) memcpy(bufs[0].buf, wireBuffer.data(), payloadLength);
    *recvd = (DWORD)payloadLength;
    return 0;
}

static int WSAAPI My_WSAEventSelect(SOCKET s, WSAEVENT ev, long events) {
    MarkNonBlocking(s, (ev != NULL && events != 0) ? events : 0);
    return g_orig_WSAEventSelect(s, ev, events);
}

static int WSAAPI My_WSAAsyncSelect(SOCKET s, HWND window, unsigned int message, long events) {
    MarkNonBlocking(s, (window != NULL && events != 0) ? events : 0);
    return g_orig_WSAAsyncSelect(s, window, message, events);
}

static int WSAAPI My_ioctlsocket(SOCKET s, long cmd, u_long* argp) {
    if (cmd == (long)FIONBIO && argp) {
        MarkNonBlocking(s, *argp ? FD_READ | FD_WRITE : 0);
    }
    return g_orig_ioctlsocket(s, cmd, argp);
}

// ============================================================================
// Additional Winsock hooks for zero-leak protection
// ============================================================================

// socket() — block only raw sockets (IPv6 handled at connect-level to avoid
// breaking internal DNS resolver which uses AF_INET6 sockets)
static SOCKET WINAPI My_socket(int af, int type, int protocol) {
    if (type == SOCK_RAW) {
        Log("socket: BLOCKED SOCK_RAW (raw socket leak prevention)");
        WSASetLastError(WSAEACCES);
        return INVALID_SOCKET;
    }
    return g_orig_socket(af, type, protocol);
}

// WSAConnect() — alternative TCP connect, route via SOCKS5 same as connect()
static int WINAPI My_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    if (!g_config.enabled || !name || namelen <= 0) {
        return g_orig_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }
    if (IsLoopbackAddress(name, namelen))
        return g_orig_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    if (lpCallerData || lpCalleeData || lpSQOS || lpGQOS)
        return FailClosed("WSAConnect ancillary data");
    if (IsUdpSocket(s)) return FailClosed("WSAConnect UDP");
    sockaddr_in ipv4 = {};
    if (TryGetIpv4Endpoint(name, namelen, &ipv4))
        return RouteTcp(s, &ipv4);
    return FailClosed("WSAConnect address family", WSAEAFNOSUPPORT);
}

// WSAConnectByNameW — take the hostname directly so the proxy resolves it.
static INT WINAPI My_WSAConnectByNameW(SOCKET s, LPCWSTR nodename, LPCWSTR servicename,
    LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
    LPTIMEVAL timeout, LPOVERLAPPED lpOverlapped) {
    if (!g_config.enabled || !nodename || !*nodename) {
        return g_orig_WSAConnectByNameW(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    char narrow[256] = {0};
    if (WideCharToMultiByte(CP_UTF8, 0, nodename, -1, narrow, sizeof(narrow)-1, NULL, NULL) <= 0)
        return FALSE;
    if (IsLoopbackHostname(narrow)) {
        return g_orig_WSAConnectByNameW(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    if (lpOverlapped) return FailClosedBoolean("WSAConnectByNameW overlapped");
    uint16_t port = 0;
    char service[16] = {0};
    if (!servicename || WideCharToMultiByte(CP_UTF8, 0, servicename, -1, service, sizeof(service)-1, NULL, NULL) <= 0
        || !ParseServicePort(service, &port)) return FailClosedBoolean("WSAConnectByNameW service", WSAEINVAL);
    Log("WSAConnectByNameW(%s:%d) — domain-mode SOCKS5", narrow, port);
    IN_ADDR numeric = {};
    int routeResult;
    sockaddr_in remote = {};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    if (InetPtonA(AF_INET, narrow, &numeric) == 1) {
        remote.sin_addr = numeric;
        routeResult = RouteTcp(s, &remote);
    } else if (IsNumericIp(narrow)) {
        return FailClosedBoolean("WSAConnectByNameW IPv6", WSAEAFNOSUPPORT);
    } else {
        uint32_t dummyIp = 0;
        if (!StoreDummy(narrow, port, &dummyIp)) return FailClosedBoolean("WSAConnectByNameW DNS map", WSAENOBUFS);
        remote.sin_addr.s_addr = dummyIp;
        routeResult = RouteTcpDomain(s, narrow, port);
    }
    if (routeResult != 0) return FALSE;
    if (RemoteAddress && RemoteAddressLength && *RemoteAddressLength >= sizeof(remote)) {
        memcpy(RemoteAddress, &remote, sizeof(remote));
        *RemoteAddressLength = sizeof(remote);
    }
    if (LocalAddress && LocalAddressLength) {
        int localLength = (int)*LocalAddressLength;
        if (getsockname(s, LocalAddress, &localLength) == 0) *LocalAddressLength = (DWORD)localLength;
    }
    return TRUE;
}

// WSAConnectByNameA — narrow-string variant
static INT WINAPI My_WSAConnectByNameA(SOCKET s, PCSTR nodename, PCSTR servicename,
    LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
    LPTIMEVAL timeout, LPOVERLAPPED lpOverlapped) {
    if (!g_config.enabled || !nodename || !*nodename) {
        return g_orig_WSAConnectByNameA(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    if (IsLoopbackHostname(nodename)) {
        return g_orig_WSAConnectByNameA(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    if (lpOverlapped) return FailClosedBoolean("WSAConnectByNameA overlapped");
    uint16_t port = 0;
    if (!ParseServicePort(servicename, &port)) return FailClosedBoolean("WSAConnectByNameA service", WSAEINVAL);
    Log("WSAConnectByNameA(%s:%d) — domain-mode SOCKS5", nodename, port);
    IN_ADDR numeric = {};
    int routeResult;
    sockaddr_in remote = {};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    if (InetPtonA(AF_INET, nodename, &numeric) == 1) {
        remote.sin_addr = numeric;
        routeResult = RouteTcp(s, &remote);
    } else if (IsNumericIp(nodename)) {
        return FailClosedBoolean("WSAConnectByNameA IPv6", WSAEAFNOSUPPORT);
    } else {
        uint32_t dummyIp = 0;
        if (!StoreDummy(nodename, port, &dummyIp)) return FailClosedBoolean("WSAConnectByNameA DNS map", WSAENOBUFS);
        remote.sin_addr.s_addr = dummyIp;
        routeResult = RouteTcpDomain(s, nodename, port);
    }
    if (routeResult != 0) return FALSE;
    if (RemoteAddress && RemoteAddressLength && *RemoteAddressLength >= sizeof(remote)) {
        memcpy(RemoteAddress, &remote, sizeof(remote));
        *RemoteAddressLength = sizeof(remote);
    }
    if (LocalAddress && LocalAddressLength) {
        int localLength = (int)*LocalAddressLength;
        if (getsockname(s, LocalAddress, &localLength) == 0) *LocalAddressLength = (DWORD)localLength;
    }
    return TRUE;
}

// WSAConnectByList — list of addresses. Rare; we route through first IPv4 dummy.
static INT WINAPI My_WSAConnectByList(SOCKET s, PSOCKET_ADDRESS_LIST list,
    LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
    LPTIMEVAL timeout, LPOVERLAPPED lpOverlapped) {
    if (!g_config.enabled || !list || list->iAddressCount <= 0) {
        return g_orig_WSAConnectByList(s, list, LocalAddressLength, LocalAddress,
            RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    if (lpOverlapped) return FailClosedBoolean("WSAConnectByList overlapped");
    for (int i = 0; i < list->iAddressCount; i++) {
        SOCKADDR* a = list->Address[i].lpSockaddr;
        int addressLength = list->Address[i].iSockaddrLength;
        if (!a || a->sa_family != AF_INET || addressLength < (int)sizeof(sockaddr_in)) continue;
        if (IsLoopbackAddress(a, addressLength))
            return g_orig_WSAConnectByList(s, list, LocalAddressLength, LocalAddress,
                RemoteAddressLength, RemoteAddress, timeout, NULL);
        return RouteTcp(s, (sockaddr_in*)a) == 0 ? TRUE : FALSE;
    }
    return FailClosedBoolean("WSAConnectByList address family", WSAEAFNOSUPPORT);
}

// ConnectEx — redirected at the ADDRESS level (inline hook on the real
// implementation resolved via WSAIoctl; it is NOT exported by name). Instead of
// emulating the operation synchronously (which breaks IOCP-based async clients
// like DreamPoeBot's auth HttpClient — they never observe the completion and
// time out), we call the REAL ConnectEx against the proxy address so the OS
// delivers overlapped completion natively, and defer the SOCKS5 CONNECT
// handshake to the first send/WSASend on that socket.
static BOOL PASCAL My_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped) {
    if (!g_config.enabled || !name || namelen <= 0) {
        if (g_orig_ConnectEx) return g_orig_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        WSASetLastError(WSAEFAULT);
        return FALSE;
    }
    if (IsLoopbackAddress(name, namelen) && g_orig_ConnectEx) {
        return g_orig_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }
    if (IsUdpSocket(s)) return FailClosedBoolean("ConnectEx UDP");
    if (lpSendBuffer && dwSendDataLength > 0) {
        // Initial data cannot be interposed before the SOCKS5 handshake.
        return FailClosedBoolean("ConnectEx initial data");
    }
    sockaddr_in target = {};
    if (!TryGetIpv4Endpoint(name, namelen, &target))
        return FailClosedBoolean("ConnectEx address family", WSAEAFNOSUPPORT);
    uint16_t port = ntohs(target.sin_port);
    char hostname[256] = {0};
    const char* hostnamePointer = NULL;
    if (IsDummyIp(target.sin_addr.s_addr)
        && LookupDummy(target.sin_addr.s_addr, hostname, sizeof(hostname), NULL)) {
        hostnamePointer = hostname;
    }
    sockaddr_in proxyAddress = {};
    if (!ResolveIpv4(g_config.socks5Host, g_config.socks5Port, &proxyAddress))
        return FailClosedBoolean("ConnectEx proxy resolution");
    sockaddr_storage socketProxyAddress = {};
    int socketProxyAddressLength = 0;
    if (!FormatProxyEndpointForSocket(s, proxyAddress, &socketProxyAddress, &socketProxyAddressLength))
        return FailClosedBoolean("ConnectEx socket family", WSAEAFNOSUPPORT);
    StorePendingConnect(s, hostnamePointer, port, target.sin_addr.s_addr);
    if (hostnamePointer) {
        Log("ConnectEx deferred: %s:%u — real ConnectEx to %s:%u, SOCKS5 on first send",
            hostnamePointer, (unsigned)port, g_config.socks5Host, (unsigned)g_config.socks5Port);
    }
    return g_orig_ConnectEx(s, (const struct sockaddr*)&socketProxyAddress, socketProxyAddressLength,
        NULL, 0, NULL, lpOverlapped);
}

// send — completes the deferred SOCKS5 handshake before the first payload byte.
static int WINAPI My_send(SOCKET s, const char* buf, int len, int flags) {
    if (g_config.enabled && !CompletePendingSendHandshake(s)) return SOCKET_ERROR;
    return g_orig_send(s, buf, len, flags);
}

// WSASend — completes the deferred SOCKS5 handshake before the first payload byte.
static int WINAPI My_WSASend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD nsent, DWORD flags,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_config.enabled && !CompletePendingSendHandshake(s)) return SOCKET_ERROR;
    return g_orig_WSASend(s, bufs, count, nsent, flags, ov, cr);
}

// --- DNS hooks: return dummy IPs, store hostname for domain-mode SOCKS5 ---

static int WINAPI My_getaddrinfo(PCSTR node, PCSTR service,
    const ADDRINFOA* hints, PADDRINFOA* result) {
    if (!g_config.enabled || !node || IsNumericIp(node) || IsLoopbackHostname(node))
        return g_orig_getaddrinfo(node, service, hints, result);
    if (!result || (hints && (hints->ai_flags & AI_NUMERICHOST))) return EAI_NONAME;
    uint16_t port = 0;
    if (service) ParseServicePort(service, &port);
    uint32_t dummyIp = 0;
    if (!StoreDummy(node, port, &dummyIp)) return EAI_MEMORY;
    IN_ADDR address = {}; address.s_addr = dummyIp;
    char numericHost[INET_ADDRSTRLEN] = {0};
    if (!InetNtopA(AF_INET, &address, numericHost, sizeof(numericHost))) return EAI_FAIL;
    ADDRINFOA localHints = {};
    if (hints) localHints = *hints;
    localHints.ai_family = AF_INET;
    localHints.ai_flags |= AI_NUMERICHOST;
    int resultCode = g_orig_getaddrinfo(numericHost, service, &localHints, result);
    if (resultCode == 0) Log("getaddrinfo(%s) -> dummy %s", node, numericHost);
    return resultCode;
}

static int WINAPI My_GetAddrInfoW(PCWSTR node, PCWSTR service,
    const ADDRINFOW* hints, PADDRINFOW* result) {
    if (!g_config.enabled || !node)
        return g_orig_GetAddrInfoW(node, service, hints, result);
    char narrow[256] = {0};
    if (WideCharToMultiByte(CP_UTF8, 0, node, -1, narrow, sizeof(narrow)-1, NULL, NULL) <= 0)
        return EAI_FAIL;
    if (IsNumericIp(narrow) || IsLoopbackHostname(narrow))
        return g_orig_GetAddrInfoW(node, service, hints, result);
    if (!result || (hints && (hints->ai_flags & AI_NUMERICHOST))) return EAI_NONAME;
    uint16_t port = 0;
    if (service) {
        char serviceNarrow[16] = {0};
        if (WideCharToMultiByte(CP_UTF8, 0, service, -1, serviceNarrow, sizeof(serviceNarrow)-1, NULL, NULL) > 0)
            ParseServicePort(serviceNarrow, &port);
    }
    uint32_t dummyIp = 0;
    if (!StoreDummy(narrow, port, &dummyIp)) return EAI_MEMORY;
    IN_ADDR address = {}; address.s_addr = dummyIp;
    wchar_t numericHost[INET_ADDRSTRLEN] = {0};
    if (!InetNtopW(AF_INET, &address, numericHost, INET_ADDRSTRLEN)) return EAI_FAIL;
    ADDRINFOW localHints = {};
    if (hints) localHints = *hints;
    localHints.ai_family = AF_INET;
    localHints.ai_flags |= AI_NUMERICHOST;
    int resultCode = g_orig_GetAddrInfoW(numericHost, service, &localHints, result);
    if (resultCode == 0) Log("GetAddrInfoW(%s) -> dummy", narrow);
    return resultCode;
}

static struct hostent* WINAPI My_gethostbyname(const char* name) {
    if (!g_config.enabled || !name || IsNumericIp(name) || IsLoopbackHostname(name))
        return g_orig_gethostbyname(name);
    uint32_t dummyIp = 0;
    if (!StoreDummy(name, 0, &dummyIp)) {
        WSASetLastError(WSAENOBUFS);
        return NULL;
    }
    IN_ADDR address = {}; address.s_addr = dummyIp;
    char numericHost[INET_ADDRSTRLEN] = {0};
    if (!InetNtopA(AF_INET, &address, numericHost, sizeof(numericHost))) return NULL;
    struct hostent* result = g_orig_gethostbyname(numericHost);
    if (result) Log("gethostbyname(%s) -> dummy %s", name, numericHost);
    return result;
}

static void FormatReadyEventName(DWORD processId, wchar_t* buffer, size_t length) {
    if (!buffer || length == 0) return;
    _snwprintf(buffer, length - 1, L"Local\\ABF.ProxyPayload.Ready.%lu", processId);
    buffer[length - 1] = 0;
}

static bool WaitForPayloadReady(DWORD processId, DWORD timeoutMilliseconds) {
    wchar_t eventName[96] = {0};
    FormatReadyEventName(processId, eventName, sizeof(eventName) / sizeof(eventName[0]));
    ULONGLONG deadline = GetTickCount64() + timeoutMilliseconds;
    while (GetTickCount64() < deadline) {
        HANDLE ready = OpenEventW(SYNCHRONIZE, FALSE, eventName);
        if (ready) {
            DWORD remaining = (DWORD)std::min<ULONGLONG>(deadline - GetTickCount64(), 0xFFFFFFFFULL);
            bool signaled = WaitForSingleObject(ready, remaining) == WAIT_OBJECT_0;
            CloseHandle(ready);
            return signaled;
        }
        Sleep(25);
    }
    return false;
}

// Synchronous DLL injection into a child process.
// Writes dllPath, fires LoadLibraryW via CreateRemoteThread, waits for completion,
// and verifies the thread exit code (HMODULE) is non-zero. Returns true only on
// confirmed load.
static bool InjectDllSynchronous(HANDLE hProcess, DWORD processId, const wchar_t* dllPath) {
    SIZE_T sz = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID mem = VirtualAllocEx(hProcess, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        Log("InjectDllSynchronous: VirtualAllocEx failed: %lu", GetLastError());
        return false;
    }
    bool loaded = false;
    bool remoteThreadCompleted = false;
    SIZE_T written = 0;
    if (WriteProcessMemory(hProcess, mem, dllPath, sz, &written) && written == sz) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC loadlib = GetProcAddress(k32, "LoadLibraryW");
        if (loadlib) {
            HANDLE t = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
            if (t) {
                DWORD waitResult = WaitForSingleObject(t, 10000);
                remoteThreadCompleted = waitResult == WAIT_OBJECT_0;
                DWORD exitCode = STILL_ACTIVE;
                loaded = remoteThreadCompleted
                    && GetExitCodeThread(t, &exitCode)
                    && exitCode != 0
                    && exitCode != STILL_ACTIVE;
                if (!loaded) Log("InjectDllSynchronous: LoadLibraryW verification failed wait=0x%08lx exit=%lu", waitResult, exitCode);
                CloseHandle(t);
            } else {
                Log("InjectDllSynchronous: CreateRemoteThread failed: %lu", GetLastError());
            }
        } else {
            Log("InjectDllSynchronous: LoadLibraryW not found");
        }
    } else {
        Log("InjectDllSynchronous: WriteProcessMemory failed: %lu", GetLastError());
    }
    if (remoteThreadCompleted) VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    if (loaded && !WaitForPayloadReady(processId, 10000)) {
        Log("InjectDllSynchronous: payload readiness timed out for PID=%lu", processId);
        loaded = false;
    }
    return loaded;
}

// Child-process injection + --language override through the complete CreateProcessInternalW ABI.
//   1. Save the caller's original dwCreationFlags.
//   2. Force CREATE_SUSPENDED before calling the original so the child's main
//      thread is paused before any user code executes.
//   3. After the original succeeds, synchronously inject ProxyPayload.dll.
//   4. Verify the LoadLibraryW exit code (HMODULE) != 0. On failure, terminate
//      the child and return FALSE so the caller never holds an unhooked process.
//   5. Resume only if the caller did NOT originally request suspension.
//
// Convert a wide string to a stack UTF-8 buffer (best-effort, truncates).
static void WideToUtf8(LPCWSTR w, char* out, size_t outLen) {
    if (!out || outLen == 0) return;
    out[0] = 0;
    if (!w) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)outLen - 1, NULL, NULL);
    out[outLen - 1] = 0;
}

// If `cmd` contains a `--language <value>` token, return a copy with that value replaced by
// `langOverrideW`; otherwise return `cmd` unchanged. Caller must keep the result alive across
// the real CreateProcessInternalW call.
static std::wstring RewriteLanguageArg(LPCWSTR cmd, const std::wstring& langOverrideW) {
    if (!cmd) return std::wstring();
    std::wstring s(cmd);
    const std::wstring tag = L"--language";
    size_t pos = s.find(tag);
    if (pos == std::wstring::npos) return s; // not a language-carrying spawn — leave untouched

    size_t valStart = pos + tag.size();
    while (valStart < s.size() && (s[valStart] == L' ' || s[valStart] == L'\t')) valStart++;

    size_t valEnd = valStart;
    if (valStart < s.size() && s[valStart] == L'"') {
        valEnd = valStart + 1;
        while (valEnd < s.size() && s[valEnd] != L'"') valEnd++;
        if (valEnd < s.size()) valEnd++; // include closing quote in the replaced span
    } else {
        while (valEnd < s.size() && s[valEnd] != L' ' && s[valEnd] != L'\t') valEnd++;
    }

    std::wstring repl = L"--language \"" + langOverrideW + L"\"";
    s.replace(pos, valEnd - pos, repl);
    return s;
}

static BOOL WINAPI My_CreateProcessInternalW(HANDLE token, LPCWSTR app, LPWSTR cmdline,
    LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInfo, PHANDLE newToken) {

    LPCWSTR origCmdline = cmdline;

    // Diagnostic: record the executable and structural command-line facts only.
    // Never persist the full launcher command line because it may carry auth material.
    {
        char appA[MAX_PATH] = {0}; WideToUtf8(app, appA, MAX_PATH);
        Log("CreateProcessInternalW: app='%s' commandLinePresent=%d languageArgPresent=%d",
            appA, origCmdline != NULL, origCmdline && wcsstr(origCmdline, L"--language") != NULL);
    }

    // Optional --language override: force the game client to a fixed language regardless of
    // OS locale (the launcher otherwise passes --language <system-locale>, which overrides the
    // account setting for the whole session).
    std::wstring rewritten;
    bool commandLineRewritten = false;
    if (origCmdline && g_config.languageOverride[0]) {
        wchar_t langW[16] = {0};
        MultiByteToWideChar(CP_UTF8, 0, g_config.languageOverride, -1, langW, 15);
        rewritten = RewriteLanguageArg(origCmdline, langW);
        if (rewritten != origCmdline) {
            commandLineRewritten = true;
            Log("CreateProcessInternalW: --language overridden");
        }
    }

    DWORD callerFlags = flags;
    BOOL callerSuspended = (callerFlags & CREATE_SUSPENDED) != 0;

    // Always force CREATE_SUSPENDED so hooks land before any user code runs.
    DWORD forcedFlags = callerFlags | CREATE_SUSPENDED;

    LPWSTR mutableCmdToPass = commandLineRewritten ? rewritten.data() : cmdline;
    BOOL r = g_orig_CreateProcessInternalW(token, app, mutableCmdToPass,
        processAttributes, threadAttributes, inherit, forcedFlags, env, cwd,
        startupInfo, processInfo, newToken);
    if (!r || !processInfo || !processInfo->hProcess) return r;
    if (g_dllPath[0] == 0 || processInfo->dwProcessId == GetCurrentProcessId()) {
        Log("CreateProcessInternalW: payload path unavailable for child PID=%lu", processInfo->dwProcessId);
        TerminateProcess(processInfo->hProcess, 1);
        WaitForSingleObject(processInfo->hProcess, 5000);
        CloseHandle(processInfo->hThread);
        CloseHandle(processInfo->hProcess);
        ZeroMemory(processInfo, sizeof(PROCESS_INFORMATION));
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    // Synchronous injection of ProxyPayload.dll into the suspended child.
    bool injected = InjectDllSynchronous(processInfo->hProcess, processInfo->dwProcessId, g_dllPath);
    if (!injected) {
        Log("CreateProcessInternalW: injection FAILED for child PID=%lu — terminating", processInfo->dwProcessId);
        TerminateProcess(processInfo->hProcess, 1);
        WaitForSingleObject(processInfo->hProcess, 5000);
        CloseHandle(processInfo->hThread);
        CloseHandle(processInfo->hProcess);
        ZeroMemory(processInfo, sizeof(PROCESS_INFORMATION));
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    Log("CreateProcessInternalW: injected into child PID=%lu (callerSuspended=%d)", processInfo->dwProcessId, (int)callerSuspended);

    // Resume only if the caller did NOT originally request suspension.
    if (!callerSuspended) {
        if (ResumeThread(processInfo->hThread) == (DWORD)-1) {
            Log("CreateProcessInternalW: ResumeThread failed for child PID=%lu", processInfo->dwProcessId);
            TerminateProcess(processInfo->hProcess, 1);
            WaitForSingleObject(processInfo->hProcess, 5000);
            CloseHandle(processInfo->hThread);
            CloseHandle(processInfo->hProcess);
            ZeroMemory(processInfo, sizeof(PROCESS_INFORMATION));
            SetLastError(ERROR_DLL_INIT_FAILED);
            return FALSE;
        }
    }
    return r;
}

// ============================================================================
// Config loader
// ============================================================================
static bool LoadConfig() {
    char path[MAX_PATH] = {0};
    bool envSpecified = false;
    ProxyConfig loaded = { "", 0, "", "", FALSE, 3, "" };

    // 1. Honor ABF_PROXY_CONFIG_PATH when set. If set but the file is missing or
    //    unreadable, fail loudly WITHOUT falling back to adjacent files.
    char envPath[MAX_PATH] = {0};
    DWORD envLen = GetEnvironmentVariableA("ABF_PROXY_CONFIG_PATH", envPath, MAX_PATH);
    if (envLen > 0 && envLen < MAX_PATH) {
        envSpecified = true;
        memcpy(path, envPath, envLen);
        path[envLen] = 0;
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
            Log("ABF_PROXY_CONFIG_PATH set but file missing: %s — config load FAILED (no fallback)", path);
            return false;
        }
    } else if (envLen >= MAX_PATH) {
        Log("ABF_PROXY_CONFIG_PATH is too long");
        return false;
    }

    // 2. Safe fallback (late injection): proxy_config.txt next to the DLL.
    if (!envSpecified) {
        HMODULE hm;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)&LoadConfig, &hm) && GetModuleFileNameA(hm, path, MAX_PATH)) {
            char* slash = strrchr(path, '\\');
            if (slash) strcpy(slash + 1, "proxy_config.txt");
            if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) path[0] = 0;
        }
        if (!path[0]) return false;
    }

    FILE* f = fopen(path, "r");
    if (!f) {
        if (envSpecified) Log("ABF_PROXY_CONFIG_PATH set but file unreadable: %s — config load FAILED (no fallback)", path);
        return false;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
        if (line[0] == 0 || line[0] == '#') continue;
        char* eq = strchr(line, '='); if (!eq) continue;
        *eq = 0; char* k = line; char* v = eq + 1;
        if (_stricmp(k, "SOCKS5_HOST") == 0) strncpy(loaded.socks5Host, v, sizeof(loaded.socks5Host)-1);
        else if (_stricmp(k, "SOCKS5_PORT") == 0) loaded.socks5Port = (uint16_t)atoi(v);
        else if (_stricmp(k, "SOCKS5_USER") == 0) strncpy(loaded.socks5User, v, sizeof(loaded.socks5User)-1);
        else if (_stricmp(k, "SOCKS5_PASS") == 0) strncpy(loaded.socks5Pass, v, sizeof(loaded.socks5Pass)-1);
        else if (_stricmp(k, "TIMEOUT_SEC") == 0) loaded.timeoutSec = atoi(v);
        else if (_stricmp(k, "LANGUAGE") == 0) strncpy(loaded.languageOverride, v, sizeof(loaded.languageOverride)-1);
    }
    fclose(f);
    loaded.socks5Host[sizeof(loaded.socks5Host)-1] = 0;
    loaded.socks5User[sizeof(loaded.socks5User)-1] = 0;
    loaded.socks5Pass[sizeof(loaded.socks5Pass)-1] = 0;
    loaded.languageOverride[sizeof(loaded.languageOverride)-1] = 0;
    if (!loaded.socks5Host[0] || loaded.socks5Port == 0) {
        Log("Config validation failed: proxy host or port is missing");
        return false;
    }
    if (loaded.timeoutSec < 1 || loaded.timeoutSec > 30) {
        Log("Config validation failed: TIMEOUT_SEC must be between 1 and 30");
        return false;
    }
    loaded.enabled = TRUE;
    g_config = loaded;
    Log("Config loaded from %s: proxy=%s:%d auth=%s language=%s", path,
        g_config.socks5Host, g_config.socks5Port, g_config.socks5User[0] ? "yes" : "no",
        g_config.languageOverride[0] ? g_config.languageOverride : "(none)");
    return true;
}

// ============================================================================
// Hook installation
// ============================================================================
struct HookStatus { const wchar_t* dll; const char* fn; bool ok; };
static HookStatus g_hookStatus[32];
static int g_hookStatusCount = 0;

static bool InstallHooks() {
    struct { const wchar_t* dll; const char* fn; LPVOID hook; LPVOID* orig; } hooks[] = {
        // Core TCP/UDP routing
        { L"ws2_32", "connect", (LPVOID)My_connect, (LPVOID*)&g_orig_connect },
        { L"ws2_32", "bind", (LPVOID)My_bind, (LPVOID*)&g_orig_bind },
        { L"ws2_32", "closesocket", (LPVOID)My_closesocket, (LPVOID*)&g_orig_closesocket },
        { L"ws2_32", "send", (LPVOID)My_send, (LPVOID*)&g_orig_send },
        { L"ws2_32", "WSASend", (LPVOID)My_WSASend, (LPVOID*)&g_orig_WSASend },
        { L"ws2_32", "sendto", (LPVOID)My_sendto, (LPVOID*)&g_orig_sendto },
        { L"ws2_32", "recvfrom", (LPVOID)My_recvfrom, (LPVOID*)&g_orig_recvfrom },
        { L"ws2_32", "WSASendTo", (LPVOID)My_WSASendTo, (LPVOID*)&g_orig_WSASendTo },
        { L"ws2_32", "WSARecvFrom", (LPVOID)My_WSARecvFrom, (LPVOID*)&g_orig_WSARecvFrom },
        { L"ws2_32", "WSAEventSelect", (LPVOID)My_WSAEventSelect, (LPVOID*)&g_orig_WSAEventSelect },
        { L"ws2_32", "WSAAsyncSelect", (LPVOID)My_WSAAsyncSelect, (LPVOID*)&g_orig_WSAAsyncSelect },
        { L"ws2_32", "ioctlsocket", (LPVOID)My_ioctlsocket, (LPVOID*)&g_orig_ioctlsocket },
        // Zero-leak: alternative TCP connect APIs
        { L"ws2_32", "WSAConnect", (LPVOID)My_WSAConnect, (LPVOID*)&g_orig_WSAConnect },
        { L"ws2_32", "WSAConnectByNameW", (LPVOID)My_WSAConnectByNameW, (LPVOID*)&g_orig_WSAConnectByNameW },
        { L"ws2_32", "WSAConnectByNameA", (LPVOID)My_WSAConnectByNameA, (LPVOID*)&g_orig_WSAConnectByNameA },
        { L"ws2_32", "WSAConnectByList", (LPVOID)My_WSAConnectByList, (LPVOID*)&g_orig_WSAConnectByList },
        // Zero-leak: DNS via dummy IPs
        { L"ws2_32", "getaddrinfo", (LPVOID)My_getaddrinfo, (LPVOID*)&g_orig_getaddrinfo },
        { L"ws2_32", "GetAddrInfoW", (LPVOID)My_GetAddrInfoW, (LPVOID*)&g_orig_GetAddrInfoW },
        { L"ws2_32", "gethostbyname", (LPVOID)My_gethostbyname, (LPVOID*)&g_orig_gethostbyname },
        // Zero-leak: block IPv6 + raw sockets
        { L"ws2_32", "socket", (LPVOID)My_socket, (LPVOID*)&g_orig_socket },
    };
    g_hookStatusCount = 0;
    bool anyFailed = false;
    // Resolve the real ConnectEx implementation through WSAIoctl (the only documented
    // acquisition path — ConnectEx is NOT exported by name from mswsock) and hook it
    // BY ADDRESS. The inline patch on the real implementation covers every way the
    // application can obtain the pointer (WSAIoctl query, GetProcAddress, caching).
    // Hooks are not enabled yet, so this WSAIoctl call reaches the real function.
    LPVOID connectExTarget = NULL;
    {
        SOCKET probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int probeResult = SOCKET_ERROR;
        DWORD probeError = probe == INVALID_SOCKET ? WSAGetLastError() : 0;
        if (probe != INVALID_SOCKET) {
            DWORD returned = 0;
            probeResult = WSAIoctl(probe, SIO_GET_EXTENSION_FUNCTION_POINTER,
                (LPVOID)&g_WSAID_CONNECTEX, sizeof(g_WSAID_CONNECTEX),
                &connectExTarget, sizeof(connectExTarget), &returned, NULL, NULL);
            if (probeResult != 0) {
                probeError = WSAGetLastError();
                connectExTarget = NULL;
            }
            closesocket(probe);
        }
        Log("ConnectEx probe: socket=%llu ioctl=%d error=%d target=%p",
            (unsigned long long)probe, probeResult, (int)probeError, connectExTarget);
    }
    for (auto& h : hooks) {
        MH_STATUS s = MH_CreateHookApi(h.dll, h.fn, h.hook, h.orig);
        bool ok = (s == MH_OK);
        if (g_hookStatusCount < 32) {
            g_hookStatus[g_hookStatusCount].dll = h.dll;
            g_hookStatus[g_hookStatusCount].fn = h.fn;
            g_hookStatus[g_hookStatusCount].ok = ok;
            g_hookStatusCount++;
        }
        if (!ok) {
            anyFailed = true;
            Log("HOOK_FAILURE: %ls!%s (MH_STATUS=%d)", h.dll, h.fn, (int)s);
        } else {
            Log("Hook %s installed", h.fn);
        }
    }

    const wchar_t* childProcessModule = L"kernelbase.dll";
    MH_STATUS childProcessStatus = MH_CreateHookApi(childProcessModule, "CreateProcessInternalW",
        (LPVOID)My_CreateProcessInternalW, (LPVOID*)&g_orig_CreateProcessInternalW);
    if (childProcessStatus != MH_OK) {
        childProcessModule = L"kernel32.dll";
        childProcessStatus = MH_CreateHookApi(childProcessModule, "CreateProcessInternalW",
            (LPVOID)My_CreateProcessInternalW, (LPVOID*)&g_orig_CreateProcessInternalW);
    }
    bool childProcessHookOk = childProcessStatus == MH_OK;
    if (g_hookStatusCount < 32) {
        g_hookStatus[g_hookStatusCount].dll = childProcessModule;
        g_hookStatus[g_hookStatusCount].fn = "CreateProcessInternalW";
        g_hookStatus[g_hookStatusCount].ok = childProcessHookOk;
        g_hookStatusCount++;
    }
    if (!childProcessHookOk) {
        anyFailed = true;
        Log("HOOK_FAILURE: CreateProcessInternalW in kernelbase/kernel32 (MH_STATUS=%d)", (int)childProcessStatus);
    } else {
        Log("Hook %ls!CreateProcessInternalW installed", childProcessModule);
    }

    // ConnectEx by address: fail closed when the implementation cannot be resolved or hooked.
    bool connectExHookOk = false;
    if (connectExTarget) {
        MH_STATUS connectExStatus = MH_CreateHook(connectExTarget, (LPVOID)My_ConnectEx, (LPVOID*)&g_orig_ConnectEx);
        connectExHookOk = (connectExStatus == MH_OK);
        if (!connectExHookOk) {
            Log("HOOK_FAILURE: ConnectEx by address %p (MH_STATUS=%d)", connectExTarget, (int)connectExStatus);
        } else {
            Log("Hook ConnectEx (by address %p) installed", connectExTarget);
        }
    } else {
        Log("HOOK_FAILURE: ConnectEx implementation was not resolved via WSAIoctl");
    }
    if (g_hookStatusCount < 32) {
        g_hookStatus[g_hookStatusCount].dll = L"winsock";
        g_hookStatus[g_hookStatusCount].fn = "ConnectEx";
        g_hookStatus[g_hookStatusCount].ok = connectExHookOk;
        g_hookStatusCount++;
    }
    if (!connectExHookOk) {
        anyFailed = true;
    }

    if (anyFailed) {
        Log("InstallHooks: one or more hooks failed — rolling back");
        MH_Uninitialize();
        return false;
    }
    MH_STATUS s = MH_EnableHook(MH_ALL_HOOKS);
    if (s != MH_OK) {
        Log("HOOK_FAILURE: MH_EnableHook (MH_STATUS=%d)", (int)s);
        MH_Uninitialize();
        return false;
    }
    Log("All hooks enabled");
    return true;
}

// Per-PID readiness marker: <logDir>\<processName>_<PID>_ready.log
// Consumed by the host readiness gate (ProxyRuntimeService) to confirm all hooks
// are active before any navigation is allowed.
static void WriteReadinessLog() {
    if (g_logDir[0] == 0) return;

    wchar_t exePathW[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePathW, MAX_PATH);
    const wchar_t* exeNameW = wcsrchr(exePathW, L'\\');
    exeNameW = exeNameW ? exeNameW + 1 : exePathW;
    char exeName[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, exeNameW, -1, exeName, MAX_PATH, NULL, NULL);

    SYSTEMTIME st;
    GetLocalTime(&st);

    char path[MAX_PATH] = {0};
    _snprintf(path, MAX_PATH - 1, "%s\\%s_%lu_ready.log", g_logDir, exeName, GetCurrentProcessId());

    FILE* f = fopen(path, "w");
    if (!f) {
        Log("WriteReadinessLog: cannot write %s", path);
        return;
    }
    int okCount = 0, failCount = 0;
    for (int i = 0; i < g_hookStatusCount; i++) {
        if (g_hookStatus[i].ok) okCount++; else failCount++;
    }
    fprintf(f, "PID=%lu\n", GetCurrentProcessId());
    fprintf(f, "PROCESS=%s\n", exeName);
    fprintf(f, "TIMESTAMP=%04d-%02d-%02dT%02d:%02d:%02d\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fprintf(f, "STATUS=%s\n", (failCount == 0 && g_hookStatusCount > 0) ? "READY" : "HOOK_FAILURE");
    fprintf(f, "HOOK_COUNT=%d\n", g_hookStatusCount);
    fprintf(f, "HOOKS_OK=%d\n", okCount);
    fprintf(f, "HOOKS_FAIL=%d\n", failCount);
    for (int i = 0; i < g_hookStatusCount; i++) {
        fprintf(f, "%s=%s\n", g_hookStatus[i].fn, g_hookStatus[i].ok ? "OK" : "FAIL");
    }
    fclose(f);
    Log("Readiness marker written: %s (ok=%d fail=%d)", path, okCount, failCount);
}

// ============================================================================
// DLL entry
// ============================================================================
static void InitializeLogging() {
    char envLogDir[MAX_PATH] = {0};
    DWORD envLogLength = GetEnvironmentVariableA("ABF_PROXY_LOG_DIR", envLogDir, MAX_PATH);
    if (envLogLength > 0 && envLogLength < MAX_PATH) {
        memcpy(g_logDir, envLogDir, envLogLength);
        g_logDir[envLogLength] = 0;
    } else {
        WideCharToMultiByte(CP_ACP, 0, g_dllPath, -1, g_logDir, MAX_PATH, NULL, NULL);
        char* separator = strrchr(g_logDir, '\\');
        if (separator) *separator = 0;
    }
    size_t directoryLength = strlen(g_logDir);
    while (directoryLength > 0 && (g_logDir[directoryLength - 1] == '\\' || g_logDir[directoryLength - 1] == '/'))
        g_logDir[--directoryLength] = 0;

    char logPath[MAX_PATH] = {0};
    char envLogPath[MAX_PATH] = {0};
    DWORD envLogPathLength = GetEnvironmentVariableA("ABF_PROXY_LOG_PATH", envLogPath, MAX_PATH);
    if (envLogPathLength > 0 && envLogPathLength < MAX_PATH)
    {
        memcpy(logPath, envLogPath, envLogPathLength);
        logPath[envLogPathLength] = 0;
    }
    else
        _snprintf(logPath, MAX_PATH - 1, "%s\\proxy_v2_log.txt", g_logDir);
    g_logFile = fopen(logPath, "a");
}

static DWORD WINAPI InitializePayload(LPVOID) {
    wchar_t eventName[128] = {0};
    FormatReadyEventName(GetCurrentProcessId(), eventName, sizeof(eventName) / sizeof(eventName[0]));
    g_readyEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    InitializeLogging();
    Log("=== ProxyPayload v2 initialization PID=%lu ===", GetCurrentProcessId());
    Log("DLL path: %ls", g_dllPath);

    if (!LoadConfig()) {
        Log("Payload initialization failed: invalid or missing config");
        WriteReadinessLog();
        return 1;
    }
    WSADATA winsock = {};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        Log("Payload initialization failed: WSAStartup");
        WriteReadinessLog();
        return 1;
    }
    if (MH_Initialize() != MH_OK) {
        Log("Payload initialization failed: MH_Initialize");
        WriteReadinessLog();
        return 1;
    }
    if (!InstallHooks()) {
        Log("Payload initialization failed: hook installation");
        WriteReadinessLog();
        return 1;
    }
    WriteReadinessLog();
    if (!g_readyEvent || !SetEvent(g_readyEvent)) {
        Log("Payload initialization failed: readiness event");
        return 1;
    }
    Log("ProxyPayload v2 ready");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_dummyLock);
        GetModuleFileNameW(hMod, g_dllPath, MAX_PATH);
        HANDLE initializationThread = CreateThread(NULL, 0, InitializePayload, NULL, 0, NULL);
        if (!initializationThread) return FALSE;
        CloseHandle(initializationThread);
    }
    return TRUE;
}
