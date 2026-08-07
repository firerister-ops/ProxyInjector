// ProxyPayload v2 — Clean SOCKS5 proxy routing via inline hooks
//
// ARCHITECTURE (based on runetfreedom/force-proxy):
//   1. Hook connect() — redirect TCP through SOCKS5
//   2. Hook bind/sendto/recvfrom/WSASendTo/WSARecvFrom — UDP via SOCKS5 UDP ASSOCIATE
//   3. Hook ioctlsocket/WSAEventSelect — track non-blocking sockets
//   4. Hook closesocket — cleanup
//
// KEY INSIGHT: Chrome uses regular connect() (confirmed in Chromium source
// tcp_socket_win.cc). It does NOT use ConnectEx. The previous approach of
// hooking WSAIoctl/ConnectEx was wrong.
//
// For non-blocking sockets (Chrome always uses them): SOCKS5 handshake is
// performed synchronously via select() waits, then we return WSAEWOULDBLOCK
// so Chrome's async I/O machinery (WSAEventSelect + FD_CONNECT) works.
//
// Config: reads proxy_config.txt next to DLL or C:\proxy_config.txt

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <mutex>
#include <shared_mutex>

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
};

static ProxyConfig g_config = { "127.0.0.1", 1080, "", "", TRUE, 3 };
static wchar_t g_dllPath[MAX_PATH] = {0};

// ============================================================================
// Logging
// ============================================================================
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;

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
typedef int (WINAPI *pfn_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WINAPI *pfn_recvfrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WINAPI *pfn_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *pfn_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *pfn_WSAEventSelect)(SOCKET, WSAEVENT, long);
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
typedef BOOL (WINAPI *pfn_CreateProcessInternalW)(HANDLE, LPCWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, HANDLE);

// ConnectEx extension function pointer type
typedef BOOL (PASCAL *pfn_ConnectEx)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);

// ConnectEx GUID
static const GUID g_WSAID_CONNECTEX = {
    0x25a207b9, 0xddf3, 0x4660,
    {0x8e, 0xe9, 0xfb, 0x9f, 0xde, 0xb1, 0x87, 0x6e}
};

static pfn_connect g_orig_connect = NULL;
static pfn_bind g_orig_bind = NULL;
static pfn_closesocket g_orig_closesocket = NULL;
static pfn_sendto g_orig_sendto = NULL;
static pfn_recvfrom g_orig_recvfrom = NULL;
static pfn_WSASendTo g_orig_WSASendTo = NULL;
static pfn_WSARecvFrom g_orig_WSARecvFrom = NULL;
static pfn_WSAEventSelect g_orig_WSAEventSelect = NULL;
static pfn_ioctlsocket g_orig_ioctlsocket = NULL;
static pfn_WSAConnect g_orig_WSAConnect = NULL;
static pfn_WSAConnectByNameW g_orig_WSAConnectByNameW = NULL;
static pfn_WSAConnectByNameA g_orig_WSAConnectByNameA = NULL;
static pfn_WSAConnectByList g_orig_WSAConnectByList = NULL;
static pfn_WSAIoctl g_orig_WSAIoctl = NULL;
static pfn_getaddrinfo g_orig_getaddrinfo = NULL;
static pfn_GetAddrInfoW g_orig_GetAddrInfoW = NULL;
static pfn_gethostbyname g_orig_gethostbyname = NULL;
static pfn_socket g_orig_socket = NULL;
// g_orig_ConnectEx obtained lazily via real WSAIoctl when first needed
static pfn_ConnectEx g_real_ConnectEx = NULL;
static pfn_CreateProcessInternalW g_orig_CreateProcessInternalW = NULL;

// ============================================================================
// Non-blocking socket tracking + UDP association map
// ============================================================================
static std::shared_mutex g_socketsMutex;
static std::map<SOCKET, long> g_nonBlockingSockets;  // socket -> network events

// UDP association: each UDP socket has a dedicated TCP control socket to proxy
struct UdpAssoc {
    SOCKET proxySock;            // TCP socket to proxy (for UDP ASSOCIATE)
    sockaddr_in udpProxyAddr;    // Address to send UDP packets to (via sendto)
};
static std::map<SOCKET, UdpAssoc> g_udpAssocMap;

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
    std::unique_lock<std::shared_mutex> lock(g_socketsMutex);
    g_nonBlockingSockets.erase(s);
    auto it = g_udpAssocMap.find(s);
    if (it != g_udpAssocMap.end()) {
        if (it->second.proxySock != INVALID_SOCKET) {
            closesocket(it->second.proxySock);
        }
        g_udpAssocMap.erase(it);
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
#define DUMMY_IP_BASE 0xF0000000u  // 240.0.0.0 host-order
#define DUMMY_IP_MASK 0x00FFFFFFu

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
    return (ntohl(netOrderIp) >> 24) == 240;
}

static BOOL IsNumericIp(const char* s) {
    if (!s || !*s) return FALSE;
    int segs = 0, segLen = 0;
    for (const char* p = s; *p; p++) {
        if (*p == '.') { if (segLen == 0 || segLen > 3) return FALSE; segs++; segLen = 0; }
        else if (*p >= '0' && *p <= '9') segLen++;
        else return FALSE;
    }
    if (segLen == 0 || segLen > 3) return FALSE;
    return ++segs == 4;
}

// Store hostname → dummy IP, returns the dummy IP (network order)
static uint32_t StoreDummy(const char* hostname, uint16_t port) {
    uint32_t h = HashStr(hostname);
    uint32_t netIp = htonl(DUMMY_IP_BASE | (h & DUMMY_IP_MASK));
    EnterCriticalSection(&g_dummyLock);
    uint32_t idx = h % DUMMY_HASH_SIZE;
    for (uint32_t i = 0; i < DUMMY_HASH_SIZE; i++) {
        uint32_t s = (idx + i) % DUMMY_HASH_SIZE;
        if (!g_dummyTable[s].used) {
            g_dummyTable[s].netOrderIp = netIp;
            strncpy(g_dummyTable[s].hostname, hostname, 255);
            g_dummyTable[s].hostname[255] = 0;
            g_dummyTable[s].port = port;
            g_dummyTable[s].used = true;
            break;
        }
    }
    LeaveCriticalSection(&g_dummyLock);
    return netIp;
}

// Look up hostname from dummy IP. Returns NULL if not found.
static const char* LookupDummy(uint32_t netOrderIp, uint16_t* outPort) {
    EnterCriticalSection(&g_dummyLock);
    const char* result = NULL;
    for (uint32_t i = 0; i < DUMMY_HASH_SIZE; i++) {
        if (g_dummyTable[i].used && g_dummyTable[i].netOrderIp == netOrderIp) {
            if (outPort) *outPort = g_dummyTable[i].port;
            result = g_dummyTable[i].hostname;
            break;
        }
    }
    LeaveCriticalSection(&g_dummyLock);
    return result;
}

// ============================================================================
// SOCKS5 helpers (non-blocking aware via select())
// ============================================================================
static bool WaitWritable(SOCKET s, int timeoutSec) {
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    timeval tv = { timeoutSec, 0 };
    return select(0, NULL, &wset, NULL, &tv) > 0 && FD_ISSET(s, &wset);
}

static bool WaitReadable(SOCKET s, int timeoutSec) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval tv = { timeoutSec, 0 };
    return select(0, &rset, NULL, NULL, &tv) > 0 && FD_ISSET(s, &rset);
}

// Connect socket to SOCKS5 proxy. Returns true on success.
static bool ConnectToProxy(SOCKET s, bool nonBlocking) {
    sockaddr_in pa = {};
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = inet_addr(g_config.socks5Host);
    pa.sin_port = htons(g_config.socks5Port);

    int r = g_orig_connect(s, (sockaddr*)&pa, sizeof(pa));
    if (r == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            Log("ConnectToProxy: connect failed err=%d", err);
            return false;
        }
        // Non-blocking: wait for writable
        if (nonBlocking && !WaitWritable(s, g_config.timeoutSec)) {
            Log("ConnectToProxy: wait writable timeout");
            return false;
        }
        // Check SO_ERROR
        int soErr = 0;
        int soLen = sizeof(soErr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &soLen);
        if (soErr != 0) {
            Log("ConnectToProxy: SO_ERROR=%d", soErr);
            return false;
        }
    }
    return true;
}

// Perform SOCKS5 auth negotiation + CONNECT request.
// targetAddr is the original sockaddr_in (ip:port) the app wanted.
// Returns true on success.
// SOCKS5 auth negotiation (shared between IPv4 and domain modes).
// Returns true on success (proxy accepted auth, ready for CONNECT).
static bool Socks5NegotiateAuth(SOCKET s, bool nonBlocking) {
    uint8_t buf[512];
    bool useAuth = (g_config.socks5User[0] != '\0');
    if (useAuth) {
        buf[0] = 0x05; buf[1] = 0x02; buf[2] = 0x00; buf[3] = 0x02;
    } else {
        buf[0] = 0x05; buf[1] = 0x01; buf[2] = 0x00;
    }
    int sendLen = useAuth ? 4 : 3;
    if (nonBlocking && !WaitWritable(s, g_config.timeoutSec)) return false;
    if (send(s, (const char*)buf, sendLen, 0) == SOCKET_ERROR) {
        Log("Socks5: auth send failed err=%d", WSAGetLastError());
        return false;
    }
    uint8_t resp[2];
    if (nonBlocking && !WaitReadable(s, g_config.timeoutSec)) return false;
    if (recv(s, (char*)resp, 2, 0) != 2 || resp[0] != 0x05) {
        Log("Socks5: auth recv failed");
        return false;
    }
    if (resp[1] == 0x02) {
        int ulen = (int)strlen(g_config.socks5User);
        int plen = (int)strlen(g_config.socks5Pass);
        int off = 0;
        buf[off++] = 0x01;
        buf[off++] = (uint8_t)ulen;
        memcpy(buf + off, g_config.socks5User, ulen); off += ulen;
        buf[off++] = (uint8_t)plen;
        memcpy(buf + off, g_config.socks5Pass, plen); off += plen;
        if (nonBlocking && !WaitWritable(s, g_config.timeoutSec)) return false;
        if (send(s, (const char*)buf, off, 0) == SOCKET_ERROR) return false;
        uint8_t aresp[2];
        if (nonBlocking && !WaitReadable(s, g_config.timeoutSec)) return false;
        if (recv(s, (char*)aresp, 2, 0) != 2 || aresp[1] != 0x00) {
            Log("Socks5: auth failed");
            return false;
        }
    } else if (resp[1] != 0x00) {
        Log("Socks5: unsupported method %d", resp[1]);
        return false;
    }
    return true;
}

// Read SOCKS5 CONNECT response after sending CONNECT request.
// Returns true on success (REP=0x00).
static bool Socks5ReadConnectResponse(SOCKET s, bool nonBlocking) {
    uint8_t r4[4];
    if (nonBlocking && !WaitReadable(s, g_config.timeoutSec)) return false;
    if (recv(s, (char*)r4, 4, 0) != 4 || r4[0] != 0x05) {
        Log("Socks5: CONNECT response recv failed");
        return false;
    }
    if (r4[1] != 0x00) {
        Log("Socks5: CONNECT rejected rep=%d", r4[1]);
        return false;
    }
    int extra = 0;
    if (r4[3] == 0x01) extra = 4 + 2;
    else if (r4[3] == 0x04) extra = 16 + 2;
    else if (r4[3] == 0x03) {
        uint8_t dlen = 0;
        if (recv(s, (char*)&dlen, 1, 0) != 1) return false;
        extra = dlen + 2;
    }
    if (extra > 0) {
        uint8_t tmp[256];
        int got = 0;
        while (got < extra) {
            if (nonBlocking && !WaitReadable(s, g_config.timeoutSec)) return false;
            int n = recv(s, (char*)tmp + got, extra - got, 0);
            if (n <= 0) return false;
            got += n;
        }
    }
    return true;
}

// SOCKS5 + CONNECT with IPv4 ATYP=0x01
static bool Socks5HandshakeAndConnect(SOCKET s, const sockaddr_in* target, bool nonBlocking) {
    if (!Socks5NegotiateAuth(s, nonBlocking)) return false;

    uint8_t buf[10] = { 0x05, 0x01, 0x00, 0x01 };
    memcpy(buf + 4, &target->sin_addr, 4);
    memcpy(buf + 8, &target->sin_port, 2);
    if (nonBlocking && !WaitWritable(s, g_config.timeoutSec)) return false;
    if (send(s, (const char*)buf, 10, 0) == SOCKET_ERROR) return false;
    return Socks5ReadConnectResponse(s, nonBlocking);
}

// SOCKS5 + CONNECT with domain ATYP=0x03 (proxy resolves hostname → no DNS leak)
static bool Socks5HandshakeAndConnectDomain(SOCKET s, const char* hostname, uint16_t port, bool nonBlocking) {
    if (!Socks5NegotiateAuth(s, nonBlocking)) return false;

    size_t hlen = strlen(hostname);
    if (hlen > 255) hlen = 255;
    uint8_t buf[512] = { 0x05, 0x01, 0x00, 0x03 };
    buf[4] = (uint8_t)hlen;
    memcpy(buf + 5, hostname, hlen);
    buf[5 + hlen] = (uint8_t)(port >> 8);
    buf[6 + hlen] = (uint8_t)(port & 0xFF);
    int total = 7 + (int)hlen;
    if (nonBlocking && !WaitWritable(s, g_config.timeoutSec)) return false;
    if (send(s, (const char*)buf, total, 0) == SOCKET_ERROR) return false;
    return Socks5ReadConnectResponse(s, nonBlocking);
}


// Top-level: route TCP connection through SOCKS5.
// For blocking sockets: returns 0 on success.
// For non-blocking sockets: returns SOCKET_ERROR with WSAEWOULDBLOCK
// (this is the correct idiom — Chrome waits for FD_CONNECT event).
// Top-level: route TCP connection through SOCKS5.
// If target IP is a dummy (240.x.x.x) → use domain-mode SOCKS5 (proxy resolves
// hostname — ISP DNS is bypassed). Otherwise use IPv4-mode SOCKS5.
static int RouteTcp(SOCKET s, const sockaddr_in* target) {
    char ipStr[32] = {0};
    inet_ntop(AF_INET, &target->sin_addr, ipStr, sizeof(ipStr));
    uint16_t port = ntohs(target->sin_port);
    bool nonBlocking = IsNonBlocking(s);

    // Detect dummy IP → resolve to hostname for ATYP=0x03 (domain) mode
    const char* hostname = NULL;
    if (IsDummyIp(target->sin_addr.s_addr)) {
        hostname = LookupDummy(target->sin_addr.s_addr, NULL);
    }

    if (hostname) {
        Log("connect(%s[=%s]:%d) nonBlocking=%d — routing via SOCKS5 domain",
            ipStr, hostname, port, nonBlocking);
    } else {
        Log("connect(%s:%d) nonBlocking=%d — routing via SOCKS5 %s:%d",
            ipStr, port, nonBlocking, g_config.socks5Host, g_config.socks5Port);
    }

    if (!ConnectToProxy(s, nonBlocking)) {
        // FAIL-CLOSED: no direct fallback. PROXY_FAIL event for ControlPanel.
        Log("PROXY_FAIL phase=tcp_connect target=%s:%d reason=proxy_unreachable",
            hostname ? hostname : ipStr, port);
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    bool ok = hostname
        ? Socks5HandshakeAndConnectDomain(s, hostname, port, nonBlocking)
        : Socks5HandshakeAndConnect(s, target, nonBlocking);
    if (!ok) {
        Log("PROXY_FAIL phase=socks5_handshake target=%s:%d reason=handshake_failed",
            hostname ? hostname : ipStr, port);
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    Log("PROXY_OK target=%s:%d via=%s:%d",
        hostname ? hostname : ipStr, port, g_config.socks5Host, g_config.socks5Port);

    if (nonBlocking) {
        // Critical: tell caller the connect is "in progress" so its async
        // machinery (WSAEventSelect FD_CONNECT) works as expected.
        WSASetLastError(WSAEWOULDBLOCK);
        return SOCKET_ERROR;
    }
    return 0;
}


// ============================================================================
// UDP via SOCKS5 UDP ASSOCIATE
// ============================================================================
static bool InitUdpAssociate(UdpAssoc* out) {
    out->proxySock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (out->proxySock == INVALID_SOCKET) return false;

    // Make proxy socket non-blocking temporarily for timeout-aware handshake
    u_long nb = 1;
    g_orig_ioctlsocket(out->proxySock, FIONBIO, &nb);

    if (!ConnectToProxy(out->proxySock, true)) return false;
    // Reuse handshake helper with a dummy target — but we need UDP ASSOCIATE,
    // not CONNECT. Do it inline.
    uint8_t buf[512];
    bool useAuth = (g_config.socks5User[0] != '\0');
    if (useAuth) { buf[0]=5; buf[1]=2; buf[2]=0; buf[3]=2; }
    else         { buf[0]=5; buf[1]=1; buf[2]=0; }

    if (!WaitWritable(out->proxySock, g_config.timeoutSec)) return false;
    if (send(out->proxySock, (const char*)buf, useAuth?4:3, 0) == SOCKET_ERROR) return false;
    uint8_t resp[2];
    if (!WaitReadable(out->proxySock, g_config.timeoutSec)) return false;
    if (recv(out->proxySock, (char*)resp, 2, 0) != 2 || resp[0] != 5) return false;

    if (resp[1] == 0x02) {
        int ulen=(int)strlen(g_config.socks5User), plen=(int)strlen(g_config.socks5Pass);
        int off=0; buf[off++]=1; buf[off++]=(uint8_t)ulen;
        memcpy(buf+off, g_config.socks5User, ulen); off+=ulen;
        buf[off++]=(uint8_t)plen; memcpy(buf+off, g_config.socks5Pass, plen); off+=plen;
        if (!WaitWritable(out->proxySock, g_config.timeoutSec)) return false;
        if (send(out->proxySock, (const char*)buf, off, 0) == SOCKET_ERROR) return false;
        uint8_t ar[2];
        if (!WaitReadable(out->proxySock, g_config.timeoutSec)) return false;
        if (recv(out->proxySock, (char*)ar, 2, 0) != 2 || ar[1] != 0) return false;
    } else if (resp[1] != 0) return false;

    // UDP ASSOCIATE
    uint8_t req[10] = { 5, 3, 0, 1, 0,0,0,0, 0,0 };
    if (!WaitWritable(out->proxySock, g_config.timeoutSec)) return false;
    if (send(out->proxySock, (const char*)req, 10, 0) == SOCKET_ERROR) return false;
    uint8_t r10[10];
    if (!WaitReadable(out->proxySock, g_config.timeoutSec)) return false;
    if (recv(out->proxySock, (char*)r10, 10, 0) != 10 || r10[1] != 0) return false;

    out->udpProxyAddr.sin_family = AF_INET;
    memcpy(&out->udpProxyAddr.sin_addr, r10 + 4, 4);
    memcpy(&out->udpProxyAddr.sin_port, r10 + 8, 2);
    return true;
}

// Build SOCKS5 UDP encapsulation header (10 bytes) + payload
static void EncapsulateUdp(WSABUF* dst, const char* buf, int len, const sockaddr* to) {
    dst->len = len + 10;
    dst->buf = (char*)malloc(dst->len);
    dst->buf[0]=0; dst->buf[1]=0; dst->buf[2]=0; dst->buf[3]=1;
    const sockaddr_in* a = (const sockaddr_in*)to;
    memcpy(dst->buf+4, &a->sin_addr, 4);
    memcpy(dst->buf+8, &a->sin_port, 2);
    memcpy(dst->buf+10, buf, len);
}

// ============================================================================
// Hooks
// ============================================================================
static int WINAPI My_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (!g_config.enabled || !name || namelen <= 0)
        return g_orig_connect(s, name, namelen);

    if (IsUdpSocket(s)) return g_orig_connect(s, name, namelen);

    // BLOCK IPv6 connect to non-local — prevents IPv6 leaks. localhost6 allowed.
    if (name->sa_family == AF_INET6) {
        Log("connect: BLOCKED AF_INET6 (IPv6 leak prevention)");
        WSASetLastError(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }

    if (name->sa_family != AF_INET) return g_orig_connect(s, name, namelen);

    const sockaddr_in* addr = (const sockaddr_in*)name;
    uint32_t ip = addr->sin_addr.s_addr;

    // Skip localhost and the proxy itself to avoid loops
    if (ip == inet_addr("127.0.0.1") || ip == 0) return g_orig_connect(s, name, namelen);
    uint32_t proxyIp = inet_addr(g_config.socks5Host);
    if (ip == proxyIp && addr->sin_port == htons(g_config.socks5Port)) {
        return g_orig_connect(s, name, namelen);
    }

    return RouteTcp(s, addr);
}

static int WINAPI My_bind(SOCKET s, const sockaddr* name, int namelen) {
    int r = g_orig_bind(s, name, namelen);
    if (!g_config.enabled || !IsUdpSocket(s)) return r;

    // Initiate UDP ASSOCIATE on first bind of a UDP socket
    {
        std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
        if (g_udpAssocMap.count(s)) return r;  // already associated
    }
    UdpAssoc a;
    if (InitUdpAssociate(&a)) {
        std::unique_lock<std::shared_mutex> lock(g_socketsMutex);
        g_udpAssocMap[s] = a;
        Log("UDP ASSOCIATE established for socket %llu", (unsigned long long)s);
    } else {
        Log("UDP ASSOCIATE failed for socket %llu", (unsigned long long)s);
    }
    return r;
}

static int WINAPI My_closesocket(SOCKET s) {
    UntrackSocket(s);
    return g_orig_closesocket(s);
}

static int WINAPI My_sendto(SOCKET s, const char* buf, int len, int flags,
                            const struct sockaddr* to, int tolen) {
    if (!g_config.enabled) return g_orig_sendto(s, buf, len, flags, to, tolen);

    // Skip multicast
    if (to && to->sa_family == AF_INET) {
        uint32_t ip = ntohl(((sockaddr_in*)to)->sin_addr.s_addr);
        if ((ip & 0xF0000000) == 0xE0000000) return g_orig_sendto(s, buf, len, flags, to, tolen);
    }

    UdpAssoc a;
    bool assoc = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
        auto it = g_udpAssocMap.find(s);
        if (it != g_udpAssocMap.end()) { a = it->second; assoc = true; }
    }
    if (!assoc) return g_orig_sendto(s, buf, len, flags, to, tolen);

    WSABUF dst;
    EncapsulateUdp(&dst, buf, len, to);
    int sent = g_orig_sendto(s, dst.buf, dst.len, 0, (sockaddr*)&a.udpProxyAddr, sizeof(a.udpProxyAddr));
    free(dst.buf);
    return sent;
}

static int WINAPI My_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD nsent,
                               DWORD flags, const struct sockaddr* to, int tolen,
                               LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (!g_config.enabled || count == 0 || !bufs || bufs->len == 0)
        return g_orig_WSASendTo(s, bufs, count, nsent, flags, to, tolen, ov, cr);

    if (to && to->sa_family == AF_INET) {
        uint32_t ip = ntohl(((sockaddr_in*)to)->sin_addr.s_addr);
        if ((ip & 0xF0000000) == 0xE0000000)
            return g_orig_WSASendTo(s, bufs, count, nsent, flags, to, tolen, ov, cr);
    }

    UdpAssoc a;
    bool assoc = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
        auto it = g_udpAssocMap.find(s);
        if (it != g_udpAssocMap.end()) { a = it->second; assoc = true; }
    }
    if (!assoc) return g_orig_WSASendTo(s, bufs, count, nsent, flags, to, tolen, ov, cr);

    WSABUF dst;
    EncapsulateUdp(&dst, bufs->buf, bufs->len, to);
    int r = g_orig_WSASendTo(s, &dst, 1, nsent, 0, (sockaddr*)&a.udpProxyAddr, sizeof(a.udpProxyAddr), ov, cr);
    free(dst.buf);
    return r;
}

static int WINAPI My_recvfrom(SOCKET s, char* buf, int len, int flags,
                              struct sockaddr* from, int* fromlen) {
    int got = g_orig_recvfrom(s, buf, len, flags, from, fromlen);
    if (got == SOCKET_ERROR || got < 10) return got;

    bool assoc = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
        assoc = g_udpAssocMap.count(s) > 0;
    }
    if (!assoc) return got;

    // Strip 10-byte SOCKS5 UDP header and rewrite `from`
    sockaddr_in* f = (sockaddr_in*)from;
    if (f) {
        memcpy(&f->sin_addr, buf + 4, 4);
        memcpy(&f->sin_port, buf + 8, 2);
    }
    memmove(buf, buf + 10, got - 10);
    return got - 10;
}

static int WINAPI My_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd,
                                 LPDWORD flags, struct sockaddr* from, LPINT fromlen,
                                 LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = g_orig_WSARecvFrom(s, bufs, count, recvd, flags, from, fromlen, ov, cr);
    if (r != 0 || !recvd || *recvd < 10) return r;

    bool assoc = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_socketsMutex);
        assoc = g_udpAssocMap.count(s) > 0;
    }
    if (!assoc) return r;

    sockaddr_in* f = (sockaddr_in*)from;
    if (f) {
        memcpy(&f->sin_addr, bufs->buf + 4, 4);
        memcpy(&f->sin_port, bufs->buf + 8, 2);
    }
    memmove(bufs->buf, bufs->buf + 10, *recvd - 10);
    *recvd -= 10;
    return r;
}

static int WSAAPI My_WSAEventSelect(SOCKET s, WSAEVENT ev, long events) {
    MarkNonBlocking(s, (ev != NULL && events != 0) ? events : 0);
    return g_orig_WSAEventSelect(s, ev, events);
}

static int WSAAPI My_ioctlsocket(SOCKET s, long cmd, u_long* argp) {
    if (cmd == FIONBIO && argp) {
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
    if (!g_config.enabled || !name || namelen <= 0 || name->sa_family != AF_INET || IsUdpSocket(s)) {
        return g_orig_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }
    const sockaddr_in* addr = (const sockaddr_in*)name;
    uint32_t ip = addr->sin_addr.s_addr;
    if (ip == inet_addr("127.0.0.1") || ip == 0) {
        return g_orig_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }
    uint32_t proxyIp = inet_addr(g_config.socks5Host);
    if (ip == proxyIp && addr->sin_port == htons(g_config.socks5Port)) {
        return g_orig_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }
    return RouteTcp(s, addr);
}

// WSAConnectByNameW — Chrome's DNS+connect in one call. Take hostname directly.
static INT WINAPI My_WSAConnectByNameW(SOCKET s, LPCWSTR nodename, LPCWSTR servicename,
    LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
    LPTIMEVAL timeout, LPOVERLAPPED lpOverlapped) {
    if (!g_config.enabled || !nodename || !*nodename) {
        return g_orig_WSAConnectByNameW(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    char narrow[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, nodename, -1, narrow, sizeof(narrow)-1, NULL, NULL);
    if (IsNumericIp(narrow)) {
        // Numeric IP — let original handle it (we'll catch the connect inside)
        return g_orig_WSAConnectByNameW(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    uint16_t port = 0;
    if (servicename && *servicename) {
        char ns[16] = {0};
        WideCharToMultiByte(CP_UTF8, 0, servicename, -1, ns, sizeof(ns)-1, NULL, NULL);
        port = (uint16_t)atoi(ns);
    }
    Log("WSAConnectByNameW(%s:%d) — domain-mode SOCKS5", narrow, port);
    bool nonBlocking = IsNonBlocking(s);
    if (!ConnectToProxy(s, nonBlocking) || !Socks5HandshakeAndConnectDomain(s, narrow, port, nonBlocking)) {
        Log("WSAConnectByNameW: failed for %s:%d", narrow, port);
        return FALSE;
    }
    if (nonBlocking) {
        WSASetLastError(WSAEWOULDBLOCK);
        return FALSE;
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
    if (IsNumericIp(nodename)) {
        return g_orig_WSAConnectByNameA(s, nodename, servicename,
            LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
    }
    uint16_t port = 0;
    if (servicename && *servicename) port = (uint16_t)atoi(servicename);
    Log("WSAConnectByNameA(%s:%d) — domain-mode SOCKS5", nodename, port);
    bool nonBlocking = IsNonBlocking(s);
    if (!ConnectToProxy(s, nonBlocking) || !Socks5HandshakeAndConnectDomain(s, nodename, port, nonBlocking)) {
        return FALSE;
    }
    if (nonBlocking) { WSASetLastError(WSAEWOULDBLOCK); return FALSE; }
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
    // Try first address — if IPv4 dummy, route via SOCKS5 domain
    for (int i = 0; i < list->iAddressCount; i++) {
        SOCKADDR* a = list->Address[i].lpSockaddr;
        if (a && a->sa_family == AF_INET) {
            sockaddr_in* sin = (sockaddr_in*)a;
            if (IsDummyIp(sin->sin_addr.s_addr)) {
                uint16_t p; const char* hn = LookupDummy(sin->sin_addr.s_addr, &p);
                if (hn) {
                    bool nonBlocking = IsNonBlocking(s);
                    if (ConnectToProxy(s, nonBlocking) && Socks5HandshakeAndConnectDomain(s, hn, p, nonBlocking)) {
                        if (nonBlocking) { WSASetLastError(WSAEWOULDBLOCK); return FALSE; }
                        return TRUE;
                    }
                    return FALSE;
                }
            }
            return RouteTcp(s, sin);
        }
    }
    return g_orig_WSAConnectByList(s, list, LocalAddressLength, LocalAddress,
        RemoteAddressLength, RemoteAddress, timeout, lpOverlapped);
}

// ConnectEx wrapper — returned by our WSAIoctl hook.
// Performs SOCKS5 + domain/IPv4 CONNECT, then signals the overlapped.
static BOOL PASCAL My_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped) {
    if (!g_config.enabled || !name || namelen <= 0 || name->sa_family != AF_INET) {
        if (g_real_ConnectEx) return g_real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        WSASetLastError(WSAEFAULT);
        return FALSE;
    }
    sockaddr_in* addr = (sockaddr_in*)name;
    if (RouteTcp(s, addr) != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        return FALSE;
    }
    // Send any initial data via regular send
    if (lpSendBuffer && dwSendDataLength > 0) {
        int sent = send(s, (const char*)lpSendBuffer, dwSendDataLength, 0);
        if (sent != SOCKET_ERROR && lpdwBytesSent) *lpdwBytesSent = (DWORD)sent;
    }
    // Signal overlapped as complete
    if (lpOverlapped) {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = (lpdwBytesSent ? *lpdwBytesSent : 0);
        if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
    }
    return TRUE;
}

// WSAIoctl — intercept SIO_GET_EXTENSION_FUNCTION_POINTER for ConnectEx
static int WINAPI My_WSAIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen,
    LPVOID outBuf, DWORD outLen, LPDWORD bytesReturned,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (code == SIO_GET_EXTENSION_FUNCTION_POINTER && inLen >= sizeof(GUID)) {
        GUID* g = (GUID*)inBuf;
        if (memcmp(g, &g_WSAID_CONNECTEX, sizeof(GUID)) == 0) {
            if (outLen >= sizeof(pfn_ConnectEx)) {
                // Cache the real ConnectEx first time we see the request
                if (!g_real_ConnectEx) {
                    DWORD br = 0;
                    g_orig_WSAIoctl(s, code, inBuf, inLen, &g_real_ConnectEx, sizeof(g_real_ConnectEx), &br, NULL, NULL);
                }
                *(pfn_ConnectEx*)outBuf = My_ConnectEx;
                if (bytesReturned) *bytesReturned = sizeof(pfn_ConnectEx);
                Log("WSAIoctl: intercepted ConnectEx request — returning wrapper");
                return 0;
            }
        }
    }
    return g_orig_WSAIoctl(s, code, inBuf, inLen, outBuf, outLen, bytesReturned, ov, cr);
}

// --- DNS hooks: return dummy IPs, store hostname for domain-mode SOCKS5 ---

static int WINAPI My_getaddrinfo(PCSTR node, PCSTR service,
    const ADDRINFOA* hints, PADDRINFOA* result) {
    // Force AF_INET in hints to skip IPv6 entirely (prevents AAAA lookups)
    ADDRINFOA localHints;
    if (hints) { localHints = *hints; } else { memset(&localHints, 0, sizeof(localHints)); }
    localHints.ai_family = AF_INET;
    int r = g_orig_getaddrinfo(node, service, &localHints, result);
    if (r != 0 || !result || !*result || !g_config.enabled || !node) return r;
    if (IsNumericIp(node)) return r;
    uint16_t port = service ? (uint16_t)atoi(service) : 0;
    uint32_t dummyIp = StoreDummy(node, port);
    ADDRINFOA* ai = *result;
    while (ai) {
        if (ai->ai_family == AF_INET && ai->ai_addr) {
            ((sockaddr_in*)ai->ai_addr)->sin_addr.s_addr = dummyIp;
        }
        ai = ai->ai_next;
    }
    Log("getaddrinfo(%s) → dummy 240.x.x.x (IPv4 forced)", node);
    return r;
}

static int WINAPI My_GetAddrInfoW(PCWSTR node, PCWSTR service,
    const ADDRINFOW* hints, PADDRINFOW* result) {
    ADDRINFOW localHints;
    if (hints) { localHints = *hints; } else { memset(&localHints, 0, sizeof(localHints)); }
    localHints.ai_family = AF_INET;
    int r = g_orig_GetAddrInfoW(node, service, &localHints, result);
    if (r != 0 || !result || !*result || !g_config.enabled || !node) return r;
    char narrow[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, node, -1, narrow, sizeof(narrow)-1, NULL, NULL);
    if (IsNumericIp(narrow)) return r;
    uint16_t port = 0;
    if (service) {
        char ns[16] = {0};
        WideCharToMultiByte(CP_UTF8, 0, service, -1, ns, sizeof(ns)-1, NULL, NULL);
        port = (uint16_t)atoi(ns);
    }
    uint32_t dummyIp = StoreDummy(narrow, port);
    ADDRINFOW* ai = *result;
    while (ai) {
        if (ai->ai_family == AF_INET && ai->ai_addr) {
            ((sockaddr_in*)ai->ai_addr)->sin_addr.s_addr = dummyIp;
        }
        ai = ai->ai_next;
    }
    Log("GetAddrInfoW(%ls) → dummy 240.x.x.x (IPv4 forced)", node);
    return r;
}

static struct hostent* WINAPI My_gethostbyname(const char* name) {
    struct hostent* he = g_orig_gethostbyname(name);
    if (!he || !g_config.enabled || !name || IsNumericIp(name)) return he;
    if (he->h_addrtype != AF_INET || he->h_length != 4) return he;
    uint32_t dummyIp = StoreDummy(name, 0);
    for (int i = 0; he->h_addr_list[i]; i++) {
        *(uint32_t*)he->h_addr_list[i] = dummyIp;
    }
    return he;
}

// Child process injection for inheritance across CreateProcess
static BOOL WINAPI My_CreateProcessInternalW(HANDLE hToken, LPCWSTR app, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi, HANDLE hNewToken) {
    BOOL r = g_orig_CreateProcessInternalW(hToken, app, pa, ta, inherit, flags, env, cwd, si, pi, hNewToken);
    if (!r || !pi || !pi->hProcess || g_dllPath[0] == 0) return r;
    if (pi->dwProcessId == GetCurrentProcessId()) return r;

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, pi->dwProcessId);
    if (!h) return r;
    SIZE_T sz = (wcslen(g_dllPath) + 1) * sizeof(wchar_t);
    LPVOID mem = VirtualAllocEx(h, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        if (WriteProcessMemory(h, mem, g_dllPath, sz, NULL)) {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            FARPROC loadlib = GetProcAddress(k32, "LoadLibraryW");
            HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
            if (t) {
                WaitForSingleObject(t, 5000);
                CloseHandle(t);
            }
        }
        VirtualFreeEx(h, mem, 0, MEM_RELEASE);
    }
    CloseHandle(h);
    return r;
}

// ============================================================================
// Config loader
// ============================================================================
static void LoadConfig() {
    char path[MAX_PATH] = {0};
    HMODULE hm;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&LoadConfig, &hm) && GetModuleFileNameA(hm, path, MAX_PATH)) {
        char* slash = strrchr(path, '\\');
        if (slash) strcpy(slash + 1, "proxy_config.txt");
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) path[0] = 0;
    }
    if (!path[0]) {
        strcpy(path, "C:\\proxy_config.txt");
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return;
    }

    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
        if (line[0] == 0 || line[0] == '#') continue;
        char* eq = strchr(line, '='); if (!eq) continue;
        *eq = 0; char* k = line; char* v = eq + 1;
        if (_stricmp(k, "SOCKS5_HOST") == 0) strncpy(g_config.socks5Host, v, sizeof(g_config.socks5Host)-1);
        else if (_stricmp(k, "SOCKS5_PORT") == 0) g_config.socks5Port = (uint16_t)atoi(v);
        else if (_stricmp(k, "SOCKS5_USER") == 0) strncpy(g_config.socks5User, v, sizeof(g_config.socks5User)-1);
        else if (_stricmp(k, "SOCKS5_PASS") == 0) strncpy(g_config.socks5Pass, v, sizeof(g_config.socks5Pass)-1);
        else if (_stricmp(k, "TIMEOUT_SEC") == 0) g_config.timeoutSec = atoi(v);
    }
    fclose(f);
    Log("Config loaded from %s: proxy=%s:%d auth=%s", path,
        g_config.socks5Host, g_config.socks5Port, g_config.socks5User[0] ? "yes" : "no");
}

// ============================================================================
// Hook installation
// ============================================================================
static bool InstallHooks() {
    struct { const wchar_t* dll; const char* fn; LPVOID hook; LPVOID* orig; } hooks[] = {
        // Core TCP/UDP routing
        { L"ws2_32", "connect", (LPVOID)My_connect, (LPVOID*)&g_orig_connect },
        { L"ws2_32", "bind", (LPVOID)My_bind, (LPVOID*)&g_orig_bind },
        { L"ws2_32", "closesocket", (LPVOID)My_closesocket, (LPVOID*)&g_orig_closesocket },
        { L"ws2_32", "sendto", (LPVOID)My_sendto, (LPVOID*)&g_orig_sendto },
        { L"ws2_32", "recvfrom", (LPVOID)My_recvfrom, (LPVOID*)&g_orig_recvfrom },
        { L"ws2_32", "WSASendTo", (LPVOID)My_WSASendTo, (LPVOID*)&g_orig_WSASendTo },
        { L"ws2_32", "WSARecvFrom", (LPVOID)My_WSARecvFrom, (LPVOID*)&g_orig_WSARecvFrom },
        { L"ws2_32", "WSAEventSelect", (LPVOID)My_WSAEventSelect, (LPVOID*)&g_orig_WSAEventSelect },
        { L"ws2_32", "ioctlsocket", (LPVOID)My_ioctlsocket, (LPVOID*)&g_orig_ioctlsocket },
        // Zero-leak: alternative TCP connect APIs
        { L"ws2_32", "WSAConnect", (LPVOID)My_WSAConnect, (LPVOID*)&g_orig_WSAConnect },
        { L"ws2_32", "WSAConnectByNameW", (LPVOID)My_WSAConnectByNameW, (LPVOID*)&g_orig_WSAConnectByNameW },
        { L"ws2_32", "WSAConnectByNameA", (LPVOID)My_WSAConnectByNameA, (LPVOID*)&g_orig_WSAConnectByNameA },
        { L"ws2_32", "WSAConnectByList", (LPVOID)My_WSAConnectByList, (LPVOID*)&g_orig_WSAConnectByList },
        { L"ws2_32", "WSAIoctl", (LPVOID)My_WSAIoctl, (LPVOID*)&g_orig_WSAIoctl },
        // Zero-leak: DNS via dummy IPs
        { L"ws2_32", "getaddrinfo", (LPVOID)My_getaddrinfo, (LPVOID*)&g_orig_getaddrinfo },
        { L"ws2_32", "GetAddrInfoW", (LPVOID)My_GetAddrInfoW, (LPVOID*)&g_orig_GetAddrInfoW },
        { L"ws2_32", "gethostbyname", (LPVOID)My_gethostbyname, (LPVOID*)&g_orig_gethostbyname },
        // Zero-leak: block IPv6 + raw sockets
        { L"ws2_32", "socket", (LPVOID)My_socket, (LPVOID*)&g_orig_socket },
        // Child injection
        { L"kernel32", "CreateProcessInternalW", (LPVOID)My_CreateProcessInternalW, (LPVOID*)&g_orig_CreateProcessInternalW },
    };
    for (auto& h : hooks) {
        MH_STATUS s = MH_CreateHookApi(h.dll, h.fn, h.hook, h.orig);
        if (s != MH_OK) Log("Hook %s failed: %d", h.fn, s);
        else Log("Hook %s installed", h.fn);
    }
    MH_STATUS s = MH_EnableHook(MH_ALL_HOOKS);
    if (s != MH_OK) { Log("MH_EnableHook failed: %d", s); return false; }
    Log("All hooks enabled");
    return true;
}

// ============================================================================
// DLL entry
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_dummyLock);

        char logPath[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, logPath);
        strcat(logPath, "proxy_v2_log.txt");
        g_logFile = fopen(logPath, "a");

        Log("=== ProxyPayload v2 loaded PID=%lu ===", GetCurrentProcessId());
        LoadConfig();
        GetModuleFileNameW(hMod, g_dllPath, MAX_PATH);
        Log("DLL path: %ls", g_dllPath);

        // WSAStartup (some processes don't call it before our hook fires)
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        if (MH_Initialize() != MH_OK) { Log("MH_Initialize failed"); return FALSE; }
        if (!InstallHooks()) return FALSE;

        Log("ProxyPayload v2 ready");
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_orig_connect) {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
        }
        if (g_logFile) { fclose(g_logFile); g_logFile = NULL; }
        DeleteCriticalSection(&g_logLock);
        DeleteCriticalSection(&g_dummyLock);
    }
    return TRUE;
}
