# ProxyPayload Hooks Reference

Полный справочник по всем Winsock хукам ProxyPayload v2.

## Сводная таблица

| # | API | DLL | Категория | Действие |
|---|---|---|---|---|
| 1 | `connect` | ws2_32 | TCP core | RouteTcp → SOCKS5 |
| 2 | `bind` | ws2_32 | UDP core | InitUdpAssociate на первом bind UDP |
| 3 | `closesocket` | ws2_32 | cleanup | UntrackSocket (maps cleanup) |
| 4 | `sendto` | ws2_32 | UDP core | EncapsulateUdp + send к прокси |
| 5 | `recvfrom` | ws2_32 | UDP core | DecapsulateUdp от прокси |
| 6 | `WSASendTo` | ws2_32 | UDP core | То же для WSABUF |
| 7 | `WSARecvFrom` | ws2_32 | UDP core | То же для WSABUF |
| 8 | `WSAEventSelect` | ws2_32 | tracking | MarkNonBlocking(s, events) |
| 9 | `ioctlsocket` | ws2_32 | tracking | MarkNonBlocking при FIONBIO |
| 10 | `CreateProcessInternalW` | kernel32 | child inject | Auto-inject DLL в дочерние процессы |
| 11 | `WSAConnect` | ws2_32 | TCP alt | RouteTcp → SOCKS5 |
| 12 | `WSAConnectByNameW` | ws2_32 | TCP alt | Domain-mode SOCKS5 напрямую |
| 13 | `WSAConnectByNameA` | ws2_32 | TCP alt | То же узкая версия |
| 14 | `WSAConnectByList` | ws2_32 | TCP alt | Первый IPv4 dummy → domain-mode |
| 15 | `WSAIoctl` | ws2_32 | ConnectEx | Перехват SIO_GET_EXTENSION_FUNCTION_POINTER |
| 16 | `getaddrinfo` | ws2_32 | DNS | Dummy IPs + forced AF_INET |
| 17 | `GetAddrInfoW` | ws2_32 | DNS | То же для wide |
| 18 | `gethostbyname` | ws2_32 | DNS legacy | Dummy IPs в hostent |
| 19 | `socket` | ws2_32 | block | Блокировка SOCK_RAW |

---

## Подробное описание по категориям

### TCP core routing

#### `My_connect(SOCKET s, const sockaddr* name, int namelen)`

**Когда**: приложение вызывает `connect()` для TCP.

**Логика**:
1. Если disabled / IPv6 / UDP / localhost / proxy-itself → pass through
2. IPv6 non-local → `WSAEAFNOSUPPORT` (block)
3. IPv4 non-local → `RouteTcp(s, addr)`

**Возвращает**:
- Blocking: `0` при успехе
- Non-blocking: `SOCKET_ERROR` + `WSAEWOULDBLOCK` (даже при успехе)
- Failure: `SOCKET_ERROR` + `WSAECONNREFUSED`

#### `My_WSAConnect(...)`

Аналогично `My_connect`, но для `WSAConnect` API. Та же логика `RouteTcp`.

### TCP alt routing

#### `My_WSAConnectByNameW(SOCKET s, LPCWSTR nodename, LPCWSTR servicename, ...)`

**Когда**: приложение вызывает `WSAConnectByName` (Chrome использует для DNS+connect в одном).

**Логика**:
1. Если nodename — numeric IP → pass through
2. Конвертирует wide → narrow, парсит порт из servicename
3. `ConnectToProxy(s, nonBlocking)` + `Socks5HandshakeAndConnectDomain(s, hostname, port, ...)`
4. Возвращает `TRUE` при успехе

### UDP routing

#### `My_bind(SOCKET s, const sockaddr* name, int namelen)`

**Когда**: приложение bind'ит UDP сокет.

**Логика**:
1. Вызывает оригинальный `bind`
2. Если UDP сокет И нет существующей ассоциации → `InitUdpAssociate(&entry)`
3. Сохраняет entry в `g_udpAssocMap`

#### `My_sendto / My_WSASendTo`

**Логика**:
1. Skip multicast (224.0.0.0/4)
2. Если сокет в UDP assoc map → `EncapsulateUdp` (10 байт header + payload)
3. `sendto` к `entry.udpProxyAddr`

#### `My_recvfrom / My_WSARecvFrom`

**Логика**:
1. Вызывает оригинал
2. Если сокет в UDP assoc map → strip 10 байт header, восстановить `from` адрес

### Tracking

#### `My_WSAEventSelect(SOCKET s, WSAEVENT ev, long events)`

**Логика**:
- Если `ev != NULL && events != 0` → `g_nonBlockingSockets[s] = events`
- Иначе → `g_nonBlockingSockets.erase(s)`
- Вызывает оригинал

#### `My_ioctlsocket(SOCKET s, long cmd, u_long* argp)`

**Логика**:
- Если `cmd == FIONBIO && argp`:
  - `*argp != 0` → `MarkNonBlocking(s, FD_READ|FD_WRITE)`
  - `*argp == 0` → `MarkNonBlocking(s, 0)` (blocking)
- Вызывает оригинал

### DNS hooks

#### `My_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result)`

**Логика**:
1. Форсирует `ai_family = AF_INET` в hints (вырезает AAAA)
2. Вызывает оригинал
3. Если node — numeric IP → return (без модификации)
4. Иначе: `StoreDummy(node, port)` → dummy IP
5. Заменяет все `AF_INET` адреса в результате на dummy IP

**Эффект**: провайдер видит только DNS запрос от resolver к DNS серверу (зашифрован
через DoT/DoH если настроено на машине), в самом приложении — dummy IPs которые
приводят к SOCKS5 domain-mode в connect().

#### `My_GetAddrInfoW(...)`

Wide-версия `My_getaddrinfo`. Конвертирует node в narrow для `StoreDummy`.

#### `My_gethostbyname(const char* name)`

**Логика**:
1. Вызывает оригинал
2. Если hostent AF_INET → заменяет все `h_addr_list[i]` на dummy IP

### Block hooks

#### `My_socket(int af, int type, int protocol)`

**Логика**:
- `type == SOCK_RAW` → `WSAEACCES` + `INVALID_SOCKET` + log
- Иначе → pass through (включая AF_INET6 — DNS resolver создаёт IPv6 сокеты)

**Важно**: IPv6 НЕ блокируется на socket-уровне, потому что внутренний DNS resolver
Windows создаёт AF_INET6 сокеты для DNS-over-IPv6. Блокировка на socket-уровне
сломала бы DNS resolution. IPv6 обрабатывается на connect-уровне.

### ConnectEx interception

#### `My_WSAIoctl(SOCKET s, DWORD code, ...)`

**Логика**:
- Если `code == SIO_GET_EXTENSION_FUNCTION_POINTER`:
  - Если GUID == `WSAID_CONNECTEX`:
    - Первый раз: получить реальный ConnectEx через оригинальный WSAIoctl
    - Вернуть `My_ConnectEx` в output buffer
- Иначе → pass through

#### `My_ConnectEx(SOCKET s, const sockaddr* name, ...)`

**Логика**:
1. Если IPv4 non-local → `RouteTcp(s, addr)`
2. Send any initial data через `send()`
3. Signal overlapped (`Internal=0`, `SetEvent(hEvent)`)

### Child injection

#### `My_CreateProcessInternalW(...)`

**Логика**:
1. Вызывает оригинал для создания процесса
2. Если child PID != self и есть DLL path → inject DLL в child:
   - `OpenProcess` с `PROCESS_CREATE_THREAD | PROCESS_VM_*`
   - `VirtualAllocEx` + `WriteProcessMemory` (DLL path)
   - `CreateRemoteThread(LoadLibraryW, dllPath)`
   - `WaitForSingleObject` 5с

**Эффект**: все дочерние процессы автоматически получают проксирование.

---

## Внутренние хелперы

### `RouteTcp(SOCKET s, const sockaddr_in* target)`

Главный маршрутизатор TCP. Логика:

1. Извлечь IP, порт, non-blocking статус
2. `IsDummyIp(ip)` → `LookupDummy()` → hostname (если есть)
3. `ConnectToProxy(s, nonBlocking)` — TCP к прокси
4. Если hostname есть → `Socks5HandshakeAndConnectDomain` (ATYP=0x03)
5. Иначе → `Socks5HandshakeAndConnect` (ATYP=0x01, IPv4)
6. Возвращает `WSAEWOULDBLOCK` для non-blocking, `0` для blocking, `WSAECONNREFUSED` для fail

### `ConnectToProxy(SOCKET s, bool nonBlocking)`

Устанавливает TCP соединение с прокси:
1. `g_orig_connect(s, proxyAddr, sizeof)`
2. Если `WSAEWOULDBLOCK` + non-blocking → `WaitWritable(s, timeout)`
3. `getsockopt(SO_ERROR)` → проверка ошибки

### `Socks5NegotiateAuth(SOCKET s, bool nonBlocking)`

Общий SOCKS5 auth:
1. Send: `05 02 00 02` (если есть креды) или `05 01 00`
2. Recv: 2 байтa ответ
3. Если method 0x02 → send login/password + recv auth result

### `Socks5ReadConnectResponse(SOCKET s, bool nonBlocking)`

Чтение ответа CONNECT:
1. Recv 4 байтa header (VER, REP, RSV, ATYP)
2. По ATYP: IPv4 (4+2), IPv6 (16+2), Domain (len+2)
3. Recv оставшиеся байты bound address

### `InitUdpAssociate(UdpAssoc* out)`

Создаёт TCP control socket для SOCKS5 UDP ASSOCIATE:
1. Создаёт TCP сокет, делает non-blocking
2. Connect к прокси
3. SOCKS5 auth
4. UDP ASSOCIATE запрос (`05 03 00 01 0.0.0.0:0`)
5. Получает `udpProxyAddr` для отправки UDP

### `EncapsulateUdp(WSABUF* dst, const char* buf, int len, const sockaddr* to)`

Строит SOCKS5 UDP packet:
```
[RSV(2)] [FRAG(1)] [ATYP(1)=0x01] [DST.IP(4)] [DST.PORT(2)] [PAYLOAD(len)]
```

### `IsDummyIp / StoreDummy / LookupDummy`

Работа с dummy IP mapping:
- `IsDummyIp(netOrderIp)` — проверить `ntohl(ip) >> 24 == 240`
- `StoreDummy(hostname, port)` — FNV-1a hash → 240.X.X.X, сохранить в `g_dummyTable[1024]`
- `LookupDummy(netOrderIp, *outPort)` — linear scan по таблице

---

## Файлы и структуры данных

### Globals

```cpp
ProxyConfig g_config;                     // конфигурация
wchar_t g_dllPath[MAX_PATH];              // путь к этой DLL (для child injection)
FILE* g_logFile;                          // лог файл
CRITICAL_SECTION g_logLock;               // блокировка лога
CRITICAL_SECTION g_dummyLock;             // блокировка dummy IP таблицы

std::shared_mutex g_socketsMutex;
std::map<SOCKET, long> g_nonBlockingSockets;   // non-blocking сокеты
std::map<SOCKET, UdpAssoc> g_udpAssocMap;       // UDP ассоциации

DummyEntry g_dummyTable[1024];            // hostname → dummy IP mapping
```

### Структуры

```cpp
struct ProxyConfig {
    char socks5Host[64];
    uint16_t socks5Port;
    char socks5User[128];
    char socks5Pass[128];
    BOOL enabled;
    int timeoutSec;
};

struct UdpAssoc {
    SOCKET proxySock;            // TCP к прокси
    sockaddr_in udpProxyAddr;    // адрес для UDP пакетов
};

struct DummyEntry {
    uint32_t netOrderIp;
    char hostname[256];
    uint16_t port;
    bool used;
};
```

---

## Минхук (MinHook) особенности

### Почему MinHook

- Single-header (просто включить)
- Поддерживает x64
- Бесплатная лицензия (BSD)
- Стабильный, battle-tested

### Использование

```cpp
MH_Initialize();                                    // один раз в DllMain
MH_CreateHookApi(L"ws2_32", "connect",
                 (LPVOID)My_connect,
                 (LPVOID*)&g_orig_connect);        // для каждого хука
MH_EnableHook(MH_ALL_HOOKS);                        // включить все сразу
```

### Ограничения

- **Не может хукать неэкспортируемые функции** (например, `ConnectEx` напрямую).
  Поэтому мы перехватываем через `WSAIoctl`.
- **Inline patches видны** через memory scanning (детектируется античитами).
- **Не защищает от uninstall** — `MH_DisableHook(MH_ALL_HOOKS)` снимет всё.
