# ProxyInjector

Прокси-инжектор для Windows приложений — DLL которая принудительно направляет
весь TCP/UDP трафик целевого процесса через SOCKS5 прокси. Применяется для
запуска игр (Path of Exile) и браузеров (Chrome) через прокси без нативной
поддержки прокси в самом приложении.

**Архитектура основана на** [runetfreedom/force-proxy](https://github.com/runetfreedom/force-proxy)
и [nefarius/socksifier](https://github.com/nefarius/socksifier).

---

## Содержание

- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Структура проекта](#структура-проекта)
- [Сборка](#сборка)
- [Конфигурация](#конфигурация)
- [Использование](#использование)
- [Принцип работы](#принцип-работы)
- [Zero-leak защита](#zero-leak-защита)
- [Тестирование](#тестирование)
- [Модель безопасности](#модель-безопасности)
- [Ограничения](#ограничения)
- [Интеграция с ControlPanel](#интеграция-с-controlpanel)
- [Troubleshooting](#troubleshooting)
- [Ссылки](#ссылки)

---

## Возможности

### Маршрутизация трафика
- ✅ TCP через `connect()`, `WSAConnect`, `WSAConnectByNameW/A`, `WSAConnectByList`
- ✅ TCP через `ConnectEx` (перехват через `WSAIoctl`)
- ✅ UDP через `bind()` + `sendto`/`WSASendTo`/`recvfrom`/`WSARecvFrom` (SOCKS5 UDP ASSOCIATE)
- ✅ Неблокирующие сокеты (Chrome, PoE) — корректный возврат `WSAEWOULDBLOCK`
- ✅ Domain-mode SOCKS5 (`ATYP=0x03`) — прокси сам резолвит hostname

### Zero-leak защита
- ✅ DNS через dummy IPs (240.x.x.x) — провайдер не видит DNS запросы
- ✅ IPv6 connect блокируется (AF_INET6 → `WSAEAFNOSUPPORT`)
- ✅ Raw sockets блокируются (`SOCK_RAW` → `WSAEACCES`)
- ✅ AAAA записи вырезаются из `getaddrinfo` результата
- ✅ Fail-closed: прокси недоступен → `WSAECONNREFUSED` (без fallback на direct)

### Инфраструктура
- ✅ Авто-инжекция в дочерние процессы через `CreateProcessInternalW` hook
- ✅ Минимальный таймаут 3 секунды (быстрый fail → быстрый retry клиентом)
- ✅ Структурированные логи `PROXY_OK` / `PROXY_FAIL` для мониторинга
- ✅ Логирование в `%TEMP%\proxy_v2_log.txt`

---

## Архитектура

```
┌──────────────────────────────────────────────────────────┐
│  Целевой процесс (PoE, Chrome, и т.д.)                    │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  ProxyPayload.dll (hook layer)                     │  │
│  │                                                    │  │
│  │  Winsock API ──── MinHook inline patches ────┐     │  │
│  │  connect(), WSAConnect(), ConnectEx, ...      │     │  │
│  │                                               ▼     │  │
│  │  ┌─────────────────────────────────────────┐       │  │
│  │  │  RouteTcp()                              │       │  │
│  │  │  ├─ ConnectToProxy() — TCP к прокси      │       │  │
│  │  │  ├─ Socks5NegotiateAuth() — handshake    │       │  │
│  │  │  ├─ Socks5HandshakeAndConnect[Domain]()  │       │  │
│  │  │  │   • IPv4 mode (ATYP=0x01)             │       │  │
│  │  │  │   • Domain mode (ATYP=0x03) ←── dummy │       │  │
│  │  │  └─ Socks5ReadConnectResponse()          │       │  │
│  │  └─────────────────────────────────────────┘       │  │
│  │                                                    │  │
│  │  Dummy IP mapping (DNS leak prevention):           │  │
│  │  getaddrinfo("foo.com") → 240.3.181.76             │  │
│  │  connect(240.3.181.76) → RouteTcp → SOCKS5 domain  │  │
│  └────────────────────────────────────────────────────┘  │
│                            │                             │
└────────────────────────────┼─────────────────────────────┘
                             │ TCP (зашифрованный TLS внутри)
                             ▼
                  ┌─────────────────────────┐
                  │   SOCKS5 прокси сервер   │
                  │   (your.proxy.ip:1080)   │
                  └─────────────────────────┘
```

### Ключевые принципы

1. **Transparent hook** — клиентский сокет используется напрямую, без создания
   промежуточных socket pairs. Это ограничивает возможности retry (см.
   [Ограничения](#ограничения)), но даёт простоту и стабильность.

2. **Fail-closed** — любая ошибка SOCKS5 даёт `WSAECONNREFUSED` приложению.
   Прямого fallback на оригинальный `connect()` **нет** для non-local адресов.

3. **Non-blocking aware** — для сокетов в неблокирующем режиме (Chrome, PoE)
   SOCKS5 handshake делается синхронно через `select()`, после чего
   возвращается `WSAEWOULDBLOCK` чтобы async-I/O машина приложения (WSAEventSelect
   + FD_CONNECT) корректно отработала.

---

## Структура проекта

```
C:\ABF\ProxyInjector\
├── README.md                            ← эта документация
├── build.bat                            ← основная сборка (DLL + Injector)
├── build_injector.bat                   ← устаревший скрипт (не использовать)
├── build_test.bat                       ← устаревший скрипт (не использовать)
├── TestProxy.cpp                        ← устаревший тест (не использовать)
│
├── ProxyPayload\
│   ├── dllmain_v2.cpp                   ← АКТИВНАЯ версия DLL (976 строк)
│   ├── dllmain.cpp                      ← устаревшая v1 (2560 строк, не используется)
│   ├── dllmain_v1_backup.cpp            ← backup v1
│   ├── ProxyPayload.vcxproj             ← MSVC project (не используется, собираем MinGW)
│   └── minhook\
│       └── MinHook.h                    ← single-header MinHook (из pixeltris/YgoMaster)
│
├── Injector\
│   └── injector.cpp                     ← NtCreateThreadEx-based инжектор (356 строк)
│
├── TestClient\
│   ├── test_client.cpp                  ← простой TCP клиент с задержкой для теста хуков
│   └── test_client.exe                  ← собранный тест-клиент
│
├── bin\                                 ← выходные бинарники
│   ├── ProxyPayload.dll                 ← собранная DLL
│   ├── Injector.exe                     ← собранный инжектор
│   ├── test_client.exe                  ← собранный тест-клиент
│   └── proxy_config.txt                 ← конфигурация прокси
│
└── mingw\
    └── mingw64\                         ← portable MinGW64 (для сборки)
```

---

## Сборка

### Требования

- **Windows 10/11 x64**
- **MinGW64** (поставляется с проектом: `mingw\mingw64\bin\g++.exe`)
- **Права администратора** для инжекции в процессы

### Команды

```cmd
:: Собрать DLL + Injector (основной путь)
C:\ABF\ProxyInjector\build.bat

:: Собрать только test_client (вручную)
cd C:\ABF\ProxyInjector\TestClient
g++ -O2 test_client.cpp -o test_client.exe -lws2_32 -static
```

Ожидаемый вывод:
```
DLL BUILD OK
INJECTOR BUILD OK
```

### Флаги компилятора DLL

```
-shared -Wall -Wno-unknown-pragmas -O2 -std=gnu++17 -lws2_32 -static -static-libgcc -static-libstdc++
```

---

## Конфигурация

DLL ищет `proxy_config.txt` в двух местах (по приоритету):

1. **Рядом с DLL** (рекомендуется): `C:\ABF\ProxyInjector\bin\proxy_config.txt`
2. **В корне C:** (fallback): `C:\proxy_config.txt`

### Формат

```ini
# SOCKS5 параметры
SOCKS5_HOST=your.proxy.ip          # IP или hostname прокси
SOCKS5_PORT=1080                   # порт
SOCKS5_USER=                       # логин (пусто = без auth)
SOCKS5_PASS=                       # пароль

# Таймауты
TIMEOUT_SEC=3                      # сек — connect/recv timeout
                                   # меньше = быстрее fail, но меньше терпимости к лагам

# Устаревшие (игнорируются v2)
BLOCK_UDP_443=1
```

### Значения по умолчанию

Если `proxy_config.txt` не найден, используются:
```cpp
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 1080
SOCKS5_USER = ""     // no auth
SOCKS5_PASS = ""
TIMEOUT_SEC = 3
```

---

## Использование

### Базовый запуск

```cmd
:: 1. Запустить целевое приложение
C:\Users\FRD1\Desktop\PathofExilesmooth\PathOfExile_x64.exe

:: 2. Подождать инициализацию (5-10 секунд для PoE)

:: 3. Узнать PID
tasklist /FI "IMAGENAME eq PathOfExile.exe"

:: 4. Инжектировать DLL
C:\ABF\ProxyInjector\bin\Injector.exe <PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 5. Проверить лог
type %TEMP%\proxy_v2_log.txt
```

### Инжекция по имени процесса (все экземпляры)

```cmd
:: Инжектирует во ВСЕ chrome.exe процессы
C:\ABF\ProxyInjector\bin\Injector.exe chrome.exe C:\ABF\ProxyInjector\bin\ProxyPayload.dll
```

### Watch mode (мониторинг новых процессов)

```cmd
:: Запустить watch mode — будет инжектить во все новые chrome.exe
C:\ABF\ProxyInjector\bin\Injector.exe --watch chrome.exe C:\ABF\ProxyInjector\bin\ProxyPayload.dll
```

Watch mode опрашивает процессы каждые 50мс и инжектирует в новые автоматически.
Полезно для Chrome который создаёт дочерние процессы асинхронно.

### Тестирование через test_client

```cmd
:: Простой тест: 3с задержка → DNS → connect → HTTP GET
C:\ABF\ProxyInjector\bin\Injector.exe <test_client_PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll
```

test_client делает задержку перед запросом чтобы DLL успела проинициализироваться
после инжекции.

### Параметры командной строки Injector.exe

```
Injector.exe <PID>                    <DLL>     Инжекция по PID
Injector.exe <process.exe>            <DLL>     Инжекция во все процессы с именем
Injector.exe --watch <process.exe>    <DLL>     Мониторинг новых процессов
Injector.exe --help                             Справка
```

---

## Принцип работы

### Полный список хуков

DLL устанавливает 19 хуков через MinHook (inline API patching):

#### Core TCP/UDP routing (10)

| API | Назначение |
|---|---|
| `connect` | TCP соединение → RouteTcp → SOCKS5 |
| `bind` | UDP сокет → InitUdpAssociate → SOCKS5 UDP ASSOCIATE |
| `closesocket` | Очистка (non-blocking map, UDP assoc map) |
| `sendto` | UDP send → инкапсуляция SOCKS5 header (10 байт) |
| `recvfrom` | UDP recv → декапсуляция SOCKS5 header |
| `WSASendTo` | То же что sendto для WSABUF |
| `WSARecvFrom` | То же что recvfrom для WSABUF |
| `WSAEventSelect` | Трекинг non-blocking сокетов |
| `ioctlsocket` | Трекинг FIONBIO (non-blocking флаг) |
| `CreateProcessInternalW` | Авто-инжекция DLL в дочерние процессы |

#### Zero-leak extension (9)

| API | Назначение |
|---|---|
| `WSAConnect` | Альтернативный TCP connect → RouteTcp |
| `WSAConnectByNameW` | DNS+connect в одном вызове → domain-mode SOCKS5 напрямую |
| `WSAConnectByNameA` | Узкая версия выше |
| `WSAConnectByList` | Список адресов → первый IPv4 dummy → domain-mode |
| `WSAIoctl` | Перехват `SIO_GET_EXTENSION_FUNCTION_POINTER` для ConnectEx |
| `getaddrinfo` | DNS → dummy IPs (forced AF_INET, AAAA вырезаны) |
| `GetAddrInfoW` | Wide-версия DNS hook |
| `gethostbyname` | Legacy DNS → dummy IPs |
| `socket` | Блокировка `SOCK_RAW` (IPv6 обрабатывается на connect-уровне) |

### SOCKS5 протокол

#### IPv4 mode (ATYP=0x01)

Используется когда connect() вызван с реальным IP (не dummy):

```
1. TCP connect к прокси
2. Auth negotiation: VER=5, METHODS=[0x00, 0x02]
3. Если метод 0x02 (user/pass): отправка логина/пароля
4. CONNECT запрос: VER=5, CMD=1, ATYP=1, IPv4, PORT
5. Чтение ответа: VER=5, REP, ATYP, BND.ADDR, BND.PORT
```

#### Domain mode (ATYP=0x03)

Используется когда connect() вызван с dummy IP (240.x.x.x) — значит
предыдущий getaddrinfo перехватил hostname:

```
1. TCP connect к прокси
2. Auth negotiation (тот же)
3. CONNECT запрос: VER=5, CMD=1, ATYP=3, DOMAIN_LEN, DOMAIN, PORT
4. Чтение ответа
5. Прокси сам резолвит домен → НЕТ DNS утечки
```

### UDP ASSOCIATE (для QUIC, DNS-over-UDP)

```
1. На bind() UDP сокета создаём отдельный TCP к прокси
2. SOCKS5 handshake на TCP
3. UDP ASSOCIATE запрос: VER=5, CMD=3, ATYP=1, 0.0.0.0:0
4. Прокси возвращает адрес для отправки UDP пакетов
5. Каждый sendto() добавляет 10-байт SOCKS5 header: RSV,FRAG,ATYP,DST.ADDR,DST.PORT
6. Каждый recvfrom() декапсулирует 10-байт header
```

### Dummy IP mapping

```
Hostname → SHA hash → 240.X.X.X (class E reserved)
Хранится в g_dummyTable[1024] под critical section

getaddrinfo("api.ipify.org") → 240.3.181.76
connect(240.3.181.76) → IsDummyIp() → LookupDummy() → "api.ipify.org"
                      → Socks5HandshakeAndConnectDomain("api.ipify.org", 80)
```

### Non-blocking сокеты

Chrome и PoE используют неблокирующие сокеты:

1. Приложение: `ioctlsocket(s, FIONBIO, &1)` или `WSAEventSelect(s, ev, FD_CONNECT|...)`
2. Наш хук записывает это в `g_nonBlockingSockets`
3. При `connect(s, addr)`:
   - SOCKS5 handshake синхронный через `select()` с timeout
   - После успеха возвращаем `WSAEWOULDBLOCK` (приложение думает "connect in progress")
4. Приложение ждёт FD_CONNECT событие — оно не сработает (мы уже подключены),
   но на Windows это работает: приложение делает `recv()`/`send()` сразу
5. Данные текут через уже установленное SOCKS5 соединение

---

## Zero-leak защита

Полный анализ векторов утечек и защита от каждого:

| Вектор | Защита | Логирование |
|---|---|---|
| TCP IPv4 через `connect()` | SOCKS5 маршрутизация | `PROXY_OK` / `PROXY_FAIL` |
| TCP через `WSAConnect` | То же | То же |
| TCP через `WSAConnectByNameW/A` | Domain-mode напрямую | То же |
| TCP через `ConnectEx` | Перехват через `WSAIoctl` | `WSAIoctl: intercepted ConnectEx` |
| DNS (getaddrinfo и т.д.) | Dummy IPs + AAAA фильтрация | `getaddrinfo(%s) → dummy 240.x.x.x` |
| IPv6 connect | `WSAEAFNOSUPPORT` | `connect: BLOCKED AF_INET6` |
| Raw sockets | `WSAEACCES` | `socket: BLOCKED SOCK_RAW` |
| UDP (QUIC) | SOCKS5 UDP ASSOCIATE | `UDP ASSOCIATE established` |
| Прокси недоступен | Fail-closed `WSAECONNREFUSED` | `PROXY_FAIL phase=tcp_connect` |
| SOCKS5 handshake fail | Fail-closed | `PROXY_FAIL phase=socks5_handshake` |

### Что НЕ защищено на уровне DLL

- **DLL выгрузка** — если хуки сняты, весь трафик пойдёт напрямую. Защита: Windows Firewall правило на уровне ControlPanel.
- **Прямые syscalls в afd.sys** — обходят ws2_32.dll. Защита: Windows Firewall.
- **WinHTTP/WinINet** — отдельный API stack, использует `ws2_32!connect` внутри, поэтому перехватывается косвенно.

---

## Тестирование

### Юнит-тест: test_client.exe

Простой TCP клиент с задержкой. Сценарий:

```cmd
:: 1. Запускаем test_client с задержкой 2с
C:\ABF\ProxyInjector\bin\test_client.exe 2 api.ipify.org 80

:: 2. Сразу инжектируем
C:\ABF\ProxyInjector\bin\Injector.exe <PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 3. Ждём завершения (5-10с)
:: 4. Вывод должен показать IP прокси, а не реальный IP
```

### End-to-end: Path of Exile

```cmd
:: 1. Убить предыдущие инстансы
taskkill /F /IM PathOfExile*

:: 2. Запустить PoE
C:\Users\FRD1\Desktop\PathofExilesmooth\PathOfExile_x64.exe

:: 3. Подождать запуск основного процесса
powershell "Get-Process PathOfExile | Select Id"

:: 4. Инжектировать
C:\ABF\ProxyInjector\bin\Injector.exe <PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 5. Наблюдать лог в реальном времени
powershell "Get-Content $env:TEMP\proxy_v2_log.txt -Wait"
```

Ожидаемые подключения PoE через прокси:
- `web.poecdn.com:443` — CDN
- `webcdn.pathofexile.com:80` — web assets
- `www.pathofExile.com:443` — сайт
- `ams.login.pathofexile.com:20484` — login (Amsterdam)
- `*.pathofexile.com:6112` — игровой сервер (TCP, real IP от сервера)
- `us.login.pathofexile.com:20484` — login US

### End-to-end: Chrome

```cmd
:: Chrome требует --no-sandbox для полной инжекции во все процессы
"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-sandbox --disable-quic

:: Инжекция во все процессы chrome.exe
C:\ABF\ProxyInjector\bin\Injector.exe chrome.exe C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: Открыть IP-чек сайт
"C:\Program Files\Google\Chrome\Application\chrome.exe" "http://api.ipify.org"
```

### Анализ лога

Структурированные события для парсинга:

```
PROXY_OK target=api.ipify.org:80 via=your.proxy.ip:1080
PROXY_FAIL phase=tcp_connect target=api.ipify.org:80 reason=proxy_unreachable
PROXY_FAIL phase=socks5_handshake target=api.ipify.org:80 reason=handshake_failed
```

Фильтр успешных:
```powershell
Get-Content $env:TEMP\proxy_v2_log.txt | Select-String 'PROXY_OK'
```

Фильтр ошибок:
```powershell
Get-Content $env:TEMP\proxy_v2_log.txt | Select-String 'PROXY_FAIL|BLOCKED|FAILED'
```

---

## Модель безопасности

### Threat model

| Угроза | Защита | Уровень |
|---|---|---|
| Провайдер видит DNS | Domain-mode SOCKS5 (ATYP=0x03) | ✅ DLL |
| Провайдер видит трафик | SOCKS5 + TLS end-to-end | ✅ DLL |
| Утечка через IPv6 | AF_INET6 connect блокируется | ✅ DLL |
| Утечка через raw socket | SOCK_RAW блокируется | ✅ DLL |
| Утечка через UDP | SOCKS5 UDP ASSOCIATE | ✅ DLL |
| Прокси упал | Fail-closed WSAECONNREFUSED | ✅ DLL |
| DLL выгрузили | Windows Firewall правило | ⚠️ ControlPanel |
| Прямые syscalls | Windows Firewall правило | ⚠️ ControlPanel |

### Рекомендация для multi-client

Для 10+ клиентов на одной машине:

1. **Каждый клиент под отдельным Windows аккаунтом** — изоляция конфигов и процессов
2. **Windows Firewall правило per process** — блокировка всего кроме прокси
3. **Раздельные proxy_config.txt** — каждый клиент со своим прокси
4. **Мониторинг через ControlPanel** — health-check + auto-restart

### Windows Firewall kill-switch

Скрипт для ControlPanel (требует admin):

```powershell
# Block ALL outbound from PathOfExile.exe except to proxy
$exe = "C:\Users\FRD1\Desktop\PathofExilesmooth\PathOfExile.exe"
$proxyIp = "your.proxy.ip"
$proxyPort = 1080

New-NetFirewallRule -DisplayName "PoE-Block-All-Outbound" `
  -Program $exe -Direction Outbound -Action Block

New-NetFirewallRule -DisplayName "PoE-Allow-Proxy" `
  -Program $exe -Direction Outbound -Action Allow `
  -RemoteAddress $proxyIp -RemotePort $proxyPort -Protocol TCP
```

Это даёт **kernel-level** защиту — даже если DLL выгрузят, пакеты будут дропнуты.

---

## Ограничения

### Архитектурные

1. **Нет DLL-level retry** — после fail клиентского сокета мы не можем его заменить.
   Retry делает само приложение (создаёт новый сокет → новый connect → наш хук снова).
   Причина: transparent hook использует клиентский сокет напрямую.

2. **Нет self-protection** — `FreeLibrary` нашей DLL возможен. Защита: firewall на уровне панели.

3. **TCP only** — дляUDP используется SOCKS5 UDP ASSOCIATE, но он не работает с multicast
   и broadcast (мы фильтруем multicast адреса 224.0.0.0/4).

4. **AF_INET6 connect блокируется жёстко** — нет IPv6 SOCKS5 маршрутизации.
   IPv6 сокеты создаются (для DNS resolver), но connect к non-local IPv6 блокируется.

### Поддерживаемые приложения

- ✅ **Path of Exile** — работает стабильно, 5+ TCP соединений через прокси
- ✅ **Chrome** — работает с `--no-sandbox --disable-quic`
- ✅ **PowerShell** — Invoke-WebRequest, .NET TcpClient
- ✅ **NetworkTestSandbox** — sync/async/iocp/dns/udp/wsconnect режимы
- ⚠️ **Discord** — не тестировалось, должно работать (использует winsock)
- ❌ **Приложения с anti-cheat** (BattlEye, EAC) — будет детектировано

### Известные проблемы

1. **PoE может упасть при двойной инжекции** — повторная инжекция в уже-инжектированный
   процесс создаёт двойные хуки. Решение: проверять через `CreateToolhelp32Snapshot`
   перед инжекцией (уже в Injector.exe через `IsProcessAlreadyInjected`).

2. **Chrome renderer с sandbox** — без `--no-sandbox` инжектируется только в main process.
   SocksCap64 решает это через `delayinj.ini` + специальный injection timing.

3. **Прокси с долгым accept** — если прокси принимает SYN-ACK но не отвечает на SOCKS5,
   таймаут 3с может быть коротким. Увеличить через `TIMEOUT_SEC` в config.

---

## Интеграция с ControlPanel

### Роли

| Роль | Где | Что делает |
|---|---|---|
| Hook + SOCKS5 маршрутизация | DLL | Перехват API, fail-closed |
| Process launch + injection | ControlPanel | Запуск PoE + Injector.exe |
| Proxy health-check | ControlPanel | TCP probe к прокси каждые 3с |
| Kill switch | ControlPanel | Kill PoE если прокси умер >10с |
| Windows Firewall | ControlPanel | Блокировка всего кроме прокси |
| Multi-instance | ControlPanel | По процессу на аккаунт/прокси |
| Log monitoring | ControlPanel | Парсинг `PROXY_OK`/`PROXY_FAIL` |
| Proxy rotation | ControlPanel | Kill + update config + restart |

### ControlPanel API для ProxyInjector (проектируемая)

```csharp
// Запуск PoE через прокси
public class ProxyInjectorService
{
    // Запускает процесс, инжектит DLL, ставит firewall правило
    public Task<InjectionResult> LaunchThroughProxy(
        string exePath,
        ProxyConfig proxy,
        CancellationToken ct);

    // Health-check прокси
    public event EventHandler<ProxyStatus> ProxyStatusChanged;

    // Kill switch
    public event EventHandler<ProxyDiedEventArgs> ProxyDied;
}
```

### Последовательность запуска (планируемая)

1. **ControlPanel** валидирует прокси (TCP connect test)
2. **ControlPanel** ставит Windows Firewall правило для `PathOfExile.exe`
3. **ControlPanel** пишет `proxy_config.txt` во временную директорию
4. **ControlPanel** запускает `PathOfExile_x64.exe` (sandboxed)
5. **ControlPanel** ждёт появление `PathOfExile.exe` процесса
6. **ControlPanel** запускает `Injector.exe <PID> ProxyPayload.dll`
7. **ControlPanel** читает `%TEMP%\proxy_v2_log.txt` для подтверждения PROXY_OK
8. **ControlPanel** запускает health-check цикл
9. При смерти прокся → kill PoE → alert user → предложить restart с новым прокси

---

## Troubleshooting

### PoE крашится после инжекции

**Симптомы**: PoE падает через ~30-60с после инжекции с `0xe0000001`.

**Причина**: конфликт с DPB (DreamPoeBot) или двойная инжекция.

**Решение**:
1. Проверить, не загружена ли уже DLL:
   ```powershell
   Get-Process PathOfExile | ForEach-Object {
       (Get-Process -Id $_.Id).Modules | Where-Object { $_.ModuleName -eq "ProxyPayload.dll" }
   }
   ```
2. Если уже загружена — перезапустить PoE
3. Инжектировать ДО загрузки DPB

### Лог пустой после инжекции

**Причина**: DLL не загрузилась, или `%TEMP%` другой.

**Решение**:
1. Проверить путь лога:
   ```cmd
   echo %TEMP%
   dir %TEMP%\proxy_v2_log.txt
   ```
2. Проверить, что Injector.exe сообщил `Injection OK`
3. Проверить права на запись в `%TEMP%`

### `DNS FAILED` в test_client

**Причина**: прокси недоступен, ИЛИ IPv6 сокет блокировка сломала DNS resolver.

**Решение**:
1. Проверить доступность прокси: `Test-NetConnection your.proxy.ip -Port 1080`
2. Проверить лог на `BLOCKED AF_INET6` — если да, убедиться что IPv6 блокировка
   не на socket-уровне (только на connect-уровне)

### Chrome без `--no-sandbox` не инжектируется

**Причина**: Chrome sandbox блокирует `CreateRemoteThread` в renderer процессах.

**Решение**:
1. Использовать `--no-sandbox` для тестирования
2. Для production: интеграция с ControlPanel через AppInit_DLLs или другой ранний механизм

### `LoadLibraryW returned NULL`

**Причина**: процесс заблокировал загрузку DLL, ИЛИ неверный путь.

**Решение**:
1. Проверить путь: должен быть **абсолютный**
2. Проверить битность: Injector x64 → только в x64 процессы
3. Антивирус может блокировать — добавить в исключения

### Поддержка IPv6-only сайта

Если сайт работает только по IPv6 — наш прокси не сможет (мы блокируем IPv6 connect).
Решение: использовать прокси с dual-stack поддержкой.

---

## Ссылки

### Reference projects (open source)

- **[runetfreedom/force-proxy](https://github.com/runetfreedom/force-proxy)** — основной
  референс. Минимальный и чистый, Microsoft Detours. Наша v2 основана на этом.
- **[nefarius/socksifier](https://github.com/nefarius/socksifier)** — похожий подход,
  хорошо документирован.
- **[k3v53/socksifier](https://github.com/k3v53/socksifier)** — вариант с spdlog
  логированием, использует ConnectEx для подключения к прокси.
- **[ViRb3/winsock-dump-proxy](https://github.com/ViRb3/winsock-dump-proxy)** — простой
  mhook-based dump прокси.

### Documentation

- **[Chromium tcp_socket_win.cc](https://chromium.googlesource.com/chromium/src/+/main/net/socket/tcp_socket_win.cc)** —
  исходники Chromium. Подтверждает что Chrome использует обычный `connect()`, не ConnectEx.
- **[ConnectEx on StackOverflow](https://stackoverflow.com/questions/41733041/how-to-get-connectex-pointer)** —
  как получать и хукать ConnectEx.
- **[Microsoft Detours](https://github.com/microsoft/Detours)** — альтернатива MinHook
  от Microsoft (мы используем MinHook — проще лицензия).

### Стандарты

- **[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)** — SOCKS5 protocol
- **[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)** — SOCKS5 username/password auth

### Внутренние ресурсы

- **SocksCap64** (референс для delayed injection): `C:\Users\FRD1\AppData\Local\SocksCap64\`
- **NetworkTestSandbox** (промежуточный тест): `C:\ABF\NetworkTestSandbox\`

---

## Changelog

### v2 (текущая) — 2026-08-05

Полная переработка:

- Переписана с нуля по образцу `runetfreedom/force-proxy`
- Удалены: WSAIoctl/ConnectEx direct hook, dummy IP mapping, DNS hooks (временно)
- Добавлены: `bind`/`sendto`/`WSASendTo`/`recvfrom`/`WSARecvFrom` хуки для UDP
- Добавлены: `WSAEventSelect`/`ioctlsocket` трекинг non-blocking сокетов
- Ключевой фикс: для non-blocking сокетов возвращаем `WSAEWOULDBLOCK` после SOCKS5
  handshake (вместо success). Это решило проблему с Chrome.
- Результат: Chrome работает через прокси (113 TCP + 10 UDP), PoE стабильно работает

### v2 zero-leak extension — 2026-08-05

- Добавлены: `WSAConnect`, `WSAConnectByNameW/A`, `WSAConnectByList` хуки
- Добавлены: `WSAIoctl` для перехвата ConnectEx
- Добавлены: DNS hooks (`getaddrinfo`, `GetAddrInfoW`, `gethostbyname`) с dummy IPs
- Добавлены: AAAA запись фильтрация (forced AF_INET)
- Добавлены: IPv6 connect блокировка, raw socket блокировка
- Добавлен: Domain-mode SOCKS5 (ATYP=0x03) — прокси резолвит hostname, нет DNS утечки
- Добавлен: Fail-closed с структурированными `PROXY_OK`/`PROXY_FAIL` логами
- Timeout уменьшен с 10с до 3с для быстрого retry клиентом

### v1 (устаревшая)

- Сложная архитектура с IOCP maps, EventSelectCache, dummy IP mapping
- Hook ConnectEx через direct `MH_CreateHookApi` (не работает — ConnectEx не экспортируется)
- Вызывает краш PoE на 44с (`0xe0000001`)
- Backup: `dllmain_v1_backup.cpp`
- **Не использовать**
