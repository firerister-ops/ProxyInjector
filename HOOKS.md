# ProxyPayload hook reference

Этот документ описывает текущий `ProxyPayload/dllmain.cpp`, а не исторические
эксперименты.

## Hook surface

| API | Назначение |
|---|---|
| `connect`, `WSAConnect` | TCP SOCKS5 routing, включая IPv4-mapped IPv6 |
| `WSAConnectByNameA/W`, `WSAConnectByList` | hostname/list connect paths |
| `ConnectEx` | hook реального extension pointer по адресу |
| `send`, `WSASend` | завершение deferred ConnectEx SOCKS5 negotiation |
| `bind`, `sendto`, `WSASendTo` | UDP ASSOCIATE и инкапсуляция |
| `recvfrom`, `WSARecvFrom` | UDP декапсуляция |
| `closesocket` | очистка socket state |
| `WSAEventSelect`, `WSAAsyncSelect`, `ioctlsocket` | non-blocking tracking |
| `getaddrinfo`, `GetAddrInfoW`, `gethostbyname` | dummy mapping для domain mode |
| `socket` | запрет `SOCK_RAW` |
| `CreateProcessInternalW` | suspended child injection и inheritance |

Всего устанавливается 20 обычных API hooks, отдельный hook `ConnectEx` по
адресу и `CreateProcessInternalW` через `kernelbase` с fallback на `kernel32`.
Любой обязательный hook failure откатывает MinHook и оставляет payload not ready.

## ConnectEx

`ConnectEx` не экспортируется как обычная функция. Payload:

1. создаёт probe socket;
2. получает адрес через документированный `SIO_GET_EXTENSION_FUNCTION_POINTER`;
3. устанавливает MinHook непосредственно на возвращённый адрес;
4. для `AF_INET6` dual-mode socket распознаёт `::ffff:a.b.c.d` как IPv4 target;
5. подключает тот же socket к SOCKS5 proxy в совместимом address family;
6. сохраняет pending target;
7. завершает SOCKS5 handshake при первом `send`/`WSASend`.

Pending hostname копируется в bounded buffer с гарантированным NUL terminator.
Unsupported overlapped/extension paths fail closed; payload не фабрикует ложные
completion events.

## Child processes

Hook использует полную ABI-сигнатуру `CreateProcessInternalW`, принудительно
добавляет `CREATE_SUSPENDED`, синхронно загружает текущий payload и проверяет
результат `LoadLibraryW`. Если injection или последующий `ResumeThread` не
удался, child завершается и caller получает failure.

Если caller сам запросил suspended child, payload сохраняет это состояние.
Опциональный `LANGUAGE` переписывает только значение `--language`; полная
command line не пишется в лог, поскольку может содержать чувствительные данные.

## DNS and dummy addresses

Domain-mode использует диапазон `198.18.0.0/16` (RFC 2544 benchmarking range).
Mapping collision-safe и bounded. Numeric/loopback names не подменяются.

Важно: hook процесса не гарантирует перехват системного DNS resolver. Поэтому
наличие dummy mapping — capability, а не автоматическое доказательство zero DNS
leak для любого framework.

## UDP

Реализованы SOCKS5 UDP ASSOCIATE, IPv4/IPv6 relay endpoint parsing, shared
association lifetime и bounded packet processing. Это покрытие должно
подтверждаться native `UDP ASSOCIATE` evidence для конкретного приложения.
Успешный UDP reply без такого события считается bypass, а не успехом proxy.

## Initialization and readiness

Тяжёлая инициализация вынесена из loader-lock в отдельный thread. Payload:

1. создаёт PID-specific ready event;
2. открывает per-instance log;
3. валидирует config;
4. запускает Winsock;
5. устанавливает все hooks;
6. пишет readiness marker;
7. сигналит event только после полного успеха.

Основной принцип потребителя: `injected != ready`. Разрешать приложению работу
можно только после подтверждения readiness именно его PID.
