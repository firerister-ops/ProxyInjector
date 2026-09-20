# ProxyInjector

Нативный Windows-компонент для раннего перенаправления сетевых соединений
целевого процесса и его дочерних процессов через SOCKS5. Основной потребитель —
ControlPanel; MultiClient используется как независимый интеграционный стенд.

Проект состоит из:

- `ProxyPayload.dll` — Winsock hooks, SOCKS5, наследование в дочерние процессы;
- `Injector.exe` — запуск suspended-процесса и загрузка payload до выполнения
  прикладного кода;
- `test_client.exe` — минимальная TCP-проверка;
- документации по контрактам, тестированию и границам покрытия.

## Проверенное покрытие

- `connect`, `WSAConnect`, `WSAConnectByNameA/W`, `WSAConnectByList`;
- настоящий `ConnectEx`, полученный через `WSAIoctl` и перехваченный по адресу;
- dual-mode `AF_INET6` сокеты с IPv4-mapped адресами `::ffff:a.b.c.d`;
- отложенный SOCKS5 handshake для `ConnectEx` через первый `send`/`WSASend`;
- ранняя синхронная инжекция в дочерние процессы через полную ABI-сигнатуру
  `CreateProcessInternalW`;
- PID-bound readiness event и readiness-файл со статусом каждого hook;
- отдельные пути конфигурации и логов для параллельных экземпляров;
- fail-closed при отсутствующей/невалидной конфигурации, ошибке hooks,
  инжекции, SOCKS5 negotiation или resume дочернего процесса.

Независимый процессный E2E (корень + 2 дочерних + 2 внука) подтвердил 15/15
raw TCP и 5/5 HTTPS соединений через один SOCKS5 exit, всего 20 подтверждённых
маршрутов без native failure.

## Честные границы

Это не универсальный packet-level VPN и не самостоятельный kernel kill switch.

- DNS hooks существуют, но системный resolver .NET может разрешать имена вне
  процесса. Нельзя заявлять proxy-side DNS без отдельного доказательства.
- SOCKS5 UDP ASSOCIATE реализован, однако generic .NET UDP probe смог получить
  прямой ответ без native UDP evidence. Полное UDP fail-closed не доказано.
- ICMP не переносится SOCKS5.
- Выгрузка DLL и прямой доступ к AFD требуют внешнего сетевого барьера.
- Для PoE1 текущие локальные логи и read-only owner-table наблюдения показывают
  TCP; UDP backend добавляется только при фактическом PoE capture.

ControlPanel/MultiClient должны дополнять payload allowlist/WFP-политикой и
owner-table аудитом. Sandboxie WFP начинает действовать только после reload
драйвера или перезагрузки системы.

## Сборка

Требования: Windows x64 и bundled MinGW в `mingw\mingw64`.

```cmd
C:\ABF\ProxyInjector\build.bat
```

Успешная сборка создаёт игнорируемые Git артефакты:

```text
bin\ProxyPayload.dll
bin\Injector.exe
bin\test_client.exe
```

## Конфигурация

Основной production-контракт — абсолютный путь в переменной окружения
`ABF_PROXY_CONFIG_PATH`. Для legacy late-injection допустим
`proxy_config.txt` рядом с DLL. Fallback на `C:\proxy_config.txt` удалён.

```ini
SOCKS5_HOST=proxy.example
SOCKS5_PORT=1080
SOCKS5_USER=
SOCKS5_PASS=
TIMEOUT_SEC=3
LANGUAGE=
```

Ограничения:

- `SOCKS5_HOST` и `SOCKS5_PORT` обязательны;
- `TIMEOUT_SEC` должен быть от 1 до 30;
- credentials не должны попадать в Git, stdout или документацию;
- невалидный config оставляет readiness в состоянии failure и не включает
  сетевые hooks.

Опциональные переменные:

- `ABF_PROXY_LOG_DIR` — каталог per-instance логов и readiness-файлов;
- `ABF_PROXY_LOG_PATH` — точный путь основного native-лога.

## Ранний запуск

```cmd
C:\ABF\ProxyInjector\bin\Injector.exe --launch ^
  E:\Games\PathofExilesmooth\PathOfExile.exe ^
  --dll C:\ABF\ProxyInjector\bin\ProxyPayload.dll
```

Хост обязан передать конфигурационные и логовые переменные окружения до
создания процесса. При ошибке инжекции suspended target завершается и никогда
не возобновляется.

## Наблюдаемость

Основные события:

```text
PROXY_OK target=<sanitized-target> via=<proxy-endpoint>
PROXY_FAIL phase=<phase> reason=<reason>
ConnectEx deferred
ConnectEx SOCKS5 negotiation complete
UDP ASSOCIATE established
HOOK_FAILURE
```

Readiness-файл содержит PID, имя процесса, количество успешных/неуспешных hooks
и их статусы. Хост не должен считать процесс готовым только по успешному exit
code инжектора — требуется PID-bound readiness event/marker.

## Документация

- [HOOKS.md](HOOKS.md) — актуальная поверхность hooks и семантика;
- [PIPELINE.md](PIPELINE.md) — обязательный host pipeline;
- [TESTING.md](TESTING.md) — проверка и критерии доказательств.

## Происхождение текущего hardening

- ABF `9953fe8`: исправленный GUID/получение ConnectEx, deferred negotiation,
  per-instance logging и TCP owner audit со стороны ControlPanel;
- ABF `ffde33f`: IPv4-mapped IPv6/dual-mode socket support;
- MultiClient EXP-018: независимое подтверждение raw TCP + HTTPS дерева и
  выявление остающейся generic UDP/DNS границы.

## Лицензии и references

Архитектура опирается на идеи
[runetfreedom/force-proxy](https://github.com/runetfreedom/force-proxy) и
[nefarius/socksifier](https://github.com/nefarius/socksifier). SOCKS5 описан в
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) и username/password auth — в
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). Перед распространением
необходимо отдельно проверить лицензии всех включённых компонентов MinHook.
