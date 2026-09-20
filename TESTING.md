# Testing ProxyInjector

## 1. Build gate

```cmd
C:\ABF\ProxyInjector\build.bat
```

Обязательный результат:

```text
DLL BUILD OK
INJECTOR BUILD OK
TEST_CLIENT BUILD OK
```

Warnings и errors должны быть сохранены в отчёте, а не скрыты.

## 2. Evidence model

Успешный HTTP/UDP ответ сам по себе не доказывает proxy route. Для каждого PID
нужны одновременно:

1. readiness marker/event;
2. `PROXY_OK` для TCP/HTTPS или `UDP ASSOCIATE` для UDP;
3. отсутствие `PROXY_FAIL`/`HOOK_FAILURE`;
4. owner-table подтверждение, что non-loopback TCP идёт только к proxy endpoint;
5. отдельный host-control exit для сравнения, хранимый только как hash/status.

Не записывать credentials и raw public IP в test artifacts.

## 3. Minimal TCP test

Использовать отдельный временный config и log path, переданные хостом через
environment. Не копировать рабочие credentials в корень репозитория.

```cmd
start "" C:\ABF\ProxyInjector\bin\test_client.exe 2 api.ipify.org 80
C:\ABF\ProxyInjector\bin\Injector.exe PID C:\ABF\ProxyInjector\bin\ProxyPayload.dll
```

Критерий: PID ready, есть `PROXY_OK`, proxy exit отличается от host control.

## 4. Process-tree E2E

Authoritative synthetic scenario должен создавать root, двух children и двух
grandchildren. Каждый процесс выполняет DNS, raw TCP, HTTPS и UDP probes.

Текущая проверенная точка:

- 5/5 PID ready;
- 15/15 raw TCP через один proxy exit;
- 5/5 HTTPS через тот же exit после IPv4-mapped IPv6 fix;
- 20 native routed records, 0 native failures;
- DNS системный, не proxy placeholder;
- UDP reply возможен без `UDP ASSOCIATE` evidence.

Поэтому generic all-protocol статус остаётся failed. Это ожидаемая честная
граница, а не причина скрывать тест.

## 5. Negative cases

Проверять отдельно:

- отсутствующий config;
- неверный host/port;
- wrong password;
- proxy недоступен после readiness;
- обязательный hook не установлен;
- child injection failure;
- direct TCP destination, отличный от proxy endpoint;
- UDP reply без native UDP evidence.

Во всех случаях target не должен продолжать работу с прямым TCP fallback.

## 6. PoE validation

Не завершать чужие экземпляры игры и не использовать `taskkill /F` как часть
теста. Перед запуском проверить отсутствие конфликтующего профильного процесса.

Один контролируемый цикл:

1. применить отдельный профиль и proxy config;
2. запустить PoE suspended через host application;
3. дождаться PID-bound readiness;
4. начать owner-table/native-log sampling;
5. пользователь выполняет логин и входит в instance;
6. сопоставить PoE `Client.txt` с proxy events и TCP/UDP owner rows;
7. штатно остановить профиль и сохранить sanitized summary.

Ожидаемые PoE1 TCP направления по локальным логам: login `:20484`, instance
`:6112`, HTTP/HTTPS patch endpoints. Не считать импорт `sendto/recvfrom`
доказательством runtime UDP — нужен фактический owned endpoint/packet evidence.

## 7. Release criteria

- build без ошибок;
- source diff reviewed;
- TCP + HTTPS tree green;
- known DNS/UDP boundaries явно документированы;
- credentials отсутствуют в staged diff;
- commit подписан и содержит DCO sign-off.
