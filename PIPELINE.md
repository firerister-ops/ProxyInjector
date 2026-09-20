# Host integration pipeline

ProxyInjector — компонент, а не самостоятельный менеджер профилей. ControlPanel
или MultiClient владеет жизненным циклом, secrets, network guard и evidence.

## Launch contract

1. Проверить proxy control-plane без раскрытия credentials.
2. Создать per-instance config за пределами репозитория.
3. Создать per-instance log directory.
4. Применить внешний allowlist: loopback + proxy endpoint, default deny.
5. Установить `ABF_PROXY_CONFIG_PATH`, `ABF_PROXY_LOG_DIR` и при необходимости
   `ABF_PROXY_LOG_PATH` в environment target.
6. Создать root process suspended.
7. Загрузить `ProxyPayload.dll` и дождаться PID-bound ready event/marker.
8. Возобновить root только после readiness.
9. Мониторить весь process tree, native events и TCP owner table.
10. При direct TCP, hook failure или proxy failure остановить принадлежащий
    профилю process tree.
11. На stop восстановить внешние правила и удалить ephemeral config.

## Fail-closed invariants

- Нет валидного config — нет ready.
- Injection failed — suspended process завершается, не resume.
- Обязательный hook failed — hooks откатываются, ready event не сигналится.
- Child injection failed — child завершается до выполнения прикладного кода.
- Proxy negotiation failed — отсутствует direct TCP fallback.
- Один readiness-файл другого PID не может разблокировать текущий PID.

## Monitoring

Хост агрегирует события без secrets:

```text
proxy.ready
proxy.route
proxy.failure
proxy.direct_leak
proxy.audit_failed
proxy.network_guard_started
```

Для process tree хранить PID, parent PID, readiness, routed/failure counters и
sanitized target class. Полные proxy URI, username/password и raw public IP в
API/SQLite/support bundle не возвращать.

TCP owner audit — reactive defense in depth. Он не заменяет WFP и не видит UDP.
WFP/allowlist — отдельный host-provider, не часть DLL.

## PoE-specific decision

PoE1 MVP требует доказанного TCP/HTTPS routing для patch/login/instance paths.
Generic UDP backend не является обязательным, пока live capture не покажет
необходимый UDP трафик PoE. Если такой трафик появится, выбирать packet-level
backend отдельно, с оценкой driver deployment и лицензии.

System DNS допускается как явно отображаемая capability boundary: он не меняет
TCP exit, но раскрывает hostname локальному resolver. Proxy-side DNS становится
обязательным только при соответствующем privacy requirement.

## Shutdown

Остановка должна быть ограничена конкретным sandbox/profile process tree.
Нельзя завершать все процессы по имени. После stop хост проверяет отсутствие
своих PID, удаляет ephemeral config и восстанавливает только принадлежащие ему
network/injection settings.
