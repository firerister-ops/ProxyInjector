# Testing Procedures

Полное руководство по тестированию ProxyPayload v2.

## Уровни тестов

1. **Юнит** — test_client.exe (1 TCP запрос)
2. **Прикладные** — Chrome, PoE
3. **Stress** — множественные соединения
4. **Negative** — прокси недоступен, fallback пути

---

## 1. Юнит-тест: test_client.exe

### Что проверяет

- Загрузка DLL в процесс
- Хук `getaddrinfo` возвращает dummy IP
- Хук `connect` вызывает SOCKS5 handshake
- Данные корректно проходят через прокси

### Процедура

```cmd
:: 1. Очистить лог
del %TEMP%\proxy_v2_log.txt

:: 2. Запустить test_client с задержкой 2с (чтобы DLL успела загрузиться)
start "" C:\ABF\ProxyInjector\bin\test_client.exe 2 api.ipify.org 80

:: 3. Сразу инжектировать (использовать актуальный PID из вывода)
C:\ABF\ProxyInjector\bin\Injector.exe <PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 4. Дождаться завершения (5-10с)
:: 5. Проверить вывод — должен быть IP прокси
```

### Ожидаемый результат

```
[test_client] PID=26684 — sleeping 2 sec for DLL injection
[test_client] Resolving api.ipify.org:80...
[test_client] Resolved to 240.3.181.76        ← dummy IP (240.x.x.x)
[test_client] Calling connect()...
[test_client] CONNECTED!
[test_client] Received 224 bytes
HTTP/1.1 200 OK
...
your.proxy.ip                                  ← IP прокси, не реальный
[test_client] DONE
```

### Проверка без прокси

```cmd
:: Без инжекции — должен показать реальный IP
C:\ABF\ProxyInjector\bin\test_client.exe 0 api.ipify.org 80
```

Должен показать ваш реальный публичный IP (`77.221.137.0` или подобное).

---

## 2. End-to-end: Path of Exile

### Предварительные условия

- Установленный PoE: `C:\Users\FRD1\Desktop\PathofExilesmooth\`
- Аккаунт GGG с доступом к игре
- Активный SOCKS5 прокси

### Процедура

```cmd
:: 1. Убить все предыдущие инстансы
taskkill /F /IM PathOfExile*
taskkill /F /IM chrome.exe
taskkill /F /IM Injector.exe

:: 2. Очистить лог
del %TEMP%\proxy_v2_log.txt

:: 3. Запустить PoE (лаунчер)
start "" C:\Users\FRD1\Desktop\PathofExilesmooth\PathOfExile_x64.exe

:: 4. Дождаться основного процесса (10-20с)
powershell "Get-Process PathOfExile | Select Id, ProcessName, @{N='Mem';E={[math]::Round($_.WorkingSet64/1MB)}}"

:: 5. Инжектировать в основной процесс (PID из вывода выше)
C:\ABF\ProxyInjector\bin\Injector.exe <PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 6. Мониторить лог
powershell "Get-Content $env:TEMP\proxy_v2_log.txt -Wait"
```

### Ожидаемые соединения PoE через прокси

| Хост | Порт | Тип |
|---|---|---|
| `web.poecdn.com` | 443 | HTTPS (CDN) |
| `webcdn.pathofexile.com` | 80 | HTTP (web assets) |
| `www.pathofexile.com` | 443 | HTTPS |
| `ams.login.pathofexile.com` | 20484 | Login EU |
| `us.login.pathofexile.com` | 20484 | Login US |
| `<game-server-ip>` | 6112 | TCP game server (через IPv4-mode) |

### Проверка стабильности

Скрипт мониторинга 90с:

```powershell
$poeId = <PID>
$startTime = Get-Date
for ($i=0; $i -lt 18; $i++) {
    Start-Sleep 5
    $elapsed = [int]((Get-Date) - $startTime).TotalSeconds
    $p = Get-Process -Id $poeId -ErrorAction SilentlyContinue
    if (-not $p) { Write-Host "[${elapsed}s] CRASHED!"; break }
    $mem = [math]::Round($p.WorkingSet64/1MB, 0)
    $logLines = (Get-Content "$env:TEMP\proxy_v2_log.txt" -ErrorAction SilentlyContinue | Measure-Object).Count
    $connects = (Get-Content "$env:TEMP\proxy_v2_log.txt" -ErrorAction SilentlyContinue | Select-String 'PROXY_OK').Count
    Write-Host "[${elapsed}s] alive Mem=${mem}MB LogLines=${logLines} SOCKS5=${connects}"
}
```

**Критерий успеха**: 90+ секунд без краша, 5+ успешных TCP соединений через SOCKS5.

---

## 3. End-to-end: Chrome

### Особенности

Chrome создаёт много дочерних процессов с sandbox. Для инжекции во все нужно:
- `--no-sandbox` — отключает sandbox
- `--disable-quic` — отключает QUIC (UDP 443), форсит TCP

### Процедура

```cmd
:: 1. Запустить Chrome с флагами
start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --no-sandbox --disable-quic

:: 2. Подождать 3с
timeout /t 3

:: 3. Инжектировать во ВСЕ chrome.exe процессы
C:\ABF\ProxyInjector\bin\Injector.exe chrome.exe C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 4. Открыть сайт IP-проверы
start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" "http://api.ipify.org"
```

### Ожидаемый результат

В окне должен отобразиться IP прокси, а не ваш реальный IP.

### Watch mode (для постоянного мониторинга)

```cmd
:: Injector будет инжектить во все новые chrome.exe автоматически
C:\ABF\ProxyInjector\bin\Injector.exe --watch chrome.exe C:\ABF\ProxyInjector\bin\ProxyPayload.dll
```

---

## 4. Negative test: прокси недоступен

### Что проверяет

- Fail-closed поведение
- Что НЕ происходит fallback на direct connection
- Структурированные `PROXY_FAIL` логи

### Процедура

```cmd
:: 1. Временно изменить конфиг на несуществующий прокси
copy C:\ABF\ProxyInjector\bin\proxy_config.txt proxy_config.txt.bak
(echo SOCKS5_HOST=192.0.2.1& echo SOCKS5_PORT=12345& echo TIMEOUT_SEC=3) > C:\ABF\ProxyInjector\bin\proxy_config.txt

:: 2. Запустить test_client
start "" C:\ABF\ProxyInjector\bin\test_client.exe 2 api.ipify.org 80

:: 3. Инжектировать
C:\ABF\ProxyInjector\bin\Injector.exe <PID> C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 4. Дождаться завершения (~10с с timeout)

:: 5. Проверить что в логе PROXY_FAIL
type %TEMP%\proxy_v2_log.txt | findstr PROXY_FAIL

:: 6. Восстановить конфиг
copy proxy_config.txt.bak C:\ABF\ProxyInjector\bin\proxy_config.txt
```

### Ожидаемый результат

```
PROXY_FAIL phase=tcp_connect target=api.ipify.org:80 reason=proxy_unreachable
```

test_client должен показать:
```
[test_client] Calling connect()...
[test_client] connect FAILED err=10061       ← WSAECONNREFUSED
```

**НЕ должен** загрузить страницу напрямую (это была бы утечка IP).

---

## 5. UDP ASSOCIATE тест (QUIC)

### Что проверяет

- Hook `bind` создаёт SOCKS5 UDP ASSOCIATE
- `sendto` инкапсулирует UDP пакеты
- `recvfrom` декапсулирует ответы
- QUIC трафик Chrome идёт через прокси

### Процедура

```cmd
:: 1. Запустить Chrome БЕЗ --disable-quic (чтобы использовал QUIC)
start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --no-sandbox

:: 2. Инжектировать
C:\ABF\ProxyInjector\bin\Injector.exe chrome.exe C:\ABF\ProxyInjector\bin\ProxyPayload.dll

:: 3. Проверить лог
type %TEMP%\proxy_v2_log.txt | findstr "UDP ASSOCIATE"
```

### Ожидаемый результат

```
UDP ASSOCIATE established for socket 6372
UDP ASSOCIATE established for socket 6452
...
```

Несколько успешных UDP ASSOCIATEs.

---

## 6. Stress test: много соединений

### Процедура

Запустить несколько одновременных test_client:

```powershell
# Запустить 10 одновременных test_client
$jobs = @()
for ($i=0; $i -lt 10; $i++) {
    $proc = Start-Process -FilePath "C:\ABF\ProxyInjector\bin\test_client.exe" `
        -ArgumentList "2","api.ipify.org","80" -PassThru -NoNewWindow
    $jobs += $proc
    Start-Sleep -Milliseconds 100
    cmd /c "C:\ABF\ProxyInjector\bin\Injector.exe $($proc.Id) C:\ABF\ProxyInjector\bin\ProxyPayload.dll 2>&1" | Out-Null
}

# Дождаться всех
$jobs | ForEach-Object { Wait-Process -Id $_.Id -Timeout 30 }

# Статистика
$log = Get-Content "$env:TEMP\proxy_v2_log.txt"
Write-Host "PROXY_OK: $(($log | Select-String 'PROXY_OK').Count)"
Write-Host "PROXY_FAIL: $(($log | Select-String 'PROXY_FAIL').Count)"
```

### Критерий успеха

10/10 PROXY_OK, 0 PROXY_FAIL. Если есть fails — прокси перегружен или timeout слишком короткий.

---

## 7. Dummy IP mapping тест

### Что проверяет

- Один и тот же hostname всегда даёт один и тот же dummy IP
- Разные hostname дают разные dummy IPs
- LookupDummy корректно находит hostname по IP

### Процедура

Запустить test_client 3 раза с одним хостом, 1 раз с другим:

```cmd
test_client.exe 2 api.ipify.org 80    → Resolved to 240.X.Y.Z
test_client.exe 2 api.ipify.org 80    → Resolved to 240.X.Y.Z (тот же!)
test_client.exe 2 api.ipify.org 80    → Resolved to 240.X.Y.Z (тот же!)
test_client.exe 2 ifconfig.me 80      → Resolved to 240.A.B.C  (другой)
```

FNV-1a hash детерминированный — одинаковый hostname всегда даёт одинаковый IP.

---

## Лог анализ

### Формат лога

```
[HH:MM:SS.mmm][PID=12345] message
```

### Полезные фильтры

```powershell
$log = Get-Content "$env:TEMP\proxy_v2_log.txt"

# Все успешные соединения
$log | Select-String 'PROXY_OK'

# Все ошибки
$log | Select-String 'PROXY_FAIL|failed|FAILED'

# Заблокированные утечки (IPv6, raw)
$log | Select-String 'BLOCKED'

# UDP ассоциации
$log | Select-String 'UDP ASSOCIATE'

# Все connect() вызовы с target
$log | Select-String 'connect\(' | ForEach-Object {
    if ($_ -match 'connect\(([^)]+)\)') { $matches[1] }
}

# Статистика по фазам fail
$log | Select-String 'phase=(\w+)' | ForEach-Object {
    if ($_ -match 'phase=(\w+)') { $matches[1] }
} | Group-Object | Select-Object Count, Name
```

### Метрики для мониторинга

| Метрика | Как считать | Норма |
|---|---|---|
| PROXY_OK rate | count per minute | >10 для активной сессии PoE |
| PROXY_FAIL rate | count per minute | <2 (допускается retry) |
| Fail ratio | fails / (fails + ok) | <5% |
| Avg handshake time | timestamp PROXY_OK - connect | <500мс |
| UDP ASSOC count | active UDP ASSOCs | 1-5 для Chrome |

---

## Автоматизация (для CI/ControlPanel)

### PowerShell скрипт для smoke-теста

```powershell
function Test-ProxyInjection {
    param([string]$ProxyHost, [int]$ProxyPort)

    # 1. Запустить test_client
    $proc = Start-Process -FilePath "C:\ABF\ProxyInjector\bin\test_client.exe" `
        -ArgumentList "3","api.ipify.org","80" -PassThru -NoNewWindow

    # 2. Инжектировать
    Start-Sleep -Milliseconds 300
    cmd /c "C:\ABF\ProxyInjector\bin\Injector.exe $($proc.Id) C:\ABF\ProxyInjector\bin\ProxyPayload.dll 2>&1" | Out-Null

    # 3. Дождаться
    Wait-Process -Id $proc.Id -Timeout 30
    $output = $proc.StandardOutput.ReadToEnd()

    # 4. Проверить IP
    if ($output -match '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b') {
        $seenIp = $matches[1]
        if ($seenIp -eq $ProxyHost) {
            Write-Host "✓ PASS: traffic routed through $ProxyHost"
            return $true
        } else {
            Write-Host "✗ FAIL: expected $ProxyHost, got $seenIp"
            return $false
        }
    }
    Write-Host "✗ FAIL: no IP in output"
    return $false
}
```

---

## Известные тест-кейсы и их результаты

| Кейс | Поведение | Статус |
|---|---|---|
| TCP connect blocking socket | RouteTcp → SOCKS5 → success | ✅ |
| TCP connect non-blocking | SOCKS5 sync + return WSAEWOULDBLOCK | ✅ |
| WSAConnect blocking | То же что connect | ✅ |
| WSAConnectByNameW | Domain-mode SOCKS5 напрямую | ✅ |
| UDP bind + sendto | SOCKS5 UDP ASSOCIATE | ✅ |
| DNS getaddrinfo | Dummy IP, AAAA вырезаны | ✅ |
| IPv6 connect | WSAEAFNOSUPPORT | ✅ |
| SOCK_RAW socket | WSAEACCES | ✅ |
| Proxy unreachable | WSAECONNREFUSED (fail-closed) | ✅ |
| ConnectEx через WSAIoctl | My_ConnectEx wrapper | ✅ |
| Child process | Auto-inject через CreateProcess | ✅ |
| Multi-client (10x) | Изоляция через процессы | ✅ |
| PoE 90+ секунд | Стабильно, 6+ TCP соединений | ✅ |
| Chrome 113+ TCP соединений | Все через прокси | ✅ |
