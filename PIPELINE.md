# Pipeline Integration: PoE Launcher + Proxy Injector

Полная спецификация паттернов launcher phase и pipeline для интеграции в ControlPanel.

---

## 1. Сравнение PoE1 vs PoE2 — хосты и порты

### Сводная таблица серверов

| Роль | PoE1 (3.29.2) | PoE2 (4.5.4.8.2) |
|---|---|---|
| **Patch server (handshake)** | `patch.pathofexile.com:12995` | `us.patch.pathofexile2.com:13060` |
| **CDN (скачивание файлов)** | `patch.poecdn.com:443` | `patch-poe2.poecdn.com:443` |
| **Web check** | `www.pathofexile.com:443` | `www.pathofexile.com:443` |
| **Login server (game)** | `*.login.pathofexile.com:20484` | `*.login.pathofexile.com:20484` |
| **Instance server (game)** | `<ip>:6112` | `<ip>:6112` |

> Примечание: CDN-хост PoE1 (`patch.poecdn.com`) виден в Client.txt как `Web root: https://patch.poecdn.com/3.29.2.1/` — в реальный connect превращается только если есть файлы для скачивания.

### Паттерн имён хостов для детекции

| Фаза | PoE1 (regex) | PoE2 (regex) | Универсальный |
|---|---|---|---|
| Handshake | `patch\.pathofexile\.com` | `.*\.patch\.pathofexile2\.com` | `.*\.patch\.pathofexile2?\.com` |
| Download (CDN) | `patch\.poecdn\.com` | `patch-poe2\.poecdn\.com` | `patch.*\.poecdn\.com` |
| Web check | `www\.pathofexile\.com` | `www\.pathofexile\.com` | `www\.pathofexile\.com` |
| Login | `.*\.login\.pathofexile\.com` | `.*\.login\.pathofexile\.com` | `.*\.login\.pathofexile\.com` |
| Instance | `.*:6112` | `.*:6112` | `.*:6112` |

---

## 2. Три теста — три сценария

### ТЕСТ A: PoE2, обновление ДОСТУПНО (12 ГБ патч)

**Состояние:** Content.ggpk устарел, нужно скачивание.

**Хронология (proxy log, PID 25284):**

| Время | Хост | Что происходит |
|---|---|---|
| 11:20:31 | — | PathOfExile.exe запущен, DLL загружена, hooks активны |
| 11:20:41 | — | `Finished checking files` (launcher составил список файлов) |
| 11:20:42 | `patch-poe2.poecdn.com:443` | PROXY_OK (1-й файл) |
| 11:20:43 | `patch-poe2.poecdn.com:443` | PROXY_OK (2-й файл) |
| 11:20:44 | `patch-poe2.poecdn.com:443` | PROXY_OK (3-й файл) |
| 11:20:45 | `patch-poe2.poecdn.com:443` | PROXY_OK (4-й файл) |
| 11:20:46 | `patch-poe2.poecdn.com:443` | PROXY_OK (5-й файл) |
| 11:20:47 | `patch-poe2.poecdn.com:443` | PROXY_OK (6-й файл) |
| 11:20:48 | `patch-poe2.poecdn.com:443` | **PROXY_OK (последний)** |
| 11:22:13 | — | `Error: Transferred a partial file` (PoE log) |
| 11:23:07 | `www.pathofexile.com:443` | PROXY_OK (финальная проверка сайта) |
| 11:23:08+ | — | **ТИШИНА** → PLAY активна |

**Активность:** ~3 минуты (скачивание + проверка), затем тишина.

**Маркеры:**
- `Finished checking files` = список составлен (НЕ завершение!)
- `patch-poe2.poecdn.com:443` — **CDN для скачивания файлов**
- `www.pathofexile.com:443` в конце = launcher закончил update, проверяет web
- Тишина 60+ секунд = PLAY готова

### ТЕСТ B: PoE2, обновление НЕ требуется

**Состояние:** Content.ggpk актуален. `--require-launch` — лаунчер без автозапуска игры.

**Хронология (proxy log, PID 18128):**

| Время | Хост | Что происходит |
|---|---|---|
| 11:39:42 | — | DLL loaded, hooks active |
| 11:39:44 | `us.patch.pathofexile2.com:13060` | PROXY_OK (patch server handshake) |
| 11:39:45 | `www.pathofexile.com:443` | PROXY_OK (web check) |
| 11:39:46 | — | `Finished checking files` |
| 11:39:47+ | — | **ТИШИНА** → PLAY активна |

**Активность:** 5 секунд, затем тишина. 132 сек подтверждённой тишины = PLAY ready.

**Маркеры:**
- Нет коннектов к `*.poecdn.com` (CDN) = обновления нет
- Сразу `Finished checking files` → PLAY готова

### ТЕСТ C: PoE1, обновление НЕ требуется (06.08.2026, 13:03)

**Состояние:** Клиент актуален (3.29.2). `--require-launch` — лаунчер без автозапуска игры.

**Хронология (proxy log, PID 12528):**

| Время | Хост | Что происходит |
|---|---|---|
| 13:03:56 | — | DLL loaded, hooks active |
| 13:03:56.973 | `patch.pathofexile.com:12995` | DNS → connect (handshake) |
| 13:03:57.537 | `patch.pathofexile.com:12995` | PROXY_OK (patch server handshake) |
| 13:03:58.040 | `www.pathofexile.com:443` | DNS → connect (web check, non-blocking) |
| 13:03:58.614 | `www.pathofexile.com:443` | PROXY_OK (web check done) |
| 13:03:58 | — | `Finished checking files` (PoE log) |
| 13:04:00+ | — | **ТИШИНА** → PLAY активна |

**Активность:** ~6 секунд, 132 сек подтверждённой тишины = PLAY ready.

**PoE Client.txt ключевые строки:**
```
[HTTP2] User agent: PoE release/tags/3.29.2 Windows x64
Send patching protocol version 7
Web root: https://patch.poecdn.com/3.29.2.1/
Backup Web root: https://patch.poecdn.com/3.29.2.1/
Requesting root contents 1
Requesting folder D3D12 2
Requesting folder Redist 3
Requesting folder Streamline 4
Got file list for "" 1
Got file list for "D3D12" 2
Got file list for "Redist" 1
Got file list for "Streamline" 0
Finished checking files
```

**Маркеры для PoE1:**
- Patch server: `patch.pathofexile.com:12995` (НЕ `.com:13060` как у PoE2)
- CDN (в Client.txt): `Web root: https://patch.poecdn.com/3.29.2.1/` — в connect превращается только если есть файлы
- Нет CDN connect = обновления нет
- Структура лога идентична PoE2 (те же `Requesting root contents`, `Finished checking files`)

---

## 3. Паттерны для детекции фаз

### Хосты и их роли (универсальные, PoE1 + PoE2)

| Хост | Порт | PoE1 | PoE2 | Роль |
|---|---|---|---|---|
| `patch.pathofexile.com` | 12995 | ✅ | — | Patch server (PoE1) |
| `us.patch.pathofexile2.com` | 13060 | — | ✅ | Patch server (PoE2) |
| `patch.poecdn.com` | 443 | ✅ | — | CDN скачивание (PoE1) |
| `patch-poe2.poecdn.com` | 443 | — | ✅ | CDN скачивание (PoE2) |
| `www.pathofexile.com` | 443 | ✅ | ✅ | Web check (после update) |
| `*.login.pathofexile.com` | 20484 | ✅ | ✅ | Login (game phase) |
| `<ip>:6112` | 6112 | ✅ | ✅ | Instance (game phase) |

### Фазы launcher'а (детекция по proxy log)

```
[ФАЗА 1: HANDSHAKE] ~1-2 сек
  PoE1: PROXY_OK patch.pathofexile.com:12995
  PoE2: PROXY_OK us.patch.pathofexile2.com:13060

[ФАЗА 2: CHECK FILES] 2-10 сек
  В PoE логе: "Finished checking files"
  В proxy log: НЕЗНАЧИТ само завершение фазы
  
[ФАЗА 3: DOWNLOAD] (только если есть update) — переменная длительность
  PoE1: PROXY_OK patch.poecdn.com:443 (много, каждые 600-700мс)
  PoE2: PROXY_OK patch-poe2.poecdn.com:443 (много, каждые 600-700мс)
  Файлы качаются параллельно через CDN
  
[ФАЗА 4: INSTALL/VERIFY] ~10-30 сек после последнего download
  Тишина в proxy log, но процесс ещё работает
  
[ФАЗА 5: WEB CHECK] 1-2 сек
  PROXY_OK www.pathofexile.com:443
  
[ФАЗА 6: PLAY READY] вечная тишина
  PLAY кнопка активна, ждёт пользователя
```

### КРИТЕРИЙ "PLAY ГОТОВА"

**Все условия (И):**
1. Прошла фаза handshake:
   - PoE1: `patch.pathofexile.com:12995` был в proxy log
   - PoE2: `us.patch.*.pathofexile2.com:13060` был в proxy log
2. Был `Finished checking files` (в PoE логе)
3. Если было скачивание (`patch*.poecdn.com`) — оно завершилось
4. **ТИШИНА в proxy log минимум 60 секунд** (последний PROXY_OK был ≥60с назад)

### ЧТО НЕЛЬЗЯ ИСПОЛЬЗОВАТЬ КАК МАРКЕР

- ❌ `Finished checking files` — НЕ означает завершение. Означает старт скачивания. Подтверждено в ТЕСТАХ A, B, C.
- ❌ Появление `www.pathofexile.com` — в ТЕСТАХ B и C появляется ДО `Finished checking files`, не AFTER download. Не годится как маркер завершения.
- ❌ Размер Content.ggpk — растёт непредсказуемо, последняя фаза может быть почти незаметна.
- ❌ Последняя строка PoE лога — часто пустая во время фазы download/install.

### Таблица детекции фаз (универсальная)

| Фаза | Условие (proxy log) | Условие (PoE Client.txt) | Таймаут |
|---|---|---|---|
| **Старт launcher** | DLL loaded + hooks enabled | `LOG FILE OPENING` | 30 сек |
| **Handshake** | PROXY_OK к `patch.*pathofexile*.com:12995/13060` | `Send patching protocol version` | 60 сек |
| **Check files** | (в это время proxy может быть тихий) | `Requesting root contents`, `Requesting folder *`, `Finished checking files` | 120 сек |
| **Download** | PROXY_OK к `patch*.poecdn.com:443` | (тихо, или `Queue file to download`) | MaxUpdateWait |
| **Install/Verify** | Тишина в proxy log, процесс жив | (тихо) | 120 сек |
| **Web check** | PROXY_OK к `www.pathofexile.com:443` | (необязательно) | 30 сек |
| **PLAY ready** | 60 сек тишина после последнего PROXY_OK | `Finished checking files` уже было | — |
| **Game login** | PROXY_OK к `*.login.pathofexile.com:20484` | `Async connecting to *.login` | 180 сек |
| **In game** | PROXY_OK к `<ip>:6112` | `Connecting to instance server at IP:6112` | — |

> **Важно:** Web check (`www.pathofexile.com:443`) может появиться КАК ДО скачивания (ТЕСТ B, C), ТАК И ПОСЛЕ (ТЕСТ A). Он не является надёжным маркером завершения. Единственный надёжный критерий PLAY ready = **60 сек тишины**.

---

## 4. Pipeline для ControlPanel (Production)

### Полный flow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. SETUP                                                       │
│     • Archive текущий Client.txt → archive/                     │
│     • Clear proxy_v2_log.txt                                    │
│     • Write proxy_config.txt (SOCKS5 host:port:user:pass)      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. START WATCH (background)                                    │
│     Injector.exe --watch PathOfExile.exe <dll>                  │
│     (ловит self-restart если "Updating client executable")      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. LAUNCH (CREATE_SUSPENDED + inject + resume)                │
│     Injector.exe --launch <exe> --dll <dll>                     │
│     (без --require-launch — пусть лаунчер сам решит,            │
│      нужно обновление или нет)                                   │
│     DLL грузится ДО первой инструкции main()                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. MONITOR PHASE 1: HANDSHAKE                                 │
│     Ждать PROXY_OK к patch server:                              │
│     PoE1: patch.pathofexile.com:12995                            │
│     PoE2: us.patch.pathofexile2.com:13060                        │
│     Timeout: 60 сек                                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. MONITOR PHASE 2: DOWNLOAD                                   │
│     Если есть PROXY_OK к patch*.poecdn.com → update в работе    │
│     PoE1: patch.poecdn.com:443                                  │
│     PoE2: patch-poe2.poecdn.com:443                             │
│     Ждать до MaxWaitMinutes                                     │
│     Печатать прогресс (count of PROXY_OK) каждые 10 сек         │
│     Если CDN коннектов не было — обновление не нужно,           │
│     сразу переход к шагу 6                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. WAIT FOR SILENCE (PLAY готов)                              │
│     Ждать пока последний PROXY_OK был ≥60 секунд назад          │
│     Это значит скачивание+установка завершены                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. KILL LAUNCHER                                              │
│     Stop-Process PathOfExile.exe                                │
│     (после 60с тишины — PLAY точно готова, можно убивать)       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  8. ARCHIVE LOG                                                │
│     Move Client.txt → archive/Client_launcher_TIMESTAMP.txt    │
│     Clear proxy_v2_log.txt                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  9. RE-LAUNCH (CREATE_SUSPENDED + inject + resume)             │
│     Injector.exe --launch <exe> --dll <dll>                     │
│     DLL грузится ДО первой инструкции main()                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  10. MONITOR GAME PHASE                                        │
│      Ждать PROXY_OK к *.login.pathofexile.com:20484            │
│      Timeout: 180 сек                                           │
│      (game может требовать ручной логин)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  11. DONE                                                      │
│      Игра работает через прокси                                 │
│      Stop watch (больше не нужен)                              │
└─────────────────────────────────────────────────────────────────┘
```

### Псевдокод для ControlPanel

```csharp
public async Task<LaunchResult> LaunchThroughProxy(string exePath, ProxyConfig proxy)
{
    // 1. Setup
    ArchiveLog(Path.Combine(gamePath, "logs", "Client.txt"));
    ClearLog(proxyLogPath);
    WriteProxyConfig(gamePath, proxy);
    
    // 2. Start watch (catches self-restart)
    var watch = StartInjector("--watch", "PathOfExile.exe", dllPath);
    
    try {
        // 3. Launch with CREATE_SUSPENDED injection (no --require-launch)
        var pid = StartInjectorLaunch(exePath, dllPath);
        
        // 4. Wait for handshake (PoE1 or PoE2 patch server)
        await WaitForProxyEvent(
            p => p.Host.Contains("patch.pathofexile.com")    // PoE1 :12995
              || p.Host.Contains("patch.pathofexile2.com"), // PoE2 :13060
            timeoutSec: 60);
        
        // 5. Optional download phase (0 sec if no update needed)
        // CDN patterns: PoE1=patch.poecdn.com, PoE2=patch-poe2.poecdn.com
        var downloadHostPattern = "poecdn.com";
        var downloadEvents = new List<ProxyEvent>();
        while (true) {
            var last = GetLastProxyEvent();
            var silenceSeconds = (DateTime.Now - last.Timestamp).TotalSeconds;
            if (silenceSeconds >= 60) break; // PLAY ready (with or without update)
            
            var newEvents = GetNewProxyEvents(matchingHost: downloadHostPattern);
            downloadEvents.AddRange(newEvents);
            
            OnDownloadProgress?.Invoke(newEvents.Count);
            await Task.Delay(5000);
        }
        
        // 6. Silence reached — PLAY ready
        // 7. Kill launcher
        KillProcess(pid);
        await Task.Delay(3000);
        
        // 8. Archive
        ArchiveLog(Path.Combine(gamePath, "logs", "Client.txt"));
        ClearLog(proxyLogPath);
        
        // 9. Re-launch
        pid = StartInjectorLaunch(exePath, dllPath);
        
        // 10. Wait for game login
        await WaitForProxyEvent(p => p.Host.Contains("login.pathofexile.com"), timeoutSec: 180);
        
        return new LaunchResult { Pid = pid, Success = true };
    } finally {
        // 11. Stop watch
        StopProcess(watch);
    }
}
```

---

## 5. CREATE_SUSPENDED Injection (детально)

### Принцип

```
ВРЕМЕННАЯ ШКАЛА ПРОЦЕССА:

Обычный запуск:
  T0: CreateProcess → kernel maps ntdll, kernel32, ... → main() start
  T1: PoE main() инициализирует сетевой стек
  T2: PoE делает первый connect()  ← РЕАЛЬНЫЙ IP УТЕЧЁТ

CREATE_SUSPENDED запуск:
  T0: CreateProcess(SUSPENDED) → kernel maps DLLs, main thread PAUSED
  T1: InjectDLL (LoadLibrary через CreateRemoteThread)
      → наша DLL грузится В ОТДЕЛЬНОМ ПОТОКЕ пока main thread sleeping
      → DllMain выполняется, MinHook устанавливает 19 хуков
  T2: ResumeThread(main) → main() стартует
  T3: PoE main() инициализирует сетевой стек → ХУКИ УЖЕ АКТИВНЫ
  T4: PoE делает connect() → ИДЁТ ЧЕРЕЗ ПРОКСИ ✓
```

### Код (Injector.exe LaunchMode)

```cpp
// 1. Создаём процесс с приостановленным главным потоком
CreateProcessW(NULL, wCmdLine, NULL, NULL, FALSE,
               CREATE_SUSPENDED,  // ← КЛЮЧЕВОЙ ФЛАГ
               NULL, workDir, &si, &pi);

// 2. В suspended процессе:
//    - kernel уже загрузил ntdll, kernel32
//    - main thread остановлен в LdrInitializeThunk (до main)
//    - мы можем вызывать LoadLibraryW через отдельный поток

// 3. VirtualAllocEx + WriteProcessMemory (путь к DLL)
SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, pathSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(pi.hProcess, remoteMem, dllPath, pathSize, NULL);

// 4. CreateRemoteThread → LoadLibraryW → наша DLL грузится
//    Внутри DllMain: MH_Initialize() + 19 MH_CreateHookApi() + MH_EnableHook(MH_ALL_HOOKS)
FARPROC pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                    (LPTHREAD_START_ROUTINE)pLoadLibraryW,
                                    remoteMem, 0, NULL);
WaitForSingleObject(hThread, 10000);  // ждём пока DllMain завершится

// 5. ResumeThread → main() стартует с уже установленными хуками
ResumeThread(pi.hThread);
```

### Гарантия

После CREATE_SUSPENDED injection, **первый connect() в PoE** уже проходит через наш хук. Реальный IP не утечёт ни на миллисекунду.

### Почему NtCreateThreadEx лучше чем CreateRemoteThread

Используется в `InjectDLL()`:
```cpp
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                 (PVOID)pLoadLibraryW, remoteMem, 0, 0, 0, 0, NULL);
```

- Не перехватывается user-mode hooks (EDR обычно хукают CreateRemoteThread)
- Меньше детектируется AV
- Fallback на CreateRemoteThread если NtCreateThreadEx недоступен

---

## 6. Маркеры в логах (полный справочник)

### PoE Client.txt (лог игры/лаунчера)

| Маркер | Значение |
|---|---|
| `***** LOG FILE OPENING *****` | Старт процесса |
| `[HTTP2] User agent: PoE release/tags/X.Y.Z` | Версия клиента |
| `Web root: https://patch-poe2.poecdn.com/X.Y.Z.N/` | Версия патча |
| `Send patching protocol version N` | Начало patching phase |
| `Requesting root contents N` | Запрос корневого списка файлов |
| `Queue file to download: <file>` | Файл добавлен в очередь |
| `Got file list for "<folder>" N` | Получен список файлов папки |
| `Finished checking files` | **Список составлен, начинается фаза скачивания** (НЕ завершение!) |
| `Updating client executable and restarting.` | Self-update (PathOfExile.exe перезапустится) |
| `[STARTUP] Loading Start` | Завершение launcher phase, game init начинается |
| `[ENGINE] Init` | Engine инициализирован |
| `[ENGINE] Ready` | Engine готов |
| `Async connecting to *.login.pathofexile.com:20484` | Login phase |
| `Connected to *.login.pathofexile.com in Nms.` | Login OK |
| `Connecting to instance server at IP:6112` | **Игра идёт** |
| `You have entered <zone>` | Игрок вошёл в локацию |
| `Error: Transferred a partial file` | Сбой передачи файла (некритично) |
| `Abnormal disconnect` | Дисконнект (часто из-за смены IP прокси) |

### Proxy log (%TEMP%\proxy_v2_log.txt)

| Событие | Значение |
|---|---|
| `=== ProxyPayload v2 loaded PID=X ===` | DLL загружена в процесс |
| `All hooks enabled` | 19 hooks установлены |
| `GetAddrInfoW(host) → dummy 240.x.x.x` | DNS перехвачен |
| `connect(host:port) — routing via SOCKS5 domain` | TCP через прокси (domain mode) |
| `PROXY_OK target=host:port via=PROXY:PORT` | **Соединение установлено через прокси** |
| `PROXY_FAIL phase=tcp_connect reason=proxy_unreachable` | Прокси недоступен |
| `PROXY_FAIL phase=socks5_handshake reason=handshake_failed` | SOCKS5 handshake fail |
| `UDP ASSOCIATE established for socket N` | UDP через SOCKS5 |
| `connect: BLOCKED AF_INET6` | IPv6 заблокирован (zero-leak) |
| `socket: BLOCKED SOCK_RAW` | Raw socket заблокирован |

---

## 7. Таблица паттернов для детекции фаз

### Старт launcher'а

| Условие | Где искать |
|---|---|
| PROXY_OK к `us.patch.pathofexile2.com:13060` | proxy log |
| ИЛИ PROXY_OK к любому `*.pathofexile.com` в первые 30 сек | proxy log |

### Update доступен

| Условие |
|---|
| PROXY_OK к `patch-poe2.poecdn.com:443` ИЛИ `patch.poecdn.com:443` |
| = скачивание идёт |

### Update завершён / PLAY готова

**Все условия (И):**
1. Последний PROXY_OK был ≥ **60 секунд назад**
2. Был handshake (`us.patch.*` или `patch-*.poecdn.com`) раньше
3. Процесс PathOfExile.exe всё ещё жив

### Game phase началась

| Условие |
|---|
| PROXY_OK к `*.login.pathofexile.com:20484` |
| ИЛИ `Connecting to instance server at IP:6112` в PoE логе |

### Self-restart (нужно для --watch)

| Условие |
|---|
| В PoE логе: `Updating client executable and restarting.` |
| PathOfExile.exe процесс умирает и появляется новый PID |

---

## 8. Конфигурация для ControlPanel

### Per-account config

```ini
# Account1.ini
[proxy]
SOCKS5_HOST=your.proxy.ip
SOCKS5_PORT=1080
SOCKS5_USER=account1_user
SOCKS5_PASS=account1_pass

[game]
EXE_PATH=D:\Games\PathofExile2\PathOfExile.exe
TIMEOUT_SEC=3

[launch]
MAX_UPDATE_WAIT_MIN=30
SILENCE_THRESHOLD_SEC=60
LOGIN_TIMEOUT_SEC=180
```

### Запуск из ControlPanel

```
ControlPanel.exe --launch-account Account1
  ↓
  1. Читает Account1.ini
  2. Копирует proxy_config.txt в папку игры
  3. Запускает pipeline (см. раздел 3)
  4. Мониторит статусы
  5. Алерт при ошибке
```

### Статусы для UI

```
[SETUP]      Конфигурация...
[WATCH]      Watch mode активен
[LAUNCH]     Launcher запущен (PID 12345)
[HANDSHAKE]  Patch server handshake...
[DOWNLOAD]   Скачивание: 134 файла (PROXY_OK)
[SILENCE]    Тишина 45/60 сек (ждём PLAY)
[KILL]       Killing launcher...
[RELAUNCH]   Re-launching (PID 12346)
[GAME]       Login phase...
[DONE]       Игра запущена через прокси
[ERROR]      <причина>
```

---

## 9. Краевые случаи

### 8.1 Self-restart во время update

Если PoE находит апдейт `PathOfExile.exe` (самого себя):
- В логе: `Updating client executable and restarting.`
- Процесс умирает и сразу появляется новый
- `--watch` ловит и инжектит в новый процесс

### 8.2 Proxy умер во время update

- `PROXY_FAIL phase=tcp_connect` в логе
- Update может застрять
- ControlPanel должен detect 5+ PROXY_FAIL подряд → alert → restart

### 8.3 Partial file error

- `Error: Transferred a partial file` в PoE логе
- Некритично — launcher повторяет скачивание
- Не является ошибкой pipeline

### 8.4 "Abnormal disconnect" после login

- Login server видит смену IP (прокси)
- Требует повторный ввод пароля
- ControlPanel должен alert "требуется ручной логин"

### 8.5 Update большой (12+ ГБ)

- Фаза DOWNLOAD может быть 20-60 минут
- MAX_UPDATE_WAIT_MIN должен быть достаточно большим
- Контроль: если `patch-*.poecdn.com` PROXY_OK продолжаются — update идёт

---

## 10. Безопасность pipeline

### Что НЕ должно происходить

1. ❌ Любой PROXY_FAIL → критично, проверить прокси
2. ❌ Трафик мимо прокси → если hooks упали (DLL unload)
3. ❌ Прямой connect к `*.pathofexile.com` без прокси → утечка IP

### Защита от утечек

1. ✅ CREATE_SUSPENDED injection — hooks активны ДО первого connect
2. ✅ Fail-closed на proxy errors (WSAECONNREFUSED)
3. ✅ DNS через dummy IPs (нет DNS leak)
4. ✅ IPv6 connect заблокирован
5. ✅ Raw sockets заблокированы
6. ⚠️ Windows Firewall правило на уровне ControlPanel (kernel-level kill switch)
7. ⚠️ Self-protection DLL (TODO — не реализовано в текущей версии)

### Мониторинг для ControlPanel

- Парсить proxy log в реальном времени
- Алерт на любой PROXY_FAIL
- Алерт если нет PROXY_OK 5+ минут во время активной фазы
- Kill процесс если IP утёк (детект через прямой connect мимо хуков)
