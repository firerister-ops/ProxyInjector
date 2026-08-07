// Injector.cpp — NtCreateThreadEx-based DLL injector
// Pattern from SocksCap64 Injector64.exe:
//   OpenProcess → VirtualAllocEx → WriteProcessMemory → NtCreateThreadEx(LoadLibraryW) → WaitForSingleObject → VirtualFreeEx

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>

// MinGW doesn't define NTSTATUS / NTAPI — supply minimal definitions
#ifndef NTAPI
#define NTAPI __stdcall
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef long NTSTATUS;

// PPS_ATTRIBUTE_LIST is defined in ntdll winternl.h, define manually for MinGW
typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1]; // variable length
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// NtCreateThreadEx function pointer type (same as SocksCap64)
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

static pfnNtCreateThreadEx NtCreateThreadEx = NULL;

static BOOL InjectDLL(HANDLE hProcess, const wchar_t* dllPath) {
    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    // 1. Allocate memory in target process for the DLL path
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        fprintf(stderr, "VirtualAllocEx failed: %lu\n", GetLastError());
        return FALSE;
    }

    // 2. Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, NULL)) {
        fprintf(stderr, "WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    // 3. Get LoadLibraryW address (same in all processes due to ASLR base sharing)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        fprintf(stderr, "GetProcAddress(LoadLibraryW) failed\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    // 4. Create remote thread via NtCreateThreadEx (bypasses hooks on CreateRemoteThread)
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)pLoadLibraryW,
        remoteMem,
        0,  // flags = 0 for hidden thread
        0,  // zeroBits
        0,  // stackSize (0 = default)
        0,  // maximumStackSize
        NULL
    );

    if (status != 0 || !hThread) {
        // Fallback: use CreateRemoteThread (some processes may not block it)
        fprintf(stderr, "NtCreateThreadEx failed (0x%lX), falling back to CreateRemoteThread\n", status);
        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)pLoadLibraryW, remoteMem, 0, NULL);
        if (!hThread) {
            fprintf(stderr, "CreateRemoteThread also failed: %lu\n", GetLastError());
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            return FALSE;
        }
    }

    // 5. Wait for LoadLibraryW to complete
    DWORD waitResult = WaitForSingleObject(hThread, 10000); // 10s timeout
    if (waitResult == WAIT_TIMEOUT) {
        fprintf(stderr, "Thread timed out — DLL may not have loaded\n");
    }

    // 6. Get thread exit code (= HMODULE of loaded DLL, or 0 on failure)
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    if (exitCode == 0) {
        fprintf(stderr, "LoadLibraryW returned NULL — DLL failed to load in target\n");
        return FALSE;
    }

    fprintf(stderr, "Injection OK — DLL loaded at 0x%lX\n", exitCode);
    return TRUE;
}

static BOOL InjectByPid(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return FALSE;
    }

    BOOL result = InjectDLL(hProcess, dllPath);
    CloseHandle(hProcess);
    return result;
}

static BOOL InjectByName(const wchar_t* processName, const wchar_t* dllPath) {
    // Snapshot all processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    int injected = 0;
    int failed = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                fprintf(stderr, "Found %ls PID=%lu\n", processName, pe.th32ProcessID);
                if (InjectByPid(pe.th32ProcessID, dllPath)) {
                    injected++;
                } else {
                    failed++;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);

    fprintf(stderr, "Results: %d injected, %d failed\n", injected, failed);
    return injected > 0;
}

// ============================================================================
// Watch mode: monitor for target process and inject immediately
// This mimics SocksCap64's delayinj.ini approach — inject BEFORE the target
// process initializes its network stack (so WSAIoctl hooks catch ConnectEx).
// ============================================================================

static BOOL IsProcessAlreadyInjected(DWORD pid, const wchar_t* dllName) {
    // Check if the target PID already has our DLL loaded
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    BOOL found = FALSE;

    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllName) == 0) {
                found = TRUE;
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return found;
}

static void WatchMode(const wchar_t* processName, const wchar_t* dllPath, const wchar_t* dllName) {
    fprintf(stderr, "[WATCH] Monitoring for %ls — inject on sight\n", processName);
    fprintf(stderr, "[WATCH] Press Ctrl+C to stop\n");

    DWORD injectedCount = 0;

    while (1) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            Sleep(200);
            continue;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName) == 0) {
                    DWORD pid = pe.th32ProcessID;

                    // Skip if already injected
                    if (IsProcessAlreadyInjected(pid, dllName)) {
                        continue;
                    }

                    fprintf(stderr, "[WATCH] NEW %ls PID=%lu — injecting...\n", processName, pid);

                    if (InjectByPid(pid, dllPath)) {
                        injectedCount++;
                        fprintf(stderr, "[WATCH] Injected into PID=%lu (total: %lu)\n", pid, injectedCount);
                    } else {
                        fprintf(stderr, "[WATCH] FAILED to inject into PID=%lu\n", pid);
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);
        Sleep(50);  // Poll every 50ms — fast enough to catch Chrome before WSAIoctl
    }
}

// ============================================================================
// Launch mode: create process SUSPENDED, inject DLL, then resume.
// This guarantees hooks are installed BEFORE the process starts executing.
// Usage: Injector.exe --launch <exe_path> [-- arg1 arg2 ...] --dll <dll_path>
// ============================================================================

static int LaunchMode(int argc, char* argv[]) {
    // argv[0] = "--launch"
    // argv[1..N-1] = exe path (may contain spaces if not properly quoted)
    // --dll <path> = DLL
    //
    // Strategy: find "--dll" in argv, everything before it (after --launch) is
    // the exe path joined with spaces; everything after --dll is the DLL path.

    if (argc < 3) {
        fprintf(stderr, "Usage: Injector.exe --launch <exe_path> --dll <dll_path>\n");
        return 1;
    }

    // Find --dll marker
    int dllIdx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dll") == 0) {
            dllIdx = i;
            break;
        }
    }
    if (dllIdx == -1 || dllIdx + 1 >= argc) {
        fprintf(stderr, "ERROR: --dll <path> is required\n");
        return 1;
    }

    // Find --target-args marker (optional arguments to pass to target process)
    int targetArgsIdx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target-args") == 0) {
            targetArgsIdx = i;
            break;
        }
    }

    const char* dllPathArg = argv[dllIdx + 1];

    // Determine exe path: between --launch (idx 0) and either --target-args or --dll
    int exeEnd = (targetArgsIdx != -1) ? targetArgsIdx : dllIdx;

    // Reconstruct exe path (handles unquoted paths with spaces)
    char exePath[MAX_PATH] = {0};
    for (int i = 1; i < exeEnd; i++) {
        if (i > 1) strcat(exePath, " ");
        strcat(exePath, argv[i]);
    }

    // Target args: between --target-args and --dll
    char targetArgs[1024] = {0};
    if (targetArgsIdx != -1) {
        for (int i = targetArgsIdx + 1; i < dllIdx; i++) {
            if (targetArgs[0]) strcat(targetArgs, " ");
            strcat(targetArgs, argv[i]);
        }
    }

    fprintf(stderr, "Exe path: %s\n", exePath);
    fprintf(stderr, "DLL path: %s\n", dllPathArg);

    // Resolve full paths
    char fullExePath[MAX_PATH] = {0};
    GetFullPathNameA(exePath, MAX_PATH, fullExePath, NULL);
    if (!PathFileExistsA(fullExePath)) {
        fprintf(stderr, "EXE not found: %s\n", fullExePath);
        return 1;
    }

    char fullDllPathA[MAX_PATH];
    GetFullPathNameA(dllPathArg, MAX_PATH, fullDllPathA, NULL);
    if (!PathFileExistsA(fullDllPathA)) {
        fprintf(stderr, "DLL not found: %s\n", fullDllPathA);
        return 1;
    }
    wchar_t fullDllPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, fullDllPathA, -1, fullDllPath, MAX_PATH);

    // Build command line for CreateProcessW (must be writable wide string)
    // Include target args if specified
    wchar_t wCmdLine[32768] = {0};
    if (targetArgs[0]) {
        _snwprintf(wCmdLine, 32767, L"\"%hs\" %hs", fullExePath, targetArgs);
    } else {
        _snwprintf(wCmdLine, 32767, L"\"%hs\"", fullExePath);
    }
    fwprintf(stderr, L"Launch: %s\n", wCmdLine);
    fwprintf(stderr, L"DLL: %hs\n", fullDllPathA);

    // Create process SUSPENDED
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    // Get working directory from exe path
    wchar_t workDir[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, fullExePath, -1, workDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(workDir, L'\\');
    if (lastSlash) *lastSlash = L'\0';
    else workDir[0] = L'\0';

    if (!CreateProcessW(NULL, wCmdLine, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL,
                        workDir[0] ? workDir : NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }

    fprintf(stderr, "Process created SUSPENDED, PID=%lu\n", pi.dwProcessId);

    // Inject DLL into suspended process
    HANDLE hProcess = pi.hProcess;  // Already have handle from CreateProcess
    BOOL injectResult = InjectDLL(hProcess, fullDllPath);

    if (!injectResult) {
        fprintf(stderr, "Injection FAILED — resuming anyway\n");
    } else {
        fprintf(stderr, "Injection OK — resuming process\n");
    }

    // Resume the main thread
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return injectResult ? 0 : 1;
}

int main(int argc, char* argv[]) {
    // Load NtCreateThreadEx from ntdll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
        fprintf(stderr, "Warning: NtCreateThreadEx not found, will fallback to CreateRemoteThread\n");
    }

    // Launch mode: create suspended → inject → resume
    if (argc >= 2 && strcmp(argv[1], "--launch") == 0) {
        return LaunchMode(argc - 1, argv + 1);
    }

    // Check for --watch mode: Injector.exe --watch <process.exe> <path_to_DLL>
    BOOL watchMode = FALSE;
    int argStart = 1;
    if (argc >= 2 && strcmp(argv[1], "--watch") == 0) {
        watchMode = TRUE;
        argStart = 2;
    }

    if (argc < argStart + 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Injector.exe <PID or process.exe> <path_to_DLL>\n");
        fprintf(stderr, "  Injector.exe --watch <process.exe> <path_to_DLL>\n");
        fprintf(stderr, "  Injector.exe --launch <exe_path> [--target-args <args>] --dll <path_to_DLL>\n");
        fprintf(stderr, "\nModes:\n");
        fprintf(stderr, "  (default)   Inject into already-running process(es)\n");
        fprintf(stderr, "  --watch     Monitor for new processes, inject as they appear\n");
        fprintf(stderr, "  --launch    Create process SUSPENDED, inject DLL BEFORE first instruction, resume\n");
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  Injector.exe 12345 C:\\ABF\\ProxyInjector\\bin\\ProxyPayload.dll\n");
        fprintf(stderr, "  Injector.exe chrome.exe C:\\ABF\\ProxyInjector\\bin\\ProxyPayload.dll\n");
        fprintf(stderr, "  Injector.exe --watch chrome.exe C:\\ABF\\ProxyInjector\\bin\\ProxyPayload.dll\n");
        fprintf(stderr, "  Injector.exe --launch C:\\PathOfExile\\PathOfExile.exe --target-args --require-launch --dll C:\\ABF\\ProxyInjector\\bin\\ProxyPayload.dll\n");
        return 1;
    }

    // Resolve DLL path to absolute
    char fullDllPathA[MAX_PATH];
    if (GetFullPathNameA(argv[argStart + 1], MAX_PATH, fullDllPathA, NULL) == 0) {
        fprintf(stderr, "GetFullPathNameA failed for '%s'\n", argv[argStart + 1]);
        return 1;
    }

    if (!PathFileExistsA(fullDllPathA)) {
        fprintf(stderr, "DLL not found: %s\n", fullDllPathA);
        return 1;
    }

    // Convert to wide for injection
    wchar_t fullDllPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, fullDllPathA, -1, fullDllPath, MAX_PATH);
    fprintf(stderr, "DLL path: %s\n", fullDllPathA);

    // Watch mode
    if (watchMode) {
        wchar_t processName[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, argv[argStart], -1, processName, MAX_PATH);

        // Extract DLL filename for already-injected check
        wchar_t dllName[MAX_PATH];
        const wchar_t* lastSlash = wcsrchr(fullDllPath, L'\\');
        wcscpy(dllName, lastSlash ? lastSlash + 1 : fullDllPath);

        WatchMode(processName, fullDllPath, dllName);
        return 0;  // Never reached
    }

    // One-shot mode (original behavior)
    char* endPtr = NULL;
    DWORD pid = strtoul(argv[1], &endPtr, 10);
    BOOL result;
    if (endPtr != argv[1] && *endPtr == '\0') {
        fprintf(stderr, "Target PID: %lu\n", pid);
        result = InjectByPid(pid, fullDllPath);
    } else {
        wchar_t processName[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, processName, MAX_PATH);
        fprintf(stderr, "Target process: %s\n", argv[1]);
        result = InjectByName(processName, fullDllPath);
    }

    return result ? 0 : 1;
}
