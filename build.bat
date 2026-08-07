@echo off
set PATH=C:\ABF\ProxyInjector\mingw\mingw64\bin;%PATH%
set GCC=g++.exe
set FLAGS=-shared -Wall -Wno-unknown-pragmas -O2 -std=gnu++17

cd /d C:\ABF\ProxyInjector\ProxyPayload
%GCC% -o ..\bin\ProxyPayload.dll dllmain.cpp %FLAGS% -lws2_32 -static -static-libgcc -static-libstdc++
if errorlevel 1 (
    echo DLL BUILD FAILED
    exit /b 1
)
echo DLL BUILD OK

cd /d C:\ABF\ProxyInjector\Injector
%GCC% -o ..\bin\Injector.exe injector.cpp -static -Wall -Wno-unknown-pragmas -O2 -lshlwapi
if errorlevel 1 (
    echo INJECTOR BUILD FAILED
    exit /b 1
)
echo INJECTOR BUILD OK

cd /d C:\ABF\ProxyInjector\TestClient
%GCC% -o ..\bin\test_client.exe test_client.cpp -lws2_32 -static -O2
if errorlevel 1 (
    echo TEST_CLIENT BUILD FAILED
    exit /b 1
)
echo TEST_CLIENT BUILD OK
