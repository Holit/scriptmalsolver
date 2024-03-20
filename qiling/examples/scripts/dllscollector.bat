@ECHO OFF

ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO :: Create the emulated Windows directory structure and registry ::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: Test for Admin privileges
ECHO [+] Test for Admin privileges
NET SESSIONS > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
	ECHO [x] Error: This script requires administrative privileges.
	pause
	EXIT /B 1
)
ECHO [+] Test for Admin privileges passed

ECHO [+] Get host system directories
:: Host system directories
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (
	SET SYSDIR32="%WINDIR%\SysWOW64"
	SET SYSDIR64="%WINDIR%\System32"
) else (
	SET SYSDIR32="%WINDIR%\System32"
	:: redundant path, this will not be used.
	SET SYSDIR64="%WINDIR%\System32"
)

ECHO [+] Get Qiling rootfs directories
:: Qiling rootfs directories
SET QL_WINDIR32="rootfs\x86_windows\Windows"
SET QL_SYSDIR32="%QL_WINDIR32%\System32"
SET QL_REGDIR32="%QL_WINDIR32%\registry"

if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (
	SET QL_WINDIR64="rootfs\x8664_windows\Windows"
	SET QL_SYSDIR64="%QL_WINDIR64%\System32"
	SET QL_REGDIR64="%QL_WINDIR64%\registry"
) else (
	ECHO [!] This is a x86 system, will not collect x64 files.
)
ECHO [+] Create emulated Windows directory structure
:: Create emulated Windows directory structure
MKDIR %QL_REGDIR32%
MKDIR %QL_SYSDIR32%
MKDIR "%QL_SYSDIR32%\drivers"
MKDIR "%QL_WINDIR32%\Temp"

if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (
	MKDIR %QL_REGDIR64%
	MKDIR %QL_SYSDIR64%
	MKDIR "%QL_SYSDIR64%\drivers"
	MKDIR "%QL_WINDIR64%\Temp"
)

ECHO [+] Generate emulated Windows registry (requires Administrator privileges)
:: Generate emulated Windows registry (requires Administrator privileges)
:: Check if its Windows XP
ver | findstr /i "5\.1\." > nul
if %errorlevel% == 0 (
	:: Windows XP has not upraded reg commands yet, it do not support /Y option
    ECHO [+] This is Windows XP. Using old reg commands...
    ECHO [+] Saving registry  HKLM\SYSTEM
	REG SAVE HKLM\SYSTEM %QL_REGDIR32%\SYSTEM
    ECHO [+] Saving registry  HKLM\SECURITY
	REG SAVE HKLM\SECURITY %QL_REGDIR32%\SECURITY
    ECHO [+] Saving registry  HKLM\SOFTWARE
	REG SAVE HKLM\SOFTWARE %QL_REGDIR32%\SOFTWARE
    ECHO [+] Saving registry  HKLM\HARDWARE
	REG SAVE HKLM\HARDWARE %QL_REGDIR32%\HARDWARE
    ECHO [+] Saving registry  HKLM\SAM
	REG SAVE HKLM\SAM %QL_REGDIR32%\SAM
) else (
    ECHO [+] Saving registry  HKLM\SYSTEM
	REG SAVE HKLM\SYSTEM %QL_REGDIR64%\SYSTEM /Y
    ECHO [+] Saving registry  HKLM\SECURITY
	REG SAVE HKLM\SECURITY %QL_REGDIR64%\SECURITY /Y
    ECHO [+] Saving registry  HKLM\SOFTWARE
	REG SAVE HKLM\SOFTWARE %QL_REGDIR64%\SOFTWARE /Y
    ECHO [+] Saving registry  HKLM\HARDWARE
	REG SAVE HKLM\HARDWARE %QL_REGDIR64%\HARDWARE /Y
    ECHO [+] Saving registry  HKLM\SAM
	REG SAVE HKLM\SAM %QL_REGDIR64%\SAM /Y
	if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (
		ECHO [+] Duplicate generated registry
		:: Duplicate generated registry
		XCOPY /F /D /Y %QL_REGDIR64%\* %QL_REGDIR32%
	)
)
:: This might failed, because Windows XP do not have it.
ECHO [+] Copy NTUSER.DAT
COPY /B /Y C:\Users\Default\NTUSER.DAT "%QL_REGDIR64%\NTUSER.DAT"

ECHO [+] Collect 32-bit DLL files
:: Collect 32-bit DLL files
CALL :collect_dll32 advapi32.dll
CALL :collect_dll32 bcrypt.dll
CALL :collect_dll32 cfgmgr32.dll
CALL :collect_dll32 ci.dll
CALL :collect_dll32 combase.dll
CALL :collect_dll32 comctl32.dll
CALL :collect_dll32 comdlg32.dll
CALL :collect_dll32 crypt32.dll
CALL :collect_dll32 cryptbase.dll
CALL :collect_dll32 gdi32.dll
CALL :collect_dll32 hal.dll
CALL :collect_dll32 iphlpapi.dll
CALL :collect_dll32 kdcom.dll
CALL :collect_dll32 kernel32.dll
CALL :collect_dll32 KernelBase.dll
CALL :collect_dll32 mpr.dll
CALL :collect_dll32 mscoree.dll
CALL :collect_dll32 msvcp_win.dll
CALL :collect_dll32 msvcp60.dll
CALL :collect_dll32 msvcr120_clr0400.dll, msvcr110.dll
CALL :collect_dll32 msvcrt.dll
CALL :collect_dll32 netapi32.dll
CALL :collect_dll32 ntdll.dll
CALL :collect_dll32 ole32.dll
CALL :collect_dll32 oleaut32.dll
CALL :collect_dll32 psapi.dll
CALL :collect_dll32 rpcrt4.dll
CALL :collect_dll32 sechost.dll
CALL :collect_dll32 setupapi.dll
CALL :collect_dll32 shell32.dll
CALL :collect_dll32 shlwapi.dll
CALL :collect_dll32 sspicli.dll
CALL :collect_dll32 ucrtbase.dll
CALL :collect_dll32 ucrtbased.dll
CALL :collect_dll32 urlmon.dll
CALL :collect_dll32 user32.dll
CALL :collect_dll32 userenv.dll
CALL :collect_dll32 uxtheme.dll
CALL :collect_dll32 vcruntime140.dll
CALL :collect_dll32 version.dll
CALL :collect_dll32 win32u.dll
CALL :collect_dll32 winhttp.dll
CALL :collect_dll32 wininet.dll
CALL :collect_dll32 winmm.dll
CALL :collect_dll32 ws2_32.dll
CALL :collect_dll32 wsock32.dll

ECHO [+] Collect downlevel folder.
CALL :collect_dll32 downlevel\api-ms-win-core-fibers-l1-1-1.dll
CALL :collect_dll32 downlevel\api-ms-win-core-localization-l1-2-1.dll
CALL :collect_dll32 downlevel\api-ms-win-core-synch-l1-2-0.dll
CALL :collect_dll32 downlevel\api-ms-win-core-sysinfo-l1-2-1.dll
CALL :collect_dll32 downlevel\api-ms-win-crt-heap-l1-1-0.dll
CALL :collect_dll32 downlevel\api-ms-win-crt-locale-l1-1-0.dll
CALL :collect_dll32 downlevel\api-ms-win-crt-math-l1-1-0.dll
CALL :collect_dll32 downlevel\api-ms-win-crt-runtime-l1-1-0.dll
CALL :collect_dll32 downlevel\api-ms-win-crt-stdio-l1-1-0.dll

if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (
	ECHO [+] Collect 64-bit DLL files
	:: Collect 64-bit DLL files
	CALL :collect_dll64 advapi32.dll
	CALL :collect_dll64 gdi32.dll
	CALL :collect_dll64 kernel32.dll
	CALL :collect_dll64 KernelBase.dll
	CALL :collect_dll64 mscoree.dll
	CALL :collect_dll64 msvcrt.dll
	CALL :collect_dll64 ntdll.dll
	CALL :collect_dll64 ntoskrnl.exe
	CALL :collect_dll64 msvcp_win.dll
	CALL :collect_dll64 ucrtbase.dll
	CALL :collect_dll64 ucrtbased.dll
	CALL :collect_dll64 urlmon.dll
	CALL :collect_dll64 rpcrt4.dll
	CALL :collect_dll64 sechost.dll
	CALL :collect_dll64 shell32.dll
	CALL :collect_dll64 shlwapi.dll
	CALL :collect_dll64 user32.dll
	CALL :collect_dll64 vcruntime140.dll
	CALL :collect_dll64 vcruntime140d.dll
	CALL :collect_dll64 vcruntime140_1.dll
	CALL :collect_dll64 vcruntime140_1d.dll
	CALL :collect_dll64 win32u.dll
	CALL :collect_dll64 winhttp.dll
	CALL :collect_dll64 wininet.dll
	CALL :collect_dll64 ws2_32.dll

	ECHO [+] Collect downlevel folder.
	CALL :collect_dll64 downlevel\api-ms-win-crt-heap-l1-1-0.dll
	CALL :collect_dll64 downlevel\api-ms-win-crt-locale-l1-1-0.dll
	CALL :collect_dll64 downlevel\api-ms-win-crt-math-l1-1-0.dll
	CALL :collect_dll64 downlevel\api-ms-win-crt-runtime-l1-1-0.dll
	CALL :collect_dll64 downlevel\api-ms-win-crt-stdio-l1-1-0.dll
)
ECHO [+] Collect extras
:: Collect extras
CALL :collect %SYSDIR64%, ntoskrnl.exe, %QL_SYSDIR32%

ECHO [+] All done!
:: All done!
PAUSE
EXIT /B 0

:: Functions definitions
:normpath
SET %1=%~dpfn2
EXIT /B

:collect
CALL :normpath SRC, %~1\%~2
CALL :normpath DST, %~3\%~4

IF EXIST %SRC% (
	ECHO [.] %SRC% -^> %DST%
	COPY /B /Y "%SRC%" "%DST%" >NUL
)
EXIT /B

:collect_dll64
CALL :collect %SYSDIR64%, %~1, %QL_SYSDIR64%, %~2
EXIT /B

:collect_dll32
CALL :collect %SYSDIR32%, %~1, %QL_SYSDIR32%, %~2
EXIT /B
