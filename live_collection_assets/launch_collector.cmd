@echo off
REM Pi Forensics Suite - Live Collection USB, Windows double-click launcher.
REM Just runs windows_collector.ps1 (plain, readable PowerShell - open it
REM in Notepad first if you want to see exactly what it does) with a
REM bypassed execution policy for THIS process only, so a station's
REM default "no unsigned scripts" policy doesn't block it. This never
REM changes the target machine's own execution-policy setting.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_collector.ps1"
echo.
pause
