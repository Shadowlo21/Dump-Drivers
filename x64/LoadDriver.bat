@echo off
sc stop ADumpedDriver >nul
sc delete AADumpedDriver >nul
sc create ADumpedDriver binPath= "%cd%\gdriver.sys" type= kernel start= demand >nul
sc start ADumpedDriver >nul
