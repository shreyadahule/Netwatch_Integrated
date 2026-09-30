@echo off
cd /d "%~dp0NetWatch_Project"
python main.py
if errorlevel 1 pause
