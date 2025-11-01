@echo off
echo Building OCTOSPOON GUI...

pip install pyqt6 pyinstaller psutil pywin32

pyinstaller --onefile --noconsole octospoon_gui.py

echo.
echo SUCCESS! → dist\octospoon_gui.exe
pause