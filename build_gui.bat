@echo off
pip install pyinstaller
pyinstaller --onefile --noconsole --icon=icon.ico --name=OctoSpoon ^
    --add-data "drivers;drivers" ^
    octospoon_gui.py
echo.
echo Build finished! Check the "dist" folder.
pause
